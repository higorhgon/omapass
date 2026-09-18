#include "onepasswordlogin.h"

#include "i18n.h"

#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QStandardPaths>

namespace {

// `op` only prompts when it is talking to a terminal, so signing in borrows
// one from `script`. Nothing secret goes on the command line: the password
// and the code are written to the pseudo terminal, like typing them.
QString shellQuoted(const QString &text) {
    QString quoted = text;
    quoted.replace(QLatin1Char('\''), QLatin1String("'\\''"));
    return QLatin1Char('\'') + quoted + QLatin1Char('\'');
}

bool ptyAvailable() {
    return !QStandardPaths::findExecutable(QStringLiteral("script")).isEmpty();
}

void wipe(QString *text) {
    text->fill(QChar(0));
    text->clear();
}

QString stripAnsi(const QString &text) {
    static const QRegularExpression ansi(QStringLiteral("\\x1b\\[[0-9;?]*[A-Za-z]"));
    QString clean = text;
    clean.remove(ansi);
    return clean;
}

}

OnePasswordLogin::OnePasswordLogin(QObject *parent) : QObject(parent) {}

OnePasswordLogin::~OnePasswordLogin() {
    cancel();
}


void OnePasswordLogin::start(const QString &address, const QString &email, const Secret &secretKey,
                             const Secret &password, const QString &shorthand) {
    cancel();

    m_stdout.clear();
    m_stderr.clear();
    m_promptsSeen.clear();
    m_stopping = false;
    m_shorthand = shorthand;
    m_password = password;

    m_secretKey = secretKey;

    // The Secret Key goes in as a variable, which `op` takes with or without
    // a terminal: /proc/<pid>/environ is readable only by the same user,
    // while /proc/<pid>/cmdline is readable by anyone. It is kept as well,
    // in case op asks for it anyway.
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("OP_SECRET_KEY"), secretKey.toString());

    // --signin --raw so the same run that adds the account hands back a
    // session token, saving a second round trip.
    const QStringList args = {QStringLiteral("account"), QStringLiteral("add"),
                              QStringLiteral("--address"), address,
                              QStringLiteral("--email"), email,
                              QStringLiteral("--shorthand"), m_shorthand,
                              QStringLiteral("--signin"), QStringLiteral("--raw")};

    runOp(args, env);
}

void OnePasswordLogin::startSignIn(const QString &account, const Secret &password) {
    cancel();

    m_stdout.clear();
    m_stderr.clear();
    m_promptsSeen.clear();
    m_stopping = false;
    m_shorthand = account;
    m_password = password;

    runOp({QStringLiteral("signin"), QStringLiteral("--account"), account, QStringLiteral("--raw")},
          QProcessEnvironment::systemEnvironment());
}

// Runs `op` with a terminal when there is one to borrow, answering its
// prompts as they come; without one, the password is written on stdin and
// an account that asks for a two-step code cannot be reached.
void OnePasswordLogin::runOp(const QStringList &args, const QProcessEnvironment &env) {
    if (!ptyAvailable()) {
        m_awaitingPasswordPrompt = false;
        begin(QStringLiteral("op"), args, env);
        answer(m_password);
        m_password.clear();
        return;
    }

    m_awaitingPasswordPrompt = true;
    QStringList quoted;
    for (const QString &argument : args)
        quoted << shellQuoted(argument);
    const QString command = QStringLiteral("op ") + quoted.join(QLatin1Char(' '));

    begin(QStringLiteral("script"),
          {QStringLiteral("-qec"), command, QStringLiteral("/dev/null")}, env);
}

void OnePasswordLogin::begin(const QString &program, const QStringList &args,
                             const QProcessEnvironment &env) {
    m_process = new QProcess(this);
    m_process->setProcessEnvironment(env);

    connect(m_process, &QProcess::readyReadStandardError, this, &OnePasswordLogin::onOutput);
    connect(m_process, &QProcess::readyReadStandardOutput, this, &OnePasswordLogin::onOutput);
    connect(m_process, &QProcess::finished, this, &OnePasswordLogin::onFinished);
    connect(m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (error != QProcess::FailedToStart)
            return;
        const QString message = m_process->errorString();
        m_process->deleteLater();
        m_process = nullptr;
        emit failed(I18n::t(QStringLiteral("onepassword.spawn_error"), QStringLiteral("err"), message),
                    OpError::Other);
    });

    m_process->start(program, args);
}

void OnePasswordLogin::answer(const Secret &secret) {
    if (!m_process)
        return;
    QByteArray line = secret.bytes();
    line.append('\n');
    m_process->write(line);
    line.fill('\0');
}

void OnePasswordLogin::sendCode(const QString &code) {
    if (!m_process)
        return;
    QByteArray line = code.trimmed().toUtf8() + '\n';
    m_process->write(line);
    line.fill('\0');
}

void OnePasswordLogin::cancel() {
    m_secretKey.clear();
    m_password.clear();
    m_awaitingPasswordPrompt = false;
    if (!m_process)
        return;

    m_stopping = true;
    m_process->disconnect(this);
    m_process->kill();
    m_process->waitForFinished(2000);
    m_process->deleteLater();
    m_process = nullptr;
}

void OnePasswordLogin::onOutput() {
    m_stdout += QString::fromUtf8(m_process->readAllStandardOutput());
    m_stderr += QString::fromUtf8(m_process->readAllStandardError());

    // Which stream the prompts come out on is op's business; both are
    // watched, and each prompt is answered once — a prompt redrawn as the
    // answer is typed must not send it twice.
    const OpPrompt prompt = detectOpPrompt(stripAnsi(m_stderr + m_stdout));
    if (prompt == OpPrompt::None || m_promptsSeen.contains(int(prompt)))
        return;
    m_promptsSeen.insert(int(prompt));

    // Under a terminal the secrets are typed at op's own prompts — waiting
    // for them keeps the plaintext out of the echo, which is on until op
    // turns it off to ask.
    if (prompt == OpPrompt::SecretKey && !m_secretKey.isEmpty()) {
        answer(m_secretKey);
        m_secretKey.clear();
        return;
    }
    if (prompt == OpPrompt::Password && m_awaitingPasswordPrompt) {
        answer(m_password);
        m_password.clear();
        m_awaitingPasswordPrompt = false;
        return;
    }

    // The two-step code is the only thing asked of the user. Everything else
    // was given up front, so being asked for it means op did not take what
    // it was given, and the run fails on its own.
    if (prompt == OpPrompt::TwoFactorCode)
        emit promptShown(prompt);
}

// Everything op said, including anything the terminal echoed back while it
// was being typed.
void OnePasswordLogin::wipeBuffers() {
    wipe(&m_stdout);
    wipe(&m_stderr);
}

void OnePasswordLogin::onFinished(int exitCode, QProcess::ExitStatus status) {
    if (m_stopping || !m_process)
        return;

    m_stdout += QString::fromUtf8(m_process->readAllStandardOutput());
    m_stderr += QString::fromUtf8(m_process->readAllStandardError());
    m_process->deleteLater();
    m_process = nullptr;
    m_secretKey.clear();
    m_password.clear();

    if (status == QProcess::NormalExit && exitCode == 0) {
        // --raw prints the session token on its own line, after whatever
        // prompts were echoed.
        QString out = stripAnsi(m_stdout);
        QString token;
        const QStringList lines = out.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        for (auto it = lines.crbegin(); it != lines.crend() && token.isEmpty(); ++it)
            token = it->trimmed();
        const Secret session(token);
        token.fill(QChar(0));
        out.fill(QChar(0));
        wipeBuffers();
        emit succeeded(m_shorthand, session);
        return;
    }

    // Under the pseudo terminal there is no separate stderr: prompts, echo
    // and the error all come back on the same channel, so both channels are
    // read. Prompts are redrawn with escape sequences instead of newlines,
    // so those mark line boundaries too; the error op printed is the last
    // line.
    static const QRegularExpression breaks(QStringLiteral("\\x1b\\[[0-9;?]*[A-Za-z]|\\r|\\n"));
    const QString output = m_stderr + QLatin1Char('\n') + m_stdout;
    QString message;
    const QStringList lines = output.split(breaks, Qt::SkipEmptyParts);
    for (auto it = lines.crbegin(); it != lines.crend() && message.isEmpty(); ++it)
        message = it->trimmed();

    const OpError kind = classifyOpError(output);
    wipeBuffers();
    emit failed(message, kind);
}
