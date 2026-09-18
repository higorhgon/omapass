#include "onepasswordlogin.h"

#include "i18n.h"
#include "onepasswordvault.h"

#include <QDebug>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QStandardPaths>

namespace {

bool ptyAvailable() {
    return !QStandardPaths::findExecutable(QStringLiteral("script")).isEmpty();
}

void wipe(QString *text) {
    text->fill(QChar(0));
    text->clear();
}

// The last thing a run said: its error, or the prompt it is waiting on.
QString lastLine(const QString &text) {
    static const QRegularExpression breaks(QStringLiteral("\\x1b\\[[0-9;?]*[A-Za-z]|\\r|\\n"));
    const QStringList lines = text.split(breaks, Qt::SkipEmptyParts);
    for (auto it = lines.crbegin(); it != lines.crend(); ++it) {
        const QString line = it->trimmed();
        if (!line.isEmpty())
            return line;
    }
    return QString();
}

QString stripAnsi(const QString &text) {
    static const QRegularExpression ansi(QStringLiteral("\\x1b\\[[0-9;?]*[A-Za-z]"));
    QString clean = text;
    clean.remove(ansi);
    return clean;
}

}

// How long `op` may go without saying anything before the run is given up
// on. It answers its own prompts in well under a second; the wait is this
// long only so a slow network is never mistaken for a stuck prompt.
constexpr int silenceTimeoutMs = 30000;

OnePasswordLogin::OnePasswordLogin(QObject *parent) : QObject(parent) {
    m_silence.setSingleShot(true);
    m_silence.setInterval(silenceTimeoutMs);
    connect(&m_silence, &QTimer::timeout, this, &OnePasswordLogin::onSilence);
}

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

    // Only the account: the session comes from `op signin` right after, the
    // one command that states the name of the variable it wants the token
    // back in. `op account add --signin` cannot say it.
    m_addingAccount = true;
    const QStringList args = {QStringLiteral("account"), QStringLiteral("add"),
                              QStringLiteral("--address"), address,
                              QStringLiteral("--email"), email,
                              QStringLiteral("--shorthand"), m_shorthand};

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
    m_addingAccount = false;

    beginSignIn();
}

void OnePasswordLogin::beginSignIn() {
    m_stdout.clear();
    m_stderr.clear();
    m_promptsSeen.clear();

    // --force because op refuses to print the session line when something
    // other than a shell is reading it — and under the pseudo terminal it is
    // a terminal that reads.
    runOp({QStringLiteral("signin"), QStringLiteral("--account"), m_shorthand,
           QStringLiteral("--force")},
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
        if (!m_addingAccount)
            m_password.clear();
        return;
    }

    m_awaitingPasswordPrompt = true;
    begin(QStringLiteral("script"),
          {QStringLiteral("-qec"), opShellCommand(args), QStringLiteral("/dev/null")}, env);
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
    m_silence.start();
}

// Nothing from `op` for a while: either it is waiting on a prompt omapass
// does not know how to answer, or it is stuck. Either way the run ends, and
// the message carries the last thing it said, which is the prompt itself.
void OnePasswordLogin::onSilence() {
    if (!m_process)
        return;

    const QString last = lastLine(stripAnsi(m_stderr + QLatin1Char('\n') + m_stdout));
    cancel();
    emit failed(last.isEmpty() ? I18n::t(QStringLiteral("onepassword.no_answer"))
                               : I18n::t(QStringLiteral("onepassword.stuck_prompt"),
                                         QStringLiteral("prompt"), last),
                OpError::Other);
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
    m_silence.stop();
    m_secretKey.clear();
    m_password.clear();
    m_awaitingPasswordPrompt = false;
    m_addingAccount = false;
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
    m_silence.start();
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
        // Kept while adding: `op signin` asks for it again right after.
        if (!m_addingAccount)
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
    m_silence.stop();
    m_process->deleteLater();
    m_process = nullptr;
    m_secretKey.clear();

    const bool ok = status == QProcess::NormalExit && exitCode == 0;

    // What settles whether the account was added is op listing it, not the
    // exit code: `op account add` can end with something to say — about
    // running `op signin` in a shell, say — over an account it did add, and
    // treating that as a failure would leave the account there with omapass
    // claiming it never arrived.
    if (m_addingAccount && (ok || OnePasswordVault::hasAccount(m_shorthand))) {
        // The account is on the device now; the session is a second run,
        // which the same password answers again — so it is only dropped
        // after that one.
        m_addingAccount = false;
        wipeBuffers();
        beginSignIn();
        return;
    }

    m_password.clear();

    if (ok) {
        // op prints `export OP_SESSION_<name>="<token>"`, after whatever
        // prompts the terminal echoed; the name is op's own and is carried
        // along rather than guessed.
        QString out = stripAnsi(m_stdout);
        OpSession parsed = parseOpSignIn(out);
        out.fill(QChar(0));
        const Secret session(parsed.token);
        parsed.token.fill(QChar(0));
        wipeBuffers();
        emit succeeded(m_shorthand, parsed.variable, session);
        return;
    }

    // Under the pseudo terminal there is no separate stderr: prompts, echo
    // and the error all come back on the same channel, so both channels are
    // read. Prompts are redrawn with escape sequences instead of newlines,
    // so those mark line boundaries too; the error op printed is the last
    // line.
    const QString output = m_stderr + QLatin1Char('\n') + m_stdout;
    const QString message = lastLine(output);
    const OpError kind = classifyOpError(output);
    wipeBuffers();
    qWarning().noquote() << "omapass: op run failed:" << message;
    emit failed(message, kind);
}
