#include "onepasswordlogin.h"

#include "i18n.h"

#include <QProcessEnvironment>
#include <QRegularExpression>

namespace {

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

QString OnePasswordLogin::shorthandFor(const QString &address) {
    static const QRegularExpression invalid(QStringLiteral("[^a-z0-9_]"));
    QString shorthand = address.section(QLatin1Char('.'), 0, 0).trimmed().toLower();
    shorthand.replace(invalid, QStringLiteral("_"));
    return shorthand.isEmpty() ? QStringLiteral("omapass") : shorthand;
}

void OnePasswordLogin::start(const QString &address, const QString &email, const Secret &secretKey,
                             const Secret &password) {
    cancel();

    m_stdout.clear();
    m_stderr.clear();
    m_promptsSeen.clear();
    m_stopping = false;
    m_shorthand = shorthandFor(address);
    m_secretKey = secretKey;
    m_password = password;

    m_process = new QProcess(this);
    m_process->setProcessEnvironment(QProcessEnvironment::systemEnvironment());

    // --signin --raw so the same run that adds the account hands back a
    // session token, saving a second round trip.
    const QStringList args = {QStringLiteral("account"), QStringLiteral("add"),
                              QStringLiteral("--address"), address,
                              QStringLiteral("--email"), email,
                              QStringLiteral("--shorthand"), m_shorthand,
                              QStringLiteral("--signin"), QStringLiteral("--raw")};

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

    m_process->start(QStringLiteral("op"), args);
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

    switch (prompt) {
    case OpPrompt::SecretKey:
        answer(m_secretKey);
        m_secretKey.clear();
        return;
    case OpPrompt::Password:
        answer(m_password);
        m_password.clear();
        return;
    case OpPrompt::TwoFactorCode:
        emit promptShown(prompt);
        return;
    case OpPrompt::SignInAddress:
    case OpPrompt::Email:
        // Both went in as flags; being asked for them means op did not take
        // what was typed, and the run will fail on its own.
    case OpPrompt::None:
        return;
    }
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
        emit succeeded(m_shorthand, session);
        return;
    }

    // Prompts are redrawn with escape sequences instead of newlines, so
    // those mark line boundaries too; the error op printed is the last line.
    static const QRegularExpression breaks(QStringLiteral("\\x1b\\[[0-9;?]*[A-Za-z]|\\r|\\n"));
    QString message;
    const QStringList lines = m_stderr.split(breaks, Qt::SkipEmptyParts);
    for (auto it = lines.crbegin(); it != lines.crend() && message.isEmpty(); ++it)
        message = it->trimmed();

    emit failed(message, classifyOpError(m_stderr));
}
