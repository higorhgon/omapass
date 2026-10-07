#include "bitwardenlogin.h"

#include "i18n.h"

#include <QProcessEnvironment>
#include <QRegularExpression>

BitwardenLogin::BitwardenLogin(QObject *parent) : QObject(parent) {}

BitwardenLogin::~BitwardenLogin() {
    cancel();
}

void BitwardenLogin::start(const QString &email, const Secret &password, const QString &server,
                           int method) {
    cancel();

    m_stderr.clear();
    m_promptsSeen.clear();
    m_stopping = false;
    m_email = email;
    m_password = password;
    m_method = method;

    if (server.isEmpty()) {
        startLogin();
        return;
    }

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("BW_NOINTERACTION"), QStringLiteral("true"));
    QProcess *process = spawn({QStringLiteral("config"), QStringLiteral("server"), server}, env);
    connect(process, &QProcess::finished, this, [this, process](int exitCode, QProcess::ExitStatus status) {
        if (process != m_process)
            return;
        const QString err = QString::fromUtf8(process->readAllStandardError()).trimmed();
        process->deleteLater();
        m_process = nullptr;

        // bw prints its "Unable to fetch ServerConfig" warnings and still
        // saves the setting; only the exit code says it did not.
        if (status != QProcess::NormalExit || exitCode != 0) {
            m_password.clear();
            emit failed(err.section(QLatin1Char('\n'), -1).trimmed(), classifyBwError(err));
            return;
        }
        startLogin();
    });
}

QProcess *BitwardenLogin::spawn(const QStringList &args, const QProcessEnvironment &env) {
    m_process = new QProcess(this);
    m_process->setProcessEnvironment(env);

    QProcess *process = m_process;
    connect(process, &QProcess::errorOccurred, this, [this, process](QProcess::ProcessError error) {
        if (error != QProcess::FailedToStart || process != m_process)
            return;
        const QString message = process->errorString();
        process->deleteLater();
        m_process = nullptr;
        m_password.clear();
        emit failed(I18n::t(QStringLiteral("bitwarden.spawn_error"), QStringLiteral("err"), message),
                    BwLoginError::Other);
    });

    process->start(QStringLiteral("bw"), args);
    return process;
}

void BitwardenLogin::startLogin() {
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.remove(QStringLiteral("BW_NOINTERACTION"));
    env.remove(QStringLiteral("BW_SESSION"));
    env.insert(QStringLiteral("OMAPASS_BW_PASSWORD"), m_password.toString());
    // Only needed until bw has read it from the environment.
    m_password.clear();

    QStringList args = {QStringLiteral("login"), m_email, QStringLiteral("--passwordenv"),
                        QStringLiteral("OMAPASS_BW_PASSWORD"), QStringLiteral("--raw")};
    if (m_method >= 0)
        args << QStringLiteral("--method") << QString::number(m_method);

    QProcess *process = spawn(args, env);
    connect(process, &QProcess::readyReadStandardError, this, &BitwardenLogin::onStderr);
    connect(process, &QProcess::finished, this, &BitwardenLogin::onFinished);
}

void BitwardenLogin::sendCode(const QString &code) {
    if (!m_process)
        return;
    QByteArray line = code.trimmed().toUtf8() + '\n';
    m_process->write(line);
    line.fill('\0');
}

void BitwardenLogin::cancel() {
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

void BitwardenLogin::onStderr() {
    m_stderr += QString::fromUtf8(m_process->readAllStandardError());

    // Inquirer redraws its prompt on every keystroke it echoes, so each
    // prompt is acted on once; bw never asks the same question twice in a run.
    const BwPrompt prompt = detectBwPrompt(m_stderr);
    if (prompt == BwPrompt::None || m_promptsSeen.contains(int(prompt)))
        return;
    m_promptsSeen.insert(int(prompt));

    if (prompt == BwPrompt::TwoFactorMethod)
        cancel();

    emit promptShown(prompt);
}

void BitwardenLogin::onFinished(int exitCode, QProcess::ExitStatus status) {
    if (m_stopping || !m_process)
        return;

    QString out = QString::fromUtf8(m_process->readAllStandardOutput());
    m_stderr += QString::fromUtf8(m_process->readAllStandardError());
    m_process->deleteLater();
    m_process = nullptr;

    if (status == QProcess::NormalExit && exitCode == 0 && !out.trimmed().isEmpty()) {
        const Secret session(out.trimmed());
        out.fill(QChar(0));
        emit succeeded(session);
        return;
    }

    // Inquirer redraws prompts with escape sequences instead of newlines, so
    // those mark line boundaries too; the error bw printed is the last line.
    // The kind is read from the whole output, which survives a message glued
    // to a prompt echo.
    static const QRegularExpression breaks(QStringLiteral("\\x1b\\[[0-9;?]*[A-Za-z]|\\r|\\n"));
    QString message;
    const QStringList lines = m_stderr.split(breaks, Qt::SkipEmptyParts);
    for (auto it = lines.crbegin(); it != lines.crend() && message.isEmpty(); ++it)
        message = it->trimmed();

    emit failed(message, classifyBwError(m_stderr));
}
