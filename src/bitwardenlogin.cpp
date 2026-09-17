#include "bitwardenlogin.h"

#include "i18n.h"

#include <QProcessEnvironment>
#include <QRegularExpression>

BitwardenLogin::BitwardenLogin(QObject *parent) : QObject(parent) {}

BitwardenLogin::~BitwardenLogin() {
    cancel();
}

void BitwardenLogin::start(const QString &email, const Secret &password, int method) {
    cancel();

    m_stderr.clear();
    m_promptsSeen.clear();
    m_stopping = false;

    m_process = new QProcess(this);

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.remove(QStringLiteral("BW_NOINTERACTION"));
    env.remove(QStringLiteral("BW_SESSION"));
    env.insert(QStringLiteral("OMAPASS_BW_PASSWORD"), password.toString());
    m_process->setProcessEnvironment(env);

    QStringList args = {QStringLiteral("login"), email, QStringLiteral("--passwordenv"),
                        QStringLiteral("OMAPASS_BW_PASSWORD"), QStringLiteral("--raw")};
    if (method >= 0)
        args << QStringLiteral("--method") << QString::number(method);

    connect(m_process, &QProcess::readyReadStandardError, this, &BitwardenLogin::onStderr);
    connect(m_process, &QProcess::finished, this, &BitwardenLogin::onFinished);
    connect(m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (error != QProcess::FailedToStart)
            return;
        const QString message = m_process->errorString();
        m_process->deleteLater();
        m_process = nullptr;
        emit failed(I18n::t(QStringLiteral("bitwarden.spawn_error"), QStringLiteral("err"), message),
                    BwLoginError::Other);
    });

    m_process->start(QStringLiteral("bw"), args);
}

void BitwardenLogin::sendCode(const QString &code) {
    if (!m_process)
        return;
    QByteArray line = code.trimmed().toUtf8() + '\n';
    m_process->write(line);
    line.fill('\0');
}

void BitwardenLogin::cancel() {
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
