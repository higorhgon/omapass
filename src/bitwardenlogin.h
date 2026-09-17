#pragma once

#include <QObject>
#include <QProcess>
#include <QSet>

#include "bitwardenjson.h"
#include "secret.h"

// One run of `bw login`, driven asynchronously. Unlike every other bw call
// this one is left interactive: two-step codes and new-device verification
// are only ever asked for on a prompt, so the process is kept alive while
// the interface asks the user, and the answer is written to its stdin.
class BitwardenLogin : public QObject {
    Q_OBJECT

public:
    explicit BitwardenLogin(QObject *parent = nullptr);
    ~BitwardenLogin() override;

    // `method` is a TwoFactorProviderType (0 authenticator, 1 e-mail,
    // 3 YubiKey), or -1 to let bw decide.
    void start(const QString &email, const Secret &password, int method = -1);
    void sendCode(const QString &code);
    void cancel();

signals:
    // Waiting on the user. For TwoFactorMethod the process has already been
    // stopped: bw's own menu cannot be driven blind, so the caller restarts
    // with the chosen method instead.
    void promptShown(BwPrompt prompt);
    void succeeded(const Secret &session);
    void failed(const QString &error, BwLoginError kind);

private:
    void onStderr();
    void onFinished(int exitCode, QProcess::ExitStatus status);

    QProcess *m_process = nullptr;
    QString m_stderr;
    QSet<int> m_promptsSeen;
    bool m_stopping = false;
};
