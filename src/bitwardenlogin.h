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
    // 3 YubiKey), or -1 to let bw decide. A non-empty `server` is handed to
    // `bw config server` first (which only works logged out, as bw is here);
    // empty leaves bw's server as it is.
    void start(const QString &email, const Secret &password, const QString &server = QString(),
               int method = -1);
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
    QProcess *spawn(const QStringList &args, const QProcessEnvironment &env);
    void startLogin();
    void onStderr();
    void onFinished(int exitCode, QProcess::ExitStatus status);

    QProcess *m_process = nullptr;
    // What the login needs once `bw config server` is done.
    QString m_email;
    Secret m_password;
    int m_method = -1;
    QString m_stderr;
    QSet<int> m_promptsSeen;
    bool m_stopping = false;
};
