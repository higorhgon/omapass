#pragma once

#include <QList>
#include <QObject>

#include "bitwardenjson.h"
#include "bwcrypto.h"
#include "secret.h"

class BitwardenVault;

// One login to a Bitwarden server, driven asynchronously: the work (the KDF,
// which takes a moment by design, and the requests) runs on a worker thread,
// and the steps the server asks for come back as prompts for the interface
// to put to the user.
//
// The flow is the official clients': prelogin for the KDF settings, the
// master password hash to the token endpoint, then — when the server asks —
// a two-step code (sending the e-mail first when that is the method) or the
// code e-mailed for a new device, and finally a first sync, after which the
// account is saved and handed over open.
class BitwardenLogin : public QObject {
    Q_OBJECT

public:
    explicit BitwardenLogin(QObject *parent = nullptr);
    ~BitwardenLogin() override;

    // `server` normalised (see normalizeBwServer).
    void start(const QString &server, const QString &email, const Secret &password);
    // After TwoFactorMethod: the TwoFactorProviderType picked.
    void chooseMethod(int method);
    // The two-step or new-device code.
    void sendCode(const QString &code);
    void cancel();

    // The two-step methods to choose from, once TwoFactorMethod was shown.
    QList<int> methods() const { return m_methods; }

signals:
    void promptShown(BwPrompt prompt);
    // The account, saved and open; the receiver owns it.
    void succeeded(BitwardenVault *vault);
    void failed(const QString &error, BwLoginError kind);

public:
    // What one attempt came back with. Public for the worker's sake.
    struct Step {
        enum class Kind { Done, TwoFactor, DeviceCode, Failed } kind = Kind::Failed;
        BitwardenVault *vault = nullptr;
        QList<int> providers;
        QString ssoToken;
        QString error;
        BwLoginError errorKind = BwLoginError::Other;
        // Worked out on the first attempt and reused by the next ones, so the
        // KDF runs once per login.
        Secret hash;
        BwKey masterKey;
        BwKdf kdf;
        QString salt;
    };

private:
    void attempt(const QString &twoFactorToken, int provider, const QString &deviceCode);
    void sendEmailThenAsk(int method);
    void finish(const Step &step, bool sentCode);

    quint64 m_generation = 0;
    QString m_server;
    QString m_email;
    Secret m_password;
    Secret m_hash;
    BwKey m_masterKey;
    BwKdf m_kdf;
    QString m_salt;
    QList<int> m_methods;
    QString m_ssoToken;
    int m_provider = -1;
    bool m_deviceCode = false;
};
