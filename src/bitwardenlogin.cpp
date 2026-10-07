#include "bitwardenlogin.h"

#include "bitwardenvault.h"
#include "bwaccount.h"
#include "bwapi.h"
#include "i18n.h"

#include <QFutureWatcher>
#include <QtConcurrent>

namespace {

using Step = BitwardenLogin::Step;

const auto newDeviceMessage = QStringLiteral("new device verification required");

Step failedStep(const QString &error, BwLoginError kind) {
    Step step;
    step.kind = Step::Kind::Failed;
    step.error = error;
    step.errorKind = kind;
    return step;
}

Step failedResponse(const BwResponse &response, bool sentCode) {
    switch (response.failure) {
    case BwResponse::Failure::Unreachable:
        return failedStep(response.networkError, BwLoginError::ServerUnreachable);
    case BwResponse::Failure::Certificate:
        return failedStep(response.networkError, BwLoginError::ServerCertificate);
    default:
        break;
    }
    const QString message = response.message();
    // Only a refusal of the attempt itself says something about the code;
    // "too many requests" or a server error do not.
    const bool aboutCode = sentCode && response.status == 400;
    return failedStep(message, classifyBwLoginMessage(message, aboutCode));
}

QList<int> providersOf(const QJsonObject &json) {
    QList<int> providers;
    const QJsonObject map = json.value(QStringLiteral("twoFactorProviders2")).toObject();
    for (auto it = map.constBegin(); it != map.constEnd(); ++it) {
        bool ok = false;
        const int type = it.key().toInt(&ok);
        if (ok)
            providers.append(type);
    }
    if (providers.isEmpty()) {
        const QJsonArray list = json.value(QStringLiteral("twoFactorProviders")).toArray();
        for (const QJsonValue &value : list)
            providers.append(value.isString() ? value.toString().toInt() : value.toInt());
    }
    return providers;
}

// After the server accepted the login: opens the user key, pulls the vault
// and saves the account, which is then handed over open.
Step completeLogin(const QString &server, const QString &email, const Step &prior,
                   const BwResponse &response) {
    const QJsonObject &json = response.json;
    const Secret accessToken(json.value(QStringLiteral("access_token")).toString());
    const int expiresIn = json.value(QStringLiteral("expires_in")).toInt(3600);
    QString refreshToken = json.value(QStringLiteral("refresh_token")).toString();

    const QJsonObject unlock = json.value(QStringLiteral("userDecryptionOptions")).toObject()
                                   .value(QStringLiteral("masterPasswordUnlock")).toObject();
    QString wrappedUserKey = json.value(QStringLiteral("key")).toString();
    if (wrappedUserKey.isEmpty())
        wrappedUserKey = unlock.value(QStringLiteral("masterKeyEncryptedUserKey")).toString();

    const std::optional<BwKey> userKey = BwCrypto::unwrapKey(wrappedUserKey, prior.masterKey);
    if (accessToken.isEmpty() || refreshToken.isEmpty() || !userKey) {
        refreshToken.fill(QChar(0));
        return failedStep(I18n::t(QStringLiteral("bitwarden.unsupported_account")), BwLoginError::Other);
    }

    BwAccountState state;
    state.server = server;
    state.email = email;
    state.salt = prior.salt;
    state.kdf = prior.kdf;
    state.userKey = wrappedUserKey;
    state.privateKey = json.value(QStringLiteral("privateKey")).toString();

    QByteArray refreshBytes = refreshToken.toUtf8();
    refreshToken.fill(QChar(0));
    state.refreshToken = BwCrypto::encrypt(refreshBytes, *userKey).value_or(QString());
    refreshBytes.fill('\0');

    const BwResponse sync = BwApi::call(server, "GET", QStringLiteral("/sync?excludeDomains=true"), accessToken);
    if (!sync.ok())
        return failedResponse(sync, false);
    BwAccount::applySync(&state, sync.json);

    BwKeys keys;
    keys.user = *userKey;
    keys.organizations = BwAccount::organizationKeys(state, *userKey);

    QString error;
    if (!BwAccount::save(state, &error))
        return failedStep(error, BwLoginError::Other);

    Step step = prior;
    step.kind = Step::Kind::Done;
    step.vault = BitwardenVault::fromLogin(state, keys, accessToken, expiresIn);
    return step;
}

Step runAttempt(const QString &server, const QString &email, const Secret &password, Step prior,
                const QString &twoFactorToken, int provider, const QString &deviceCode) {
    // The KDF runs on the first attempt only; the code steps reuse it.
    if (prior.hash.isEmpty()) {
        const BwResponse prelogin = BwApi::prelogin(server, email);
        if (!prelogin.ok())
            return failedResponse(prelogin, false);

        // The flat fields every server sends, or the newer kdfSettings
        // object when only that is there; the salt is the e-mail unless the
        // server names another.
        const QJsonObject &json = prelogin.json;
        const QJsonObject settings = json.value(QStringLiteral("kdfSettings")).toObject();
        const bool flat = json.contains(QStringLiteral("kdfIterations"));
        prior.kdf.type = flat ? json.value(QStringLiteral("kdf")).toInt()
                              : settings.value(QStringLiteral("kdfType")).toInt();
        prior.kdf.iterations = flat ? json.value(QStringLiteral("kdfIterations")).toInt()
                                    : settings.value(QStringLiteral("iterations")).toInt();
        prior.kdf.memory = flat ? json.value(QStringLiteral("kdfMemory")).toInt()
                                : settings.value(QStringLiteral("memory")).toInt();
        prior.kdf.parallelism = flat ? json.value(QStringLiteral("kdfParallelism")).toInt()
                                     : settings.value(QStringLiteral("parallelism")).toInt();
        const QString salt = json.value(QStringLiteral("salt")).toString();
        prior.salt = salt.isEmpty() ? email.trimmed().toLower() : salt;

        const std::optional<BwBytes> material = BwCrypto::deriveKdfMaterial(password, prior.salt, prior.kdf);
        const std::optional<BwKey> masterKey = material ? BwCrypto::stretchMasterKey(*material) : std::nullopt;
        if (!masterKey)
            return failedStep(I18n::t(QStringLiteral("bitwarden.unsupported_account")), BwLoginError::Other);
        prior.hash = BwCrypto::masterPasswordHash(*material, password);
        prior.masterKey = *masterKey;
    }

    BwApi::Form form{{QStringLiteral("grant_type"), QStringLiteral("password")},
                     {QStringLiteral("username"), email},
                     {QStringLiteral("password"), prior.hash.toString()}};
    if (!twoFactorToken.isEmpty()) {
        form << qMakePair(QStringLiteral("twoFactorToken"), twoFactorToken)
             << qMakePair(QStringLiteral("twoFactorProvider"), QString::number(provider))
             << qMakePair(QStringLiteral("twoFactorRemember"), QStringLiteral("0"));
    }
    if (!deviceCode.isEmpty())
        form << qMakePair(QStringLiteral("newDeviceOtp"), deviceCode);
    const bool sentCode = !twoFactorToken.isEmpty() || !deviceCode.isEmpty();

    const BwResponse response = BwApi::token(server, form);
    if (response.ok())
        return completeLogin(server, email, prior, response);

    if (response.failure == BwResponse::Failure::Http && response.status == 400) {
        const QList<int> providers = providersOf(response.json);
        if (!providers.isEmpty()) {
            Step step = prior;
            step.kind = Step::Kind::TwoFactor;
            step.providers = providers;
            step.ssoToken = response.json.value(QStringLiteral("ssoEmail2faSessionToken")).toString();
            return step;
        }
        if (response.message().contains(newDeviceMessage, Qt::CaseInsensitive)) {
            Step step = prior;
            step.kind = Step::Kind::DeviceCode;
            return step;
        }
    }
    return failedResponse(response, sentCode);
}

}

BitwardenLogin::BitwardenLogin(QObject *parent) : QObject(parent) {}

BitwardenLogin::~BitwardenLogin() {
    cancel();
}

void BitwardenLogin::start(const QString &server, const QString &email, const Secret &password) {
    cancel();
    m_server = server;
    m_email = email.trimmed();
    m_password = password;
    attempt(QString(), -1, QString());
}

void BitwardenLogin::chooseMethod(int method) {
    if (!m_methods.contains(method))
        return;
    m_provider = method;
    if (method == 1)
        sendEmailThenAsk(method);
    else
        emit promptShown(BwPrompt::TwoFactorCode);
}

void BitwardenLogin::sendCode(const QString &code) {
    const QString trimmed = code.trimmed();
    if (m_deviceCode)
        attempt(QString(), -1, trimmed);
    else
        attempt(trimmed, m_provider, QString());
}

void BitwardenLogin::cancel() {
    ++m_generation;
    m_password.clear();
    m_hash.clear();
    m_masterKey = BwKey();
    m_methods.clear();
    m_ssoToken.clear();
    m_provider = -1;
    m_deviceCode = false;
}

void BitwardenLogin::attempt(const QString &twoFactorToken, int provider, const QString &deviceCode) {
    const quint64 generation = ++m_generation;
    const bool sentCode = !twoFactorToken.isEmpty() || !deviceCode.isEmpty();

    Step prior;
    prior.hash = m_hash;
    prior.masterKey = m_masterKey;
    prior.kdf = m_kdf;
    prior.salt = m_salt;

    auto *watcher = new QFutureWatcher<Step>(this);
    connect(watcher, &QFutureWatcher<Step>::finished, this, [this, watcher, generation, sentCode]() {
        const Step step = watcher->result();
        watcher->deleteLater();
        if (generation != m_generation) {
            delete step.vault;   // cancelled meanwhile
            return;
        }
        finish(step, sentCode);
    });
    watcher->setFuture(QtConcurrent::run(runAttempt, m_server, m_email, m_password, prior,
                                         twoFactorToken, provider, deviceCode));
}

void BitwardenLogin::sendEmailThenAsk(int method) {
    const quint64 generation = ++m_generation;
    QJsonObject body{{QStringLiteral("email"), m_email},
                     {QStringLiteral("masterPasswordHash"), m_hash.toString()},
                     {QStringLiteral("deviceIdentifier"), BwApi::deviceIdentifier()}};
    if (!m_ssoToken.isEmpty())
        body.insert(QStringLiteral("ssoEmail2FaSessionToken"), m_ssoToken);
    const QString server = m_server;

    auto *watcher = new QFutureWatcher<BwResponse>(this);
    connect(watcher, &QFutureWatcher<BwResponse>::finished, this, [this, watcher, generation, method]() {
        const BwResponse response = watcher->result();
        watcher->deleteLater();
        if (generation != m_generation)
            return;
        if (!response.ok()) {
            const Step step = failedResponse(response, false);
            emit failed(step.error, step.errorKind);
            return;
        }
        m_provider = method;
        emit promptShown(BwPrompt::TwoFactorCode);
    });
    watcher->setFuture(QtConcurrent::run([server, body]() {
        return BwApi::call(server, "POST", QStringLiteral("/two-factor/send-email-login"), Secret(),
                           body, true);
    }));
}

void BitwardenLogin::finish(const Step &step, bool sentCode) {
    if (step.kind != Step::Kind::Failed) {
        m_hash = step.hash;
        m_masterKey = step.masterKey;
        m_kdf = step.kdf;
        m_salt = step.salt;
    }

    switch (step.kind) {
    case Step::Kind::Done:
        m_password.clear();
        emit succeeded(step.vault);
        cancel();
        return;

    case Step::Kind::TwoFactor:
        // Asked again after a code went with the attempt: the code was wrong.
        if (sentCode) {
            emit failed(I18n::t(QStringLiteral("bitwarden.invalid_code")), BwLoginError::InvalidCode);
            return;
        }
        m_ssoToken = step.ssoToken;
        m_methods = bwSupportedTwoFactor(step.providers);
        if (m_methods.isEmpty()) {
            emit failed(I18n::t(QStringLiteral("bitwarden.unsupported_two_step")),
                        BwLoginError::UnsupportedTwoStep);
        } else if (m_methods.size() == 1) {
            chooseMethod(m_methods.first());
        } else {
            emit promptShown(BwPrompt::TwoFactorMethod);
        }
        return;

    case Step::Kind::DeviceCode:
        if (sentCode) {
            emit failed(I18n::t(QStringLiteral("bitwarden.invalid_code")), BwLoginError::InvalidCode);
            return;
        }
        m_deviceCode = true;
        emit promptShown(BwPrompt::NewDeviceCode);
        return;

    case Step::Kind::Failed:
        emit failed(step.error, step.errorKind);
        return;
    }
}
