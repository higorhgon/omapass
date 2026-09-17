#include "bwcache.h"

#include "bwcrypto.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>

namespace {

// Marks a failure that should send the caller back to `bw`.
struct Unsupported {};

// A field that may be null; anything present has to decrypt.
QJsonValue decryptField(const QJsonValue &value, const BwKey &key) {
    if (value.isNull() || value.isUndefined())
        return QJsonValue::Null;
    if (!value.isString())
        throw Unsupported();
    const std::optional<QString> text = BwCrypto::decryptString(value.toString(), key);
    if (!text)
        throw Unsupported();
    return *text;
}

QJsonObject decryptLogin(const QJsonObject &cipher, const BwKey &key) {
    const QJsonObject login = cipher.value(QStringLiteral("login")).toObject();

    QJsonArray uris;
    const QJsonArray encryptedUris = login.value(QStringLiteral("uris")).toArray();
    for (const QJsonValue &value : encryptedUris) {
        const QJsonObject uri = value.toObject();
        uris.append(QJsonObject{{QStringLiteral("match"), uri.value(QStringLiteral("match"))},
                                {QStringLiteral("uri"), decryptField(uri.value(QStringLiteral("uri")), key)}});
    }

    return QJsonObject{
        {QStringLiteral("username"), decryptField(login.value(QStringLiteral("username")), key)},
        {QStringLiteral("password"), decryptField(login.value(QStringLiteral("password")), key)},
        {QStringLiteral("totp"), decryptField(login.value(QStringLiteral("totp")), key)},
        {QStringLiteral("uris"), uris},
    };
}

}

QString BwCache::defaultPath() {
    const QString custom = qEnvironmentVariable("BITWARDENCLI_APPDATA_DIR");
    if (!custom.isEmpty())
        return custom + QStringLiteral("/data.json");
    QString config = qEnvironmentVariable("XDG_CONFIG_HOME");
    if (config.isEmpty())
        config = QDir::homePath() + QStringLiteral("/.config");
    return config + QStringLiteral("/Bitwarden CLI/data.json");
}

std::optional<BwCache> BwCache::load(const QString &path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return std::nullopt;

    // The file also holds bw's tokens: the buffer is wiped as soon as the
    // parts below have been copied out of it.
    QByteArray content = file.readAll();
    const QJsonDocument document = QJsonDocument::fromJson(content);
    content.fill('\0');
    if (!document.isObject())
        return std::nullopt;

    const QJsonObject root = document.object();
    const QString userId = root.value(QStringLiteral("global_account_activeAccountId")).toString();
    if (userId.isEmpty())
        return std::nullopt;

    const QString prefix = QStringLiteral("user_") + userId + QLatin1Char('_');
    const auto userValue = [&root, &prefix](const char *key) {
        return root.value(prefix + QLatin1String(key));
    };

    BwCache cache;
    cache.m_email = root.value(QStringLiteral("global_account_accounts")).toObject()
                        .value(userId).toObject().value(QStringLiteral("email")).toString();
    cache.m_unlockKey = userValue("masterPasswordUnlock_masterPasswordUnlockKey").toObject();
    cache.m_cryptoState = userValue("crypto_accountCryptographicState").toObject();
    cache.m_organizationKeys = userValue("crypto_organizationKeys").toObject();
    cache.m_folders = userValue("folder_folders").toObject();

    const QJsonValue ciphers = userValue("ciphers_ciphers");
    cache.m_ciphers = ciphers.toObject();

    // Accounts without a master password (SSO with Key Connector or trusted
    // devices) have no unlock key; a vault never synced has no ciphers entry.
    if (cache.m_email.isEmpty() || cache.m_unlockKey.isEmpty() || !ciphers.isObject())
        return std::nullopt;
    return cache;
}

BwCache::Result BwCache::decrypt(const Secret &password, QHash<QString, QJsonObject> *items,
                                 QHash<QString, QString> *folders) const {
    const QJsonObject kdfObject = m_unlockKey.value(QStringLiteral("kdf")).toObject();
    BwKdf kdf;
    kdf.type = kdfObject.value(QStringLiteral("kdfType")).toInt(-1);
    kdf.iterations = kdfObject.value(QStringLiteral("iterations")).toInt();
    kdf.memory = kdfObject.value(QStringLiteral("memory")).toInt();
    kdf.parallelism = kdfObject.value(QStringLiteral("parallelism")).toInt();

    const QString salt = m_unlockKey.value(QStringLiteral("salt")).toString();
    const QString wrappedUserKey = m_unlockKey.value(QStringLiteral("masterKeyWrappedUserKey")).toString();
    if (salt.isEmpty() || !wrappedUserKey.startsWith(QLatin1String("2.")))
        return Result::Unsupported;

    const std::optional<BwKey> masterKey = BwCrypto::deriveMasterKey(password, salt, kdf);
    if (!masterKey)
        return Result::Unsupported;

    // The user key is an authenticated type 2 string: failing to open it
    // with a correctly derived key means the password is wrong.
    const std::optional<BwKey> userKey = BwCrypto::unwrapKey(wrappedUserKey, *masterKey);
    if (!userKey)
        return Result::WrongPassword;

    QHash<QString, QJsonObject> decryptedItems;
    QHash<QString, QString> decryptedFolders;

    try {
        // Organisation keys are only needed when the account has any.
        QHash<QString, BwKey> organizationKeys;
        if (!m_organizationKeys.isEmpty()) {
            const QString encryptedPrivateKey = m_cryptoState.value(QStringLiteral("V1")).toObject()
                                                    .value(QStringLiteral("private_key")).toString();
            const std::optional<BwBytes> privateKey = BwCrypto::decrypt(encryptedPrivateKey, *userKey);
            if (!privateKey)
                throw Unsupported();

            for (auto it = m_organizationKeys.constBegin(); it != m_organizationKeys.constEnd(); ++it) {
                const QJsonObject entry = it.value().toObject();
                // Provider-managed organisations wrap their key differently;
                // such an organisation's items make the vault unsupported
                // below, when one is actually met.
                if (entry.value(QStringLiteral("type")).toString() != QLatin1String("organization"))
                    continue;
                const std::optional<BwBytes> bytes =
                    BwCrypto::rsaDecrypt(entry.value(QStringLiteral("key")).toString(), *privateKey);
                const std::optional<BwKey> key = bytes ? BwCrypto::keyFromBytes(*bytes) : std::nullopt;
                if (!key)
                    throw Unsupported();
                organizationKeys.insert(it.key(), *key);
            }
        }

        for (auto it = m_folders.constBegin(); it != m_folders.constEnd(); ++it) {
            const QJsonValue name = decryptField(it.value().toObject().value(QStringLiteral("name")), *userKey);
            QString text = name.toString();
            while (text.endsWith(QLatin1Char('/')))
                text.chop(1);
            if (!text.isEmpty())
                decryptedFolders.insert(it.key(), text);
        }

        for (auto it = m_ciphers.constBegin(); it != m_ciphers.constEnd(); ++it) {
            const QJsonObject cipher = it.value().toObject();
            if (cipher.value(QStringLiteral("type")).toInt() != 1)
                continue;
            const QJsonValue deleted = cipher.value(QStringLiteral("deletedDate"));
            if (!deleted.isNull() && !deleted.isUndefined())
                continue;

            const QString organizationId = cipher.value(QStringLiteral("organizationId")).toString();
            BwKey baseKey = *userKey;
            if (!organizationId.isEmpty()) {
                if (!organizationKeys.contains(organizationId))
                    throw Unsupported();
                baseKey = organizationKeys.value(organizationId);
            }

            // Newer items carry a key of their own, wrapped with the user's
            // or the organisation's key; older ones use that key directly.
            BwKey itemKey = baseKey;
            const QJsonValue wrappedItemKey = cipher.value(QStringLiteral("key"));
            if (wrappedItemKey.isString()) {
                const std::optional<BwKey> key = BwCrypto::unwrapKey(wrappedItemKey.toString(), baseKey);
                if (!key)
                    throw Unsupported();
                itemKey = *key;
            }

            QJsonObject item;
            item.insert(QStringLiteral("object"), QStringLiteral("item"));
            item.insert(QStringLiteral("id"), it.key());
            item.insert(QStringLiteral("type"), 1);
            item.insert(QStringLiteral("organizationId"), cipher.value(QStringLiteral("organizationId")));
            item.insert(QStringLiteral("folderId"), cipher.value(QStringLiteral("folderId")));
            item.insert(QStringLiteral("collectionIds"), cipher.value(QStringLiteral("collectionIds")));
            item.insert(QStringLiteral("revisionDate"), cipher.value(QStringLiteral("revisionDate")));
            item.insert(QStringLiteral("deletedDate"), QJsonValue::Null);
            item.insert(QStringLiteral("name"), decryptField(cipher.value(QStringLiteral("name")), itemKey));
            item.insert(QStringLiteral("notes"), decryptField(cipher.value(QStringLiteral("notes")), itemKey));
            item.insert(QStringLiteral("login"), decryptLogin(cipher, itemKey));
            decryptedItems.insert(it.key(), item);
        }
    } catch (const Unsupported &) {
        return Result::Unsupported;
    }

    *items = std::move(decryptedItems);
    *folders = std::move(decryptedFolders);
    return Result::Ok;
}
