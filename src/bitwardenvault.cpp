#include "bitwardenvault.h"

#include "i18n.h"
#include "totp.h"

#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMutexLocker>
#include <QSettings>
#include <QUrl>

namespace {

// The account versions that drove `bw` remembered. It has no copy here, so
// it shows up only to be logged into again, after which it is forgotten.
const auto legacyAccountSetting = QStringLiteral("bitwarden/account");

// Refreshed this long before the server's own expiry, so a token does not
// run out between being checked and being used.
constexpr int tokenMarginSecs = 120;

// A sync right after logging in has nothing new to bring.
constexpr int freshSyncSecs = 60;

QString lastSegment(const QString &path) {
    return path.section(QLatin1Char('/'), -1);
}

QString failureMessage(const BwResponse &response) {
    switch (response.failure) {
    case BwResponse::Failure::Unreachable:
        return I18n::t(QStringLiteral("bitwarden.network_error"), QStringLiteral("err"),
                       response.networkError);
    case BwResponse::Failure::Certificate:
        return I18n::t(QStringLiteral("bitwarden.certificate_error"), QStringLiteral("err"),
                       response.networkError);
    default:
        break;
    }
    const QString message = response.message();
    return message.isEmpty() ? QStringLiteral("HTTP %1").arg(response.status) : message;
}

// Replaces the element with the same id in `array`, or appends it.
void upsert(QJsonArray *array, const QJsonObject &object) {
    const QString id = object.value(QStringLiteral("id")).toString();
    for (int i = 0; i < array->size(); ++i) {
        if (array->at(i).toObject().value(QStringLiteral("id")).toString() == id) {
            array->replace(i, object);
            return;
        }
    }
    array->append(object);
}

void removeById(QJsonArray *array, const QString &id) {
    for (int i = 0; i < array->size(); ++i) {
        if (array->at(i).toObject().value(QStringLiteral("id")).toString() == id) {
            array->removeAt(i);
            return;
        }
    }
}

QJsonObject findById(const QJsonArray &array, const QString &id) {
    for (const QJsonValue &value : array) {
        const QJsonObject object = value.toObject();
        if (object.value(QStringLiteral("id")).toString() == id)
            return object;
    }
    return QJsonObject();
}

}

BitwardenVault::BitwardenVault(const BwAccountState &state, const BwKeys &keys)
    : Vault(VaultKind::Bitwarden, BwAccount::refPath(state.email, state.server)),
      m_state(state), m_keys(keys) {
    rebuild();
}

QVector<DbRef> BitwardenVault::accounts() {
    QVector<DbRef> databases;
    const QStringList paths = BwAccount::refPaths();
    for (const QString &path : paths)
        databases.append({path, VaultKind::Bitwarden});

    const QString legacy = QSettings().value(legacyAccountSetting).toString();
    if (!legacy.isEmpty()) {
        const QString path = BwAccount::refPath(legacy, QString());
        if (!paths.contains(path))
            databases.append({path, VaultKind::Bitwarden});
    }
    return databases;
}

bool BitwardenVault::hasSession(const QString &refPath) {
    const std::optional<BwAccountState> state = BwAccount::load(refPath);
    return state && !state->refreshToken.isEmpty();
}

QString BitwardenVault::displayName(const QString &refPath) {
    const QString email = BwAccount::emailOf(refPath);
    const QString server = BwAccount::serverOf(refPath);
    if (server.isEmpty())
        return email;
    const QUrl url(server);
    QString host = url.host();
    if (url.port() != -1)
        host += QLatin1Char(':') + QString::number(url.port());
    return QStringLiteral("%1 (%2)").arg(email, host);
}

QString BitwardenVault::serverLabel(const QString &refPath) {
    return bwServerLabel(BwAccount::serverOf(refPath));
}

bool BitwardenVault::logout(const QString &refPath, QString *error) {
    Q_UNUSED(error);
    BwAccount::remove(refPath);
    QSettings settings;
    if (BwAccount::refPath(settings.value(legacyAccountSetting).toString(), QString()) == refPath)
        settings.remove(legacyAccountSetting);
    return true;
}

bool BitwardenVault::verifyPassword(const QString &refPath, const Secret &password, QString *error) {
    const std::optional<BwAccountState> state = BwAccount::load(refPath);
    if (!state)
        return true;   // nothing to check against; the open itself will say
    BwKeys keys;
    if (BwAccount::unlock(*state, password, &keys) == BwAccount::Unlock::WrongPassword) {
        *error = I18n::t(QStringLiteral("backend.wrong_password"));
        return false;
    }
    return true;
}

BitwardenVault *BitwardenVault::unlock(const QString &refPath, const Secret &password, QString *error) {
    const std::optional<BwAccountState> state = BwAccount::load(refPath);
    if (!state || state->refreshToken.isEmpty()) {
        *error = I18n::t(QStringLiteral("bitwarden.not_logged_in"));
        return nullptr;
    }

    BwKeys keys;
    switch (BwAccount::unlock(*state, password, &keys)) {
    case BwAccount::Unlock::Ok:
        return new BitwardenVault(*state, keys);
    case BwAccount::Unlock::WrongPassword:
        *error = I18n::t(QStringLiteral("backend.wrong_password"));
        return nullptr;
    case BwAccount::Unlock::UnsafeKdf:
        *error = I18n::t(QStringLiteral("bitwarden.unsafe_kdf"));
        return nullptr;
    case BwAccount::Unlock::Unsupported:
        break;
    }
    *error = I18n::t(QStringLiteral("bitwarden.unsupported_account"));
    return nullptr;
}

BitwardenVault *BitwardenVault::fromLogin(const BwAccountState &state, const BwKeys &keys,
                                          const Secret &accessToken, int expiresIn) {
    QSettings settings;
    if (settings.value(legacyAccountSetting).toString() == state.email)
        settings.remove(legacyAccountSetting);

    auto *vault = new BitwardenVault(state, keys);
    vault->m_accessToken = accessToken;
    vault->m_tokenExpiry = QDateTime::currentDateTimeUtc().addSecs(expiresIn - tokenMarginSecs);
    vault->m_syncedAt = QDateTime::currentDateTimeUtc();
    return vault;
}

bool BitwardenVault::authorize(QString *error) const {
    if (!m_accessToken.isEmpty() && QDateTime::currentDateTimeUtc() < m_tokenExpiry)
        return true;

    QString server;
    QString encryptedRefresh;
    BwKey user;
    {
        const QMutexLocker locker(&m_mutex);
        server = m_state.server;
        encryptedRefresh = m_state.refreshToken;
        user = m_keys.user;
    }

    const std::optional<QString> refreshToken = BwCrypto::decryptString(encryptedRefresh, user);
    if (!refreshToken || refreshToken->isEmpty()) {
        *error = I18n::t(QStringLiteral("bitwarden.session_expired"));
        return false;
    }

    QString token = *refreshToken;
    const BwResponse response = BwApi::token(server, {{QStringLiteral("grant_type"), QStringLiteral("refresh_token")},
                                                      {QStringLiteral("refresh_token"), token}});
    token.fill(QChar(0));

    if (!response.ok()) {
        // The server no longer takes it — logged out from the web vault, the
        // password changed, the session expired: only logging in again helps.
        if (response.status == 400 || response.status == 401) {
            const QMutexLocker locker(&m_mutex);
            m_state.refreshToken.clear();
            QString ignored;
            BwAccount::save(m_state, &ignored);
            *error = I18n::t(QStringLiteral("bitwarden.session_expired"));
        } else {
            *error = failureMessage(response);
        }
        return false;
    }

    m_accessToken = Secret(response.json.value(QStringLiteral("access_token")).toString());
    const int expiresIn = response.json.value(QStringLiteral("expires_in")).toInt(3600);
    m_tokenExpiry = QDateTime::currentDateTimeUtc().addSecs(qMax(60, expiresIn - tokenMarginSecs));

    // Servers that rotate refresh tokens hand back a new one.
    const QString rotated = response.json.value(QStringLiteral("refresh_token")).toString();
    if (!rotated.isEmpty()) {
        QByteArray bytes = rotated.toUtf8();
        const std::optional<QString> encrypted = BwCrypto::encrypt(bytes, user);
        bytes.fill('\0');
        if (encrypted) {
            const QMutexLocker locker(&m_mutex);
            if (*encrypted != m_state.refreshToken) {
                m_state.refreshToken = *encrypted;
                QString ignored;
                BwAccount::save(m_state, &ignored);
            }
        }
    }
    return true;
}

BwResponse BitwardenVault::request(const QByteArray &method, const QString &path, QString *error,
                                   const QJsonObject &body, bool hasBody) const {
    BwResponse response;
    if (!authorize(error)) {
        response.failure = BwResponse::Failure::Http;
        return response;
    }

    QString server;
    {
        const QMutexLocker locker(&m_mutex);
        server = m_state.server;
    }

    response = BwApi::call(server, method, path, m_accessToken, body, hasBody);
    if (response.status == 401) {
        m_accessToken.clear();
        if (!authorize(error))
            return response;
        response = BwApi::call(server, method, path, m_accessToken, body, hasBody);
    }
    if (!response.ok())
        *error = failureMessage(response);
    return response;
}

bool BitwardenVault::sync(QString *error, bool force) {
    if (!force && m_syncedAt.isValid() && m_syncedAt.secsTo(QDateTime::currentDateTimeUtc()) < freshSyncSecs)
        return true;

    const BwResponse response = request("GET", QStringLiteral("/sync?excludeDomains=true"), error);
    if (!response.ok())
        return false;

    {
        const QMutexLocker locker(&m_mutex);
        BwAccount::applySync(&m_state, response.json);
        m_keys.organizations = BwAccount::organizationKeys(m_state, m_keys.user);
        rebuild();
    }
    persist();
    m_syncedAt = QDateTime::currentDateTimeUtc();
    return true;
}

bool BitwardenVault::syncCipher(const QString &cipherId, QString *error) const {
    if (cipherId.isEmpty())
        return false;
    const BwResponse response = request("GET", QStringLiteral("/ciphers/%1/details").arg(cipherId), error);
    if (!response.ok())
        return false;

    const QJsonValue deleted = response.json.value(QStringLiteral("deletedDate"));
    if (!deleted.isNull() && !deleted.isUndefined()) {
        removeLocalCipher(cipherId);
        return true;
    }

    storeCipher(response.json);
    return true;
}

bool BitwardenVault::removeLocalCipher(const QString &cipherId) const {
    if (cipherId.isEmpty())
        return false;
    bool existed = false;
    {
        const QMutexLocker locker(&m_mutex);
        existed = m_items.contains(cipherId) || !findById(m_state.ciphers, cipherId).isEmpty();
        if (!existed)
            return false;
        removeById(&m_state.ciphers, cipherId);
        m_items.remove(cipherId);
        m_index = buildBwIndex(m_items, m_folders);
    }
    persist();
    return true;
}

QString BitwardenVault::serverUrl() const {
    const QMutexLocker locker(&m_mutex);
    return m_state.server;
}

bool BitwardenVault::validAccessToken(Secret *token, QString *error) const {
    if (!authorize(error))
        return false;
    *token = m_accessToken;
    return !token->isEmpty();
}

bool BitwardenVault::createSend(const BwSendOptions &options, QString *shareUrl, QString *error) const {
    const QString name = options.name.trimmed();
    if (name.isEmpty()) {
        *error = I18n::t(QStringLiteral("bitwarden.send_name_empty"));
        return false;
    }
    if (options.type == 0 && options.text.isEmpty()) {
        *error = I18n::t(QStringLiteral("bitwarden.send_text_empty"));
        return false;
    }

    QByteArray fileBytes;
    QString fileName;
    if (options.type == 1) {
        if (options.filePath.isEmpty()) {
            *error = I18n::t(QStringLiteral("bitwarden.send_file_empty"));
            return false;
        }
        QFile file(options.filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            *error = I18n::t(QStringLiteral("bitwarden.send_file_unreadable"));
            return false;
        }
        fileBytes = file.readAll();
        if (fileBytes.isEmpty()) {
            *error = I18n::t(QStringLiteral("bitwarden.send_file_unreadable"));
            return false;
        }
        fileName = QFileInfo(options.filePath).fileName();
    }

    BwKey user;
    QString server;
    {
        const QMutexLocker locker(&m_mutex);
        user = m_keys.user;
        server = m_state.server;
    }

    const BwBytes seed = BwCrypto::randomBytes(16);
    const std::optional<BwKey> sendKey = BwCrypto::deriveSendKey(seed);
    if (!sendKey) {
        *error = I18n::t(QStringLiteral("bitwarden.send_error"), QStringLiteral("err"), QStringLiteral("crypto"));
        return false;
    }

    const QByteArray seedBytes(reinterpret_cast<const char *>(seed.data()), qsizetype(seed.size()));
    const std::optional<QString> encryptedKey = BwCrypto::encrypt(seedBytes, user);
    const std::optional<QString> encName = BwCrypto::encrypt(name.toUtf8(), *sendKey);
    if (!encryptedKey || !encName) {
        *error = I18n::t(QStringLiteral("bitwarden.send_error"), QStringLiteral("err"), QStringLiteral("crypto"));
        return false;
    }

    QJsonValue encNotes = QJsonValue::Null;
    if (!options.notes.trimmed().isEmpty()) {
        const std::optional<QString> enc = BwCrypto::encrypt(options.notes.toUtf8(), *sendKey);
        if (enc)
            encNotes = *enc;
    }

    const int deleteHours = qMax(1, options.deleteHours);
    const QString deletionDate =
        QDateTime::currentDateTimeUtc().addSecs(qint64(deleteHours) * 3600).toString(Qt::ISODate);

    QJsonValue passwordHash = QJsonValue::Null;
    if (!options.password.isEmpty()) {
        const QString hash = BwCrypto::sendPasswordHash(options.password, seed);
        if (!hash.isEmpty())
            passwordHash = hash;
    }

    QJsonObject body{
        {QStringLiteral("type"), options.type},
        {QStringLiteral("name"), *encName},
        {QStringLiteral("notes"), encNotes},
        {QStringLiteral("key"), *encryptedKey},
        {QStringLiteral("maxAccessCount"),
         options.maxAccessCount > 0 ? QJsonValue(options.maxAccessCount) : QJsonValue(QJsonValue::Null)},
        {QStringLiteral("deletionDate"), deletionDate},
        {QStringLiteral("expirationDate"), QJsonValue::Null},
        {QStringLiteral("password"), passwordHash},
        {QStringLiteral("disabled"), false},
        {QStringLiteral("hideEmail"), options.hideEmail},
    };

    QJsonObject createdSend;
    QString accessId;
    if (options.type == 0) {
        const std::optional<QString> encText = BwCrypto::encrypt(options.text.toUtf8(), *sendKey);
        if (!encText) {
            *error = I18n::t(QStringLiteral("bitwarden.send_error"), QStringLiteral("err"), QStringLiteral("crypto"));
            return false;
        }
        body.insert(QStringLiteral("text"),
                    QJsonObject{{QStringLiteral("text"), *encText},
                                {QStringLiteral("hidden"), options.hidden}});

        const BwResponse response = request("POST", QStringLiteral("/sends"), error, body);
        if (!response.ok())
            return false;
        createdSend = response.json;
        accessId = createdSend.value(QStringLiteral("accessId")).toString();
    } else {
        const std::optional<QString> encFileName = BwCrypto::encrypt(fileName.toUtf8(), *sendKey);
        const std::optional<QByteArray> encFile = BwCrypto::encryptBuffer(fileBytes, *sendKey);
        fileBytes.fill('\0');
        if (!encFileName || !encFile) {
            *error = I18n::t(QStringLiteral("bitwarden.send_error"), QStringLiteral("err"), QStringLiteral("crypto"));
            return false;
        }

        body.insert(QStringLiteral("file"), QJsonObject{{QStringLiteral("fileName"), *encFileName}});
        QJsonObject v2Body = body;
        v2Body.insert(QStringLiteral("fileLength"), qint64(encFile->size()));

        QString v2Error;
        const BwResponse v2Response = request("POST", QStringLiteral("/sends/file/v2"), &v2Error, v2Body);
        if (v2Response.ok()) {
            const int uploadType = v2Response.json.value(QStringLiteral("fileUploadType")).toInt(0);
            const QString uploadUrl = v2Response.json.value(QStringLiteral("url")).toString();
            const QJsonObject sendResponse = v2Response.json.value(QStringLiteral("sendResponse")).toObject();
            createdSend = sendResponse;
            const QString sendId = sendResponse.value(QStringLiteral("id")).toString();
            const QString fileId = sendResponse.value(QStringLiteral("file")).toObject()
                                       .value(QStringLiteral("id")).toString();
            accessId = sendResponse.value(QStringLiteral("accessId")).toString();

            BwResponse uploadResponse;
            if (uploadType == 1 && !uploadUrl.isEmpty()) {
                if (!isBwAzureUploadUrl(uploadUrl)) {
                    *error = I18n::t(QStringLiteral("bitwarden.send_error"), QStringLiteral("err"),
                                     QStringLiteral("upload url"));
                    return false;
                }
                uploadResponse = BwApi::putRaw(uploadUrl, *encFile,
                                               {{"x-ms-blob-type", "BlockBlob"},
                                                {"x-ms-version", "2019-07-07"},
                                                {"Content-Type", "application/octet-stream"}});
            } else {
                if (!authorize(error))
                    return false;
                const QString uploadPath = QStringLiteral("/sends/%1/file/%2").arg(sendId, fileId);
                uploadResponse = BwApi::uploadMultipart(
                    server, uploadPath, m_accessToken,
                    {{QStringLiteral("data"), *encFileName, "application/octet-stream", *encFile}});
            }
            if (!uploadResponse.ok()) {
                *error = failureMessage(uploadResponse);
                return false;
            }
        } else if (v2Response.status == 404) {
            if (!authorize(error))
                return false;
            const BwResponse legacy = BwApi::uploadMultipart(
                server, QStringLiteral("/sends/file"), m_accessToken,
                {{QStringLiteral("model"), QString(), "application/json",
                  QJsonDocument(body).toJson(QJsonDocument::Compact)},
                 {QStringLiteral("data"), *encFileName, "application/octet-stream", *encFile}});
            if (!legacy.ok()) {
                *error = failureMessage(legacy);
                return false;
            }
            createdSend = legacy.json;
            accessId = legacy.json.value(QStringLiteral("accessId")).toString();
        } else {
            *error = v2Error;
            return false;
        }
    }

    if (accessId.isEmpty()) {
        *error = I18n::t(QStringLiteral("bitwarden.send_error"), QStringLiteral("err"), QStringLiteral("accessId"));
        return false;
    }
    if (!createdSend.value(QStringLiteral("id")).toString().isEmpty()) {
        {
            const QMutexLocker locker(&m_mutex);
            upsert(&m_state.sends, createdSend);
            rebuild();
        }
        persist();
    }
    *shareUrl = BwCrypto::sendUrl(server, accessId, seed);
    return true;
}

void BitwardenVault::rebuild() const {
    BwAccount::decryptVault(m_state, m_keys, &m_items, &m_folders, &m_undecryptable);
    m_index = buildBwIndex(m_items, m_folders);

    m_collections.clear();
    for (const QJsonValue &v : m_state.collections) {
        const QJsonObject col = v.toObject();
        const QString id = col.value(QStringLiteral("id")).toString();
        const QString orgId = col.value(QStringLiteral("organizationId")).toString();
        const QString name = BwAccount::decryptCollection(col, m_keys);
        if (!id.isEmpty() && !name.isEmpty())
            m_collections.append({id, name, orgId});
    }
    std::sort(m_collections.begin(), m_collections.end(),
              [](const BwCollectionItem &a, const BwCollectionItem &b) {
                  return a.name.compare(b.name, Qt::CaseInsensitive) < 0;
              });

    m_trash.clear();
    for (const QJsonValue &v : m_state.ciphers) {
        const QJsonObject cipher = v.toObject();
        const QJsonValue deleted = cipher.value(QStringLiteral("deletedDate"));
        if (deleted.isNull() || deleted.isUndefined())
            continue;
        const std::optional<QJsonObject> item = BwAccount::decryptCipher(cipher, m_keys, true);
        if (!item)
            continue;
        BwTrashItem t;
        t.id = item->value(QStringLiteral("id")).toString();
        t.name = bwDisplayName(item->value(QStringLiteral("name")).toString());
        const int type = item->value(QStringLiteral("type")).toInt();
        t.type = type == 5 ? QStringLiteral("ssh")
               : type == 2 ? QStringLiteral("note")
               : type == 3 ? QStringLiteral("card")
               : type == 4 ? QStringLiteral("identity")
                           : QStringLiteral("login");
        t.username = bwEntryData(*item).username;
        t.deletedDate = deleted.toString().left(10);
        m_trash.append(t);
    }
    std::sort(m_trash.begin(), m_trash.end(), [](const BwTrashItem &a, const BwTrashItem &b) {
        return a.name.compare(b.name, Qt::CaseInsensitive) < 0;
    });

    m_sends.clear();
    for (const QJsonValue &v : m_state.sends) {
        const std::optional<QJsonObject> dec = BwAccount::decryptSend(v.toObject(), m_keys.user, m_state.server);
        if (!dec)
            continue;
        BwSendItem s;
        s.id = dec->value(QStringLiteral("id")).toString();
        s.name = dec->value(QStringLiteral("name")).toString();
        s.type = dec->value(QStringLiteral("type")).toInt();
        s.url = dec->value(QStringLiteral("url")).toString();
        s.accessCount = dec->value(QStringLiteral("accessCount")).toInt();
        s.maxAccessCount = dec->value(QStringLiteral("maxAccessCount")).toInt();
        s.deletionDate = dec->value(QStringLiteral("deletionDate")).toString().left(10);
        s.disabled = dec->value(QStringLiteral("disabled")).toBool();
        m_sends.append(s);
    }
    std::sort(m_sends.begin(), m_sends.end(), [](const BwSendItem &a, const BwSendItem &b) {
        return a.name.compare(b.name, Qt::CaseInsensitive) < 0;
    });
}

QVector<BwCollectionItem> BitwardenVault::collections() const {
    const QMutexLocker locker(&m_mutex);
    return m_collections;
}

QVector<BwOrganizationItem> BitwardenVault::organizations() const {
    const QMutexLocker locker(&m_mutex);
    QVector<BwOrganizationItem> result;
    for (auto it = m_keys.organizations.cbegin(); it != m_keys.organizations.cend(); ++it) {
        const QString id = it.key();
        QString name = m_state.organizationNames.value(id).toString();
        if (name.isEmpty())
            name = id.left(8);
        result.append({id, name});
    }
    std::sort(result.begin(), result.end(),
              [](const BwOrganizationItem &a, const BwOrganizationItem &b) {
                  return a.name.compare(b.name, Qt::CaseInsensitive) < 0;
              });
    return result;
}

bool BitwardenVault::createCollection(const QString &organizationId, const QString &name,
                                      QString *error) const {
    const QString trimmed = name.trimmed();
    if (organizationId.isEmpty() || trimmed.isEmpty()) {
        if (error)
            *error = I18n::t(QStringLiteral("app.group_invalid"));
        return false;
    }

    BwKey orgKey;
    {
        const QMutexLocker locker(&m_mutex);
        if (!m_keys.organizations.contains(organizationId)) {
            if (error)
                *error = I18n::t(QStringLiteral("bitwarden.org_key_missing"));
            return false;
        }
        orgKey = m_keys.organizations.value(organizationId);
    }

    const std::optional<QString> encName = BwCrypto::encrypt(trimmed.toUtf8(), orgKey);
    if (!encName) {
        if (error)
            *error = I18n::t(QStringLiteral("app.group_create_error"));
        return false;
    }

    const QJsonObject body{
        {QStringLiteral("name"), *encName},
        {QStringLiteral("externalId"), QJsonValue::Null},
        {QStringLiteral("groups"), QJsonArray()},
        {QStringLiteral("users"), QJsonArray()}
    };
    const BwResponse response = request(
        "POST", QStringLiteral("/organizations/%1/collections").arg(organizationId), error, body);
    if (!response.ok())
        return false;

    QJsonObject created = response.json;
    if (!created.value(QStringLiteral("id")).toString().isEmpty()) {
        if (created.value(QStringLiteral("organizationId")).toString().isEmpty())
            created.insert(QStringLiteral("organizationId"), organizationId);
        {
            const QMutexLocker locker(&m_mutex);
            upsert(&m_state.collections, created);
            rebuild();
        }
        persist();
    }
    return true;
}

bool BitwardenVault::deleteCollection(const QString &collectionId, QString *error) const {
    QString organizationId;
    {
        const QMutexLocker locker(&m_mutex);
        for (const BwCollectionItem &c : std::as_const(m_collections)) {
            if (c.id == collectionId) {
                organizationId = c.organizationId;
                break;
            }
        }
    }
    if (collectionId.isEmpty() || organizationId.isEmpty()) {
        if (error)
            *error = I18n::t(QStringLiteral("app.collection_not_found"));
        return false;
    }

    const BwResponse response = request(
        "DELETE", QStringLiteral("/organizations/%1/collections/%2").arg(organizationId, collectionId),
        error);
    if (!response.ok())
        return false;

    // Items keep existing in the organization; only the link to the
    // collection goes, here as on the server.
    {
        const QMutexLocker locker(&m_mutex);
        removeById(&m_state.collections, collectionId);
        for (int i = 0; i < m_state.ciphers.size(); ++i) {
            QJsonObject cipher = m_state.ciphers.at(i).toObject();
            QJsonArray ids = cipher.value(QStringLiteral("collectionIds")).toArray();
            bool changed = false;
            for (int j = ids.size() - 1; j >= 0; --j) {
                if (ids.at(j).toString() == collectionId) {
                    ids.removeAt(j);
                    changed = true;
                }
            }
            if (changed) {
                cipher.insert(QStringLiteral("collectionIds"), ids);
                m_state.ciphers.replace(i, cipher);
            }
        }
        rebuild();
    }
    persist();
    return true;
}

bool BitwardenVault::createGroup(const QString &group, QString *error) const {
    const QString trimmed = group.trimmed();
    if (trimmed.isEmpty()) {
        if (error)
            *error = I18n::t(QStringLiteral("app.group_invalid"));
        return false;
    }
    QString folderId;
    return ensureFolder(trimmed, &folderId, error);
}

QVector<BwTrashItem> BitwardenVault::trashItems() const {
    const QMutexLocker locker(&m_mutex);
    return m_trash;
}

QVector<BwSendItem> BitwardenVault::sends() const {
    const QMutexLocker locker(&m_mutex);
    return m_sends;
}

bool BitwardenVault::restoreCipher(const QString &cipherId, QString *error) const {
    if (cipherId.isEmpty())
        return false;
    const BwResponse response = request("PUT", QStringLiteral("/ciphers/%1/restore").arg(cipherId), error);
    if (!response.ok())
        return false;
    if (!response.json.value(QStringLiteral("id")).toString().isEmpty()) {
        storeCipher(response.json);
        const QMutexLocker locker(&m_mutex);
        rebuild();
    } else {
        QString ignored;
        syncCipher(cipherId, &ignored);
        const QMutexLocker locker(&m_mutex);
        rebuild();
    }
    return true;
}

bool BitwardenVault::purgeCipher(const QString &cipherId, QString *error) const {
    if (cipherId.isEmpty())
        return false;
    const BwResponse response = request("DELETE", QStringLiteral("/ciphers/%1").arg(cipherId), error);
    if (!response.ok())
        return false;
    {
        const QMutexLocker locker(&m_mutex);
        removeById(&m_state.ciphers, cipherId);
        m_items.remove(cipherId);
        rebuild();
    }
    persist();
    return true;
}

bool BitwardenVault::deleteSend(const QString &sendId, QString *error) const {
    if (sendId.isEmpty())
        return false;
    const BwResponse response = request("DELETE", QStringLiteral("/sends/%1").arg(sendId), error);
    if (!response.ok())
        return false;
    {
        const QMutexLocker locker(&m_mutex);
        removeById(&m_state.sends, sendId);
        rebuild();
    }
    persist();
    return true;
}

QString BitwardenVault::warning() const {
    int undecryptable = 0;
    {
        const QMutexLocker locker(&m_mutex);
        undecryptable = m_undecryptable;
    }
    if (undecryptable == 0)
        return QString();
    return I18n::t(QStringLiteral("bitwarden.undecryptable"), QStringLiteral("count"),
                   QString::number(undecryptable));
}

void BitwardenVault::persist() const {
    BwAccountState copy;
    {
        const QMutexLocker locker(&m_mutex);
        copy = m_state;
    }
    // A failed write only costs the next open a stale copy; the server has
    // the change either way.
    QString ignored;
    BwAccount::save(copy, &ignored);
}

void BitwardenVault::storeCipher(const QJsonObject &cipher) const {
    const QString id = cipher.value(QStringLiteral("id")).toString();
    if (id.isEmpty())
        return;
    {
        const QMutexLocker locker(&m_mutex);
        upsert(&m_state.ciphers, cipher);
        if (const std::optional<QJsonObject> item = BwAccount::decryptCipher(cipher, m_keys))
            m_items.insert(id, *item);
        else
            m_items.remove(id);
        m_index = buildBwIndex(m_items, m_folders);
    }
    persist();
}

void BitwardenVault::storeFolder(const QJsonObject &folder) const {
    const QString id = folder.value(QStringLiteral("id")).toString();
    if (id.isEmpty())
        return;
    {
        const QMutexLocker locker(&m_mutex);
        upsert(&m_state.folders, folder);
        const QString name = BwAccount::decryptFolder(folder, m_keys.user);
        if (!name.isEmpty())
            m_folders.insert(id, name);
        m_index = buildBwIndex(m_items, m_folders);
    }
    persist();
}

bool BitwardenVault::lookup(const QString &entryPath, BwItemRef *ref, QJsonObject *item,
                            QString *error) const {
    const QMutexLocker locker(&m_mutex);
    if (!m_index.items.contains(entryPath)) {
        *error = I18n::t(QStringLiteral("bitwarden.entry_not_found"), QStringLiteral("entry"), entryPath);
        return false;
    }
    *ref = m_index.items.value(entryPath);
    if (item)
        *item = m_items.value(ref->id);
    return true;
}

bool BitwardenVault::ensureFolder(const QString &group, QString *folderId, QString *error) const {
    if (group.isEmpty()) {
        folderId->clear();
        return true;
    }

    BwKey user;
    {
        const QMutexLocker locker(&m_mutex);
        if (m_index.folders.contains(group)) {
            *folderId = m_index.folders.value(group);
            return true;
        }
        user = m_keys.user;
    }

    const BwResponse response = request("POST", QStringLiteral("/folders"), error,
                                        BwAccount::folderRequest(group, user));
    if (!response.ok())
        return false;

    *folderId = response.json.value(QStringLiteral("id")).toString();
    storeFolder(response.json);
    return true;
}

void BitwardenVault::list(QStringList *entries, QStringList *groups) const {
    {
        const QMutexLocker locker(&m_mutex);
        *entries = m_index.entries;
        *groups = m_index.groups;
    }
    appendEmptyGroups(*groups, entries);
}

QHash<QString, EntryMeta> BitwardenVault::entryMeta() const {
    QHash<QString, EntryMeta> meta;
    const QMutexLocker locker(&m_mutex);
    for (auto it = m_index.items.cbegin(); it != m_index.items.cend(); ++it) {
        const QJsonObject item = m_items.value(it.value().id);
        EntryMeta entry;
        const QJsonArray colIds = item.value(QStringLiteral("collectionIds")).toArray();
        for (const QJsonValue &cv : colIds) {
            const QString cid = cv.toString();
            if (!cid.isEmpty())
                entry.collectionIds.append(cid);
        }
        const int type = item.value(QStringLiteral("type")).toInt();
        if (type == 5) {
            entry.type = QStringLiteral("ssh");
            entry.ssh = SshKeyConfig{it.value().id, {}};
        } else if (type == 2) {
            entry.type = QStringLiteral("note");
        } else if (type == 3) {
            entry.type = QStringLiteral("card");
            const EntryData data = bwEntryData(item);
            QString digits;
            const QString num = data.card.number.toString();
            for (const QChar c : num) {
                if (c.isDigit())
                    digits.append(c);
            }
            QString summary;
            if (!data.card.brand.isEmpty())
                summary = data.card.brand;
            if (digits.size() >= 4) {
                const QString tail = QStringLiteral("•••• ") + digits.right(4);
                summary = summary.isEmpty() ? tail : summary + QLatin1Char(' ') + tail;
            }
            if (summary.isEmpty())
                summary = data.card.cardholderName;
            entry.username = summary;
        } else if (type == 4) {
            entry.type = QStringLiteral("identity");
            const EntryData data = bwEntryData(item);
            QStringList nameParts;
            if (!data.identity.firstName.isEmpty())
                nameParts.append(data.identity.firstName);
            if (!data.identity.lastName.isEmpty())
                nameParts.append(data.identity.lastName);
            entry.username = nameParts.isEmpty() ? data.identity.email : nameParts.join(QLatin1Char(' '));
            entry.url = data.identity.email;
        } else {
            const EntryData data = bwEntryData(item);
            entry.username = data.username;
            entry.url = data.url;
            entry.extraUrls = data.extraUrls;
            entry.hasOtp = !data.otp.isEmpty() && Totp::parse(data.otp.toString()).has_value();
        }
        meta.insert(it.key(), entry);
    }
    return meta;
}

QString BitwardenVault::titleFor(const QString &entryPath, const QString &fallback) const {
    const QMutexLocker locker(&m_mutex);
    const QString name = m_index.items.value(entryPath).name;
    return name.isEmpty() ? fallback : name;
}

bool BitwardenVault::fetchPassword(const QString &entryPath, Secret *password, QString *error) const {
    EntryData data;
    if (!fetchEntry(entryPath, &data, error))
        return false;
    *password = data.password;
    return true;
}

bool BitwardenVault::fetchEntry(const QString &entryPath, EntryData *data, QString *error) const {
    BwItemRef ref;
    QJsonObject item;
    if (!lookup(entryPath, &ref, &item, error))
        return false;
    *data = bwEntryData(item);
    return true;
}

bool BitwardenVault::fetchSshKey(const QString &entryPath, const QString &id, Secret *key,
                                 QString *error) const {
    BwItemRef ref;
    QJsonObject item;
    if (!lookup(entryPath, &ref, &item, error) || ref.id != id
        || item.value(QStringLiteral("type")).toInt() != 5)
        return false;
    *key = bwEntryData(item).password;
    return !key->isEmpty();
}

bool BitwardenVault::addEntry(const QString &entryPath, const QString &group, const EntryData &data,
                              QString *error) const {
    QString folderId;
    if (!ensureFolder(group, &folderId, error))
        return false;

    BwKey key;
    QString userId;
    QString orgId;
    QStringList selectedCollections;
    {
        const QMutexLocker locker(&m_mutex);
        key = m_keys.user;
        userId = m_state.userId;
        if (!data.collectionIds.isEmpty()) {
            for (const BwCollectionItem &c : m_collections) {
                if (!data.collectionIds.contains(c.id))
                    continue;
                if (orgId.isEmpty() && !c.organizationId.isEmpty()
                    && m_keys.organizations.contains(c.organizationId)) {
                    orgId = c.organizationId;
                }
                if (!orgId.isEmpty() && c.organizationId == orgId)
                    selectedCollections.append(c.id);
            }
            if (!orgId.isEmpty())
                key = m_keys.organizations.value(orgId);
        }
    }

    QJsonObject cipherBody = BwAccount::cipherRequest(
        QJsonObject(), QString(), lastSegment(entryPath), folderId, data, key, userId);

    BwResponse response;
    if (!orgId.isEmpty() && !selectedCollections.isEmpty()) {
        cipherBody.insert(QStringLiteral("organizationId"), orgId);
        QJsonArray colIds;
        for (const QString &cid : selectedCollections)
            colIds.append(cid);
        const QJsonObject wrapper{
            {QStringLiteral("cipher"), cipherBody},
            {QStringLiteral("collectionIds"), colIds}
        };
        response = request("POST", QStringLiteral("/ciphers/create"), error, wrapper);
    } else {
        response = request("POST", QStringLiteral("/ciphers"), error, cipherBody);
    }
    if (!response.ok())
        return false;
    QJsonObject created = response.json;
    if (created.value(QStringLiteral("id")).toString().isEmpty()
        && created.value(QStringLiteral("cipher")).isObject()) {
        created = created.value(QStringLiteral("cipher")).toObject();
    }
    storeCipher(created);
    return true;
}

bool BitwardenVault::editEntry(const QString &oldPath, const QString &newPath, const QString &group,
                               const EntryData &data, QString *error) const {
    BwItemRef ref;
    QJsonObject item;
    if (!lookup(oldPath, &ref, &item, error))
        return false;

    // The cipher as the server has it, not the decrypted copy: that one only
    // carries the fields omapass shows, and editing from it would drop
    // password history, attachments, passkeys and the like.
    QJsonObject cipher;
    std::optional<BwKey> key;
    QString userId;
    QString existingOrgId;
    QString targetOrgId;
    QStringList selectedCollections;
    QStringList existingCollections;
    {
        const QMutexLocker locker(&m_mutex);
        userId = m_state.userId;
        cipher = findById(m_state.ciphers, ref.id);
        key = BwAccount::cipherKey(cipher, m_keys);
        existingOrgId = cipher.value(QStringLiteral("organizationId")).toString();
        for (const QJsonValue &v : cipher.value(QStringLiteral("collectionIds")).toArray())
            existingCollections.append(v.toString());
        if (data.collectionsLoaded && !data.collectionIds.isEmpty()) {
            targetOrgId = existingOrgId;
            for (const BwCollectionItem &c : m_collections) {
                if (!data.collectionIds.contains(c.id))
                    continue;
                if (targetOrgId.isEmpty() && !c.organizationId.isEmpty()
                    && m_keys.organizations.contains(c.organizationId)) {
                    targetOrgId = c.organizationId;
                }
                if (!targetOrgId.isEmpty() && c.organizationId == targetOrgId)
                    selectedCollections.append(c.id);
            }
        }
    }
    if (cipher.isEmpty() || !key) {
        *error = I18n::t(QStringLiteral("bitwarden.entry_not_found"), QStringLiteral("entry"), oldPath);
        return false;
    }

    QString folderId;
    if (!ensureFolder(group, &folderId, error))
        return false;

    // An untouched title keeps the real name: the path segment may carry a
    // look-alike slash or the id suffix that told duplicates apart.
    const QString title = lastSegment(newPath);
    const QString name = title == lastSegment(oldPath) ? ref.name : title;

    QString previousPassword = bwEntryData(item).password.toString();

    // Moving a personal item into an organization's collection(s) uses /share.
    if (existingOrgId.isEmpty() && !targetOrgId.isEmpty() && !selectedCollections.isEmpty()) {
        BwKey orgKey;
        {
            const QMutexLocker locker(&m_mutex);
            orgKey = m_keys.organizations.value(targetOrgId);
        }
        QJsonObject shareCipher =
            BwAccount::cipherRequest(cipher, previousPassword, name, folderId, data, orgKey, userId);
        previousPassword.fill(QChar(0));
        shareCipher.insert(QStringLiteral("organizationId"), targetOrgId);
        shareCipher.remove(QStringLiteral("key"));
        QJsonArray colIds;
        for (const QString &cid : selectedCollections)
            colIds.append(cid);
        const QJsonObject shareBody{
            {QStringLiteral("cipher"), shareCipher},
            {QStringLiteral("collectionIds"), colIds}
        };
        const BwResponse response =
            request("PUT", QStringLiteral("/ciphers/%1/share").arg(ref.id), error, shareBody);
        if (!response.ok())
            return false;
        QJsonObject updated = response.json;
        if (updated.value(QStringLiteral("id")).toString().isEmpty()
            && updated.value(QStringLiteral("cipher")).isObject()) {
            updated = updated.value(QStringLiteral("cipher")).toObject();
        }
        if (!updated.value(QStringLiteral("id")).toString().isEmpty()) {
            storeCipher(updated);
        } else {
            QString ignored;
            syncCipher(ref.id, &ignored);
        }
        return true;
    }

    const QJsonObject body =
        BwAccount::cipherRequest(cipher, previousPassword, name, folderId, data, *key, userId);
    previousPassword.fill(QChar(0));

    const BwResponse response = request("PUT", QStringLiteral("/ciphers/") + ref.id, error, body);
    if (!response.ok())
        return false;
    QJsonObject updated = response.json;
    if (updated.value(QStringLiteral("id")).toString().isEmpty()
        && updated.value(QStringLiteral("cipher")).isObject()) {
        updated = updated.value(QStringLiteral("cipher")).toObject();
    }
    if (!updated.value(QStringLiteral("id")).toString().isEmpty()) {
        storeCipher(updated);
    } else {
        QString ignored;
        syncCipher(ref.id, &ignored);
    }

    if (!existingOrgId.isEmpty() && data.collectionsLoaded && !selectedCollections.isEmpty()) {
        QStringList sortedOld = existingCollections;
        QStringList sortedNew = selectedCollections;
        sortedOld.sort();
        sortedNew.sort();
        if (sortedOld != sortedNew) {
            QJsonArray colIds;
            for (const QString &cid : selectedCollections)
                colIds.append(cid);
            const BwResponse colResp = request(
                "PUT", QStringLiteral("/ciphers/%1/collections").arg(ref.id), error,
                QJsonObject{{QStringLiteral("collectionIds"), colIds}});
            if (!colResp.ok())
                return false;
            QString ignored;
            syncCipher(ref.id, &ignored);
        }
    }
    return true;
}

bool BitwardenVault::removeEntry(const QString &entryPath, QString *error) const {
    BwItemRef ref;
    if (!lookup(entryPath, &ref, nullptr, error))
        return false;

    // A soft delete: the item goes to Bitwarden's trash, recoverable from the
    // web vault for 30 days.
    const BwResponse response =
        request("PUT", QStringLiteral("/ciphers/%1/delete").arg(ref.id), error);
    if (!response.ok())
        return false;

    {
        const QMutexLocker locker(&m_mutex);
        QJsonObject trashed = findById(m_state.ciphers, ref.id);
        if (!trashed.isEmpty()) {
            trashed.insert(QStringLiteral("deletedDate"), QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
            upsert(&m_state.ciphers, trashed);
        }
        rebuild();
    }
    persist();
    return true;
}

bool BitwardenVault::renameGroup(const QString &oldGroup, const QString &newName, QString *error) const {
    const QString parent = parentGroup(oldGroup);
    const QString newGroup = parent.isEmpty() ? newName : parent + QLatin1Char('/') + newName;
    const QString oldPrefix = oldGroup + QLatin1Char('/');

    QHash<QString, QString> folders;
    BwKey user;
    {
        const QMutexLocker locker(&m_mutex);
        folders = m_folders;
        user = m_keys.user;
    }

    // Bitwarden nests by name alone, so renaming a group is renaming every
    // folder at or below it. A parent that exists only implicitly has no
    // folder of its own and is covered through its children. Each folder
    // renamed is stored as it goes, so a failure midway still leaves the
    // list showing what actually changed.
    for (auto it = folders.cbegin(); it != folders.cend(); ++it) {
        const QString &name = it.value();
        if (name != oldGroup && !name.startsWith(oldPrefix))
            continue;

        const BwResponse response =
            request("PUT", QStringLiteral("/folders/") + it.key(), error,
                    BwAccount::folderRequest(newGroup + name.mid(oldGroup.size()), user));
        if (!response.ok())
            return false;
        storeFolder(response.json);
    }
    return true;
}

bool BitwardenVault::removeGroup(const QString &group, QString *error) const {
    QString folderId;
    {
        const QMutexLocker locker(&m_mutex);
        folderId = m_index.folders.value(group);
    }
    if (folderId.isEmpty())
        return true;

    const BwResponse response = request("DELETE", QStringLiteral("/folders/") + folderId, error);
    if (!response.ok())
        return false;

    // The server moves what was in the folder to no folder; the copy follows.
    {
        const QMutexLocker locker(&m_mutex);
        removeById(&m_state.folders, folderId);
        for (int i = 0; i < m_state.ciphers.size(); ++i) {
            QJsonObject cipher = m_state.ciphers.at(i).toObject();
            if (cipher.value(QStringLiteral("folderId")).toString() == folderId) {
                cipher.insert(QStringLiteral("folderId"), QJsonValue::Null);
                m_state.ciphers.replace(i, cipher);
            }
        }
        rebuild();
    }
    persist();
    return true;
}

void BitwardenVault::close() {
    m_accessToken.clear();
    {
        const QMutexLocker locker(&m_mutex);
        m_keys = BwKeys();
        m_items.clear();
        m_folders.clear();
        m_collections.clear();
        m_trash.clear();
        m_sends.clear();
        m_index = BwIndex();
    }
}
