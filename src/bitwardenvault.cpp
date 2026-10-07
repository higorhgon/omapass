#include "bitwardenvault.h"

#include "i18n.h"

#include <QJsonArray>
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

bool BitwardenVault::sync(QString *error) {
    if (m_syncedAt.isValid() && m_syncedAt.secsTo(QDateTime::currentDateTimeUtc()) < freshSyncSecs)
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

void BitwardenVault::rebuild() const {
    BwAccount::decryptVault(m_state, m_keys, &m_items, &m_folders);
    m_index = buildBwIndex(m_items, m_folders);
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

bool BitwardenVault::addEntry(const QString &entryPath, const QString &group, const EntryData &data,
                              QString *error) const {
    QString folderId;
    if (!ensureFolder(group, &folderId, error))
        return false;

    BwKey user;
    QString userId;
    {
        const QMutexLocker locker(&m_mutex);
        user = m_keys.user;
        userId = m_state.userId;
    }

    const BwResponse response = request(
        "POST", QStringLiteral("/ciphers"), error,
        BwAccount::cipherRequest(QJsonObject(), QString(), lastSegment(entryPath), folderId, data, user,
                                 userId));
    if (!response.ok())
        return false;
    storeCipher(response.json);
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
    {
        const QMutexLocker locker(&m_mutex);
        userId = m_state.userId;
        cipher = findById(m_state.ciphers, ref.id);
        key = BwAccount::cipherKey(cipher, m_keys);
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
    const QJsonObject body =
        BwAccount::cipherRequest(cipher, previousPassword, name, folderId, data, *key, userId);
    previousPassword.fill(QChar(0));

    const BwResponse response = request("PUT", QStringLiteral("/ciphers/") + ref.id, error, body);
    if (!response.ok())
        return false;
    storeCipher(response.json);
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
        removeById(&m_state.ciphers, ref.id);
        m_items.remove(ref.id);
        m_index = buildBwIndex(m_items, m_folders);
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
    const QMutexLocker locker(&m_mutex);
    m_keys = BwKeys();
    m_items.clear();
    m_folders.clear();
    m_index = BwIndex();
}
