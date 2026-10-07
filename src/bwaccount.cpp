#include "bwaccount.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QSaveFile>
#include <QStandardPaths>

namespace {

const auto refPrefix = QStringLiteral("bitwarden:");

// Marks a field that should decrypt and does not.
struct Undecryptable {};

QJsonValue decryptField(const QJsonValue &value, const BwKey &key) {
    if (value.isNull() || value.isUndefined())
        return QJsonValue::Null;
    if (!value.isString())
        throw Undecryptable();
    const std::optional<QString> text = BwCrypto::decryptString(value.toString(), key);
    if (!text)
        throw Undecryptable();
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

// A field to send: encrypted, or null when there is nothing in it.
QJsonValue encryptedField(const QString &text, const BwKey &key) {
    if (text.isEmpty())
        return QJsonValue::Null;
    QByteArray bytes = text.toUtf8();
    const std::optional<QString> encrypted = BwCrypto::encrypt(bytes, key);
    bytes.fill('\0');
    return encrypted ? QJsonValue(*encrypted) : QJsonValue(QJsonValue::Null);
}

// How many old passwords an item keeps, as in the official clients.
constexpr int passwordHistoryLength = 5;

QString fileFor(const QString &refPath) {
    const QByteArray hash = QCryptographicHash::hash(refPath.toUtf8(), QCryptographicHash::Sha256).toHex();
    return BwAccount::directory() + QLatin1Char('/') + QString::fromLatin1(hash.left(32))
        + QStringLiteral(".json");
}

QJsonObject kdfToJson(const BwKdf &kdf) {
    return {{QStringLiteral("type"), kdf.type},
            {QStringLiteral("iterations"), kdf.iterations},
            {QStringLiteral("memory"), kdf.memory},
            {QStringLiteral("parallelism"), kdf.parallelism}};
}

BwKdf kdfFromJson(const QJsonObject &object) {
    BwKdf kdf;
    kdf.type = object.value(QStringLiteral("type")).toInt(-1);
    kdf.iterations = object.value(QStringLiteral("iterations")).toInt();
    kdf.memory = object.value(QStringLiteral("memory")).toInt();
    kdf.parallelism = object.value(QStringLiteral("parallelism")).toInt();
    return kdf;
}

}

QString BwAccount::directory() {
    return QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
        + QStringLiteral("/omapass/bitwarden");
}

QString BwAccount::refPath(const QString &email, const QString &server) {
    return server.isEmpty() ? refPrefix + email : refPrefix + email + QLatin1Char('|') + server;
}

QString BwAccount::emailOf(const QString &path) {
    const QString rest = path.startsWith(refPrefix) ? path.mid(refPrefix.size()) : path;
    return rest.section(QLatin1Char('|'), 0, 0);
}

QString BwAccount::serverOf(const QString &path) {
    const QString rest = path.startsWith(refPrefix) ? path.mid(refPrefix.size()) : path;
    return rest.section(QLatin1Char('|'), 1);
}

QStringList BwAccount::refPaths() {
    QStringList paths;
    const QDir dir(directory());
    const QStringList files = dir.entryList({QStringLiteral("*.json")}, QDir::Files, QDir::Name);
    for (const QString &name : files) {
        QFile file(dir.filePath(name));
        if (!file.open(QIODevice::ReadOnly))
            continue;
        // Only the two plain fields are wanted; the rest stays encrypted
        // either way.
        const QJsonObject root = QJsonDocument::fromJson(file.readAll()).object();
        const QString email = root.value(QStringLiteral("email")).toString();
        if (!email.isEmpty())
            paths.append(refPath(email, root.value(QStringLiteral("server")).toString()));
    }
    paths.sort(Qt::CaseInsensitive);
    return paths;
}

std::optional<BwAccountState> BwAccount::load(const QString &path) {
    QFile file(fileFor(path));
    if (!file.open(QIODevice::ReadOnly))
        return std::nullopt;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    if (!document.isObject())
        return std::nullopt;

    const QJsonObject root = document.object();
    BwAccountState state;
    state.server = root.value(QStringLiteral("server")).toString();
    state.email = root.value(QStringLiteral("email")).toString();
    state.userId = root.value(QStringLiteral("userId")).toString();
    state.salt = root.value(QStringLiteral("salt")).toString();
    state.kdf = kdfFromJson(root.value(QStringLiteral("kdf")).toObject());
    state.userKey = root.value(QStringLiteral("userKey")).toString();
    state.privateKey = root.value(QStringLiteral("privateKey")).toString();
    state.refreshToken = root.value(QStringLiteral("refreshToken")).toString();
    state.organizationKeys = root.value(QStringLiteral("organizationKeys")).toObject();
    state.folders = root.value(QStringLiteral("folders")).toArray();
    state.ciphers = root.value(QStringLiteral("ciphers")).toArray();

    if (state.email.isEmpty() || refPath(state.email, state.server) != path)
        return std::nullopt;
    return state;
}

bool BwAccount::save(const BwAccountState &state, QString *error) {
    QDir dir;
    if (!dir.mkpath(directory())) {
        *error = QStringLiteral("cannot create %1").arg(directory());
        return false;
    }
    QFile::setPermissions(directory(), QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                           | QFileDevice::ExeOwner);

    const QJsonObject root{
        {QStringLiteral("version"), 1},
        {QStringLiteral("server"), state.server},
        {QStringLiteral("email"), state.email},
        {QStringLiteral("userId"), state.userId},
        {QStringLiteral("salt"), state.salt},
        {QStringLiteral("kdf"), kdfToJson(state.kdf)},
        {QStringLiteral("userKey"), state.userKey},
        {QStringLiteral("privateKey"), state.privateKey},
        {QStringLiteral("refreshToken"), state.refreshToken},
        {QStringLiteral("organizationKeys"), state.organizationKeys},
        {QStringLiteral("folders"), state.folders},
        {QStringLiteral("ciphers"), state.ciphers},
    };

    // Written aside and renamed over the old one: a crash midway never
    // leaves half a vault behind.
    QSaveFile file(fileFor(refPath(state.email, state.server)));
    if (!file.open(QIODevice::WriteOnly)) {
        *error = file.errorString();
        return false;
    }
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    file.write(QJsonDocument(root).toJson(QJsonDocument::Compact));
    if (!file.commit()) {
        *error = file.errorString();
        return false;
    }
    return true;
}

void BwAccount::remove(const QString &path) {
    QFile::remove(fileFor(path));
}

BwAccount::Unlock BwAccount::unlock(const BwAccountState &state, const Secret &password, BwKeys *keys) {
    if (state.salt.isEmpty() || !state.userKey.startsWith(QLatin1String("2.")))
        return Unlock::Unsupported;

    const std::optional<BwKey> masterKey = BwCrypto::deriveMasterKey(password, state.salt, state.kdf);
    if (!masterKey)
        return Unlock::Unsupported;

    // The user key is an authenticated type 2 string: failing to open it
    // with a correctly derived key means the password is wrong.
    const std::optional<BwKey> userKey = BwCrypto::unwrapKey(state.userKey, *masterKey);
    if (!userKey)
        return Unlock::WrongPassword;

    keys->user = *userKey;
    keys->organizations = organizationKeys(state, *userKey);
    return Unlock::Ok;
}

QHash<QString, BwKey> BwAccount::organizationKeys(const BwAccountState &state, const BwKey &user) {
    QHash<QString, BwKey> keys;
    if (state.organizationKeys.isEmpty())
        return keys;

    const std::optional<BwBytes> privateKey = BwCrypto::decrypt(state.privateKey, user);
    if (!privateKey)
        return keys;

    for (auto it = state.organizationKeys.constBegin(); it != state.organizationKeys.constEnd(); ++it) {
        const std::optional<BwBytes> bytes = BwCrypto::rsaDecrypt(it.value().toString(), *privateKey);
        const std::optional<BwKey> key = bytes ? BwCrypto::keyFromBytes(*bytes) : std::nullopt;
        if (key)
            keys.insert(it.key(), *key);
    }
    return keys;
}

void BwAccount::applySync(BwAccountState *state, const QJsonObject &sync) {
    const QJsonObject profile = sync.value(QStringLiteral("profile")).toObject();

    const QString userId = profile.value(QStringLiteral("id")).toString();
    if (!userId.isEmpty())
        state->userId = userId;

    const QString userKey = profile.value(QStringLiteral("key")).toString();
    if (!userKey.isEmpty())
        state->userKey = userKey;

    QString privateKey = profile.value(QStringLiteral("privateKey")).toString();
    if (privateKey.isEmpty()) {
        privateKey = profile.value(QStringLiteral("accountKeys")).toObject()
                         .value(QStringLiteral("publicKeyEncryptionKeyPair")).toObject()
                         .value(QStringLiteral("wrappedPrivateKey")).toString();
    }
    if (!privateKey.isEmpty())
        state->privateKey = privateKey;

    // Newer servers say how the master password opens the account; older
    // ones leave it to prelogin, which is what the state already has.
    const QJsonObject unlock = sync.value(QStringLiteral("userDecryption")).toObject()
                                   .value(QStringLiteral("masterPasswordUnlock")).toObject();
    if (!unlock.isEmpty()) {
        const QJsonObject kdf = unlock.value(QStringLiteral("kdf")).toObject();
        if (kdf.contains(QStringLiteral("kdfType"))) {
            state->kdf.type = kdf.value(QStringLiteral("kdfType")).toInt();
            state->kdf.iterations = kdf.value(QStringLiteral("iterations")).toInt();
            state->kdf.memory = kdf.value(QStringLiteral("memory")).toInt();
            state->kdf.parallelism = kdf.value(QStringLiteral("parallelism")).toInt();
        }
        const QString salt = unlock.value(QStringLiteral("salt")).toString();
        if (!salt.isEmpty())
            state->salt = salt;
        const QString wrapped = unlock.value(QStringLiteral("masterKeyEncryptedUserKey")).toString();
        if (!wrapped.isEmpty())
            state->userKey = wrapped;
    }

    QJsonObject organizations;
    const QJsonArray profileOrganizations = profile.value(QStringLiteral("organizations")).toArray();
    for (const QJsonValue &value : profileOrganizations) {
        const QJsonObject organization = value.toObject();
        const QString id = organization.value(QStringLiteral("id")).toString();
        const QString key = organization.value(QStringLiteral("key")).toString();
        if (!id.isEmpty() && !key.isEmpty())
            organizations.insert(id, key);
    }
    state->organizationKeys = organizations;

    state->folders = sync.value(QStringLiteral("folders")).toArray();
    state->ciphers = sync.value(QStringLiteral("ciphers")).toArray();
}

std::optional<BwKey> BwAccount::cipherKey(const QJsonObject &cipher, const BwKeys &keys) {
    const QString organizationId = cipher.value(QStringLiteral("organizationId")).toString();
    BwKey baseKey = keys.user;
    if (!organizationId.isEmpty()) {
        if (!keys.organizations.contains(organizationId))
            return std::nullopt;
        baseKey = keys.organizations.value(organizationId);
    }

    // Newer items carry a key of their own, wrapped with the user's or the
    // organisation's key; older ones use that key directly.
    const QJsonValue wrapped = cipher.value(QStringLiteral("key"));
    if (wrapped.isString() && !wrapped.toString().isEmpty())
        return BwCrypto::unwrapKey(wrapped.toString(), baseKey);
    return baseKey;
}

std::optional<QJsonObject> BwAccount::decryptCipher(const QJsonObject &cipher, const BwKeys &keys) {
    if (cipher.value(QStringLiteral("type")).toInt() != 1)
        return std::nullopt;
    const QJsonValue deleted = cipher.value(QStringLiteral("deletedDate"));
    if (!deleted.isNull() && !deleted.isUndefined())
        return std::nullopt;

    const std::optional<BwKey> key = cipherKey(cipher, keys);
    if (!key)
        return std::nullopt;

    try {
        QJsonObject item;
        item.insert(QStringLiteral("object"), QStringLiteral("item"));
        item.insert(QStringLiteral("id"), cipher.value(QStringLiteral("id")));
        item.insert(QStringLiteral("type"), 1);
        item.insert(QStringLiteral("organizationId"), cipher.value(QStringLiteral("organizationId")));
        item.insert(QStringLiteral("folderId"), cipher.value(QStringLiteral("folderId")));
        item.insert(QStringLiteral("collectionIds"), cipher.value(QStringLiteral("collectionIds")));
        item.insert(QStringLiteral("revisionDate"), cipher.value(QStringLiteral("revisionDate")));
        item.insert(QStringLiteral("deletedDate"), QJsonValue::Null);
        item.insert(QStringLiteral("name"), decryptField(cipher.value(QStringLiteral("name")), *key));
        item.insert(QStringLiteral("notes"), decryptField(cipher.value(QStringLiteral("notes")), *key));
        item.insert(QStringLiteral("login"), decryptLogin(cipher, *key));
        return item;
    } catch (const Undecryptable &) {
        return std::nullopt;
    }
}

QString BwAccount::decryptFolder(const QJsonObject &folder, const BwKey &user) {
    const std::optional<QString> name =
        BwCrypto::decryptString(folder.value(QStringLiteral("name")).toString(), user);
    if (!name)
        return QString();
    QString text = *name;
    while (text.endsWith(QLatin1Char('/')))
        text.chop(1);
    return text;
}

QJsonObject BwAccount::cipherRequest(const QJsonObject &encrypted, const QString &previousPassword,
                                     const QString &name, const QString &folderId,
                                     const EntryData &data, const BwKey &key,
                                     const QString &userId) {
    QJsonObject request = encrypted;
    if (request.isEmpty()) {
        request = QJsonObject{
            {QStringLiteral("type"), 1},
            {QStringLiteral("organizationId"), QJsonValue::Null},
            {QStringLiteral("favorite"), false},
            {QStringLiteral("reprompt"), 0},
            {QStringLiteral("fields"), QJsonValue::Null},
            {QStringLiteral("passwordHistory"), QJsonValue::Null},
            {QStringLiteral("login"), QJsonObject{{QStringLiteral("uris"), QJsonArray()},
                                                  {QStringLiteral("totp"), QJsonValue::Null}}},
        };
    } else {
        // The server checks this against its own copy, so an edit made from
        // a stale one is refused rather than silently undoing another.
        request.insert(QStringLiteral("lastKnownRevisionDate"), encrypted.value(QStringLiteral("revisionDate")));
    }

    // Servers check that what they are given was encrypted by the account
    // sending it, so a client with stale keys cannot overwrite an item.
    request.insert(QStringLiteral("encryptedFor"), userId);
    request.insert(QStringLiteral("name"), encryptedField(name, key));
    request.insert(QStringLiteral("notes"), encryptedField(data.notes, key));
    request.insert(QStringLiteral("folderId"), folderId.isEmpty() ? QJsonValue(QJsonValue::Null)
                                                                  : QJsonValue(folderId));

    QJsonObject login = request.value(QStringLiteral("login")).toObject();
    login.insert(QStringLiteral("username"), encryptedField(data.username, key));

    QString password = data.password.toString();
    if (!encrypted.isEmpty() && password != previousPassword) {
        const QString now = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
        if (!previousPassword.isEmpty()) {
            QJsonArray history = request.value(QStringLiteral("passwordHistory")).toArray();
            history.prepend(QJsonObject{{QStringLiteral("lastUsedDate"), now},
                                        {QStringLiteral("password"), encryptedField(previousPassword, key)}});
            while (history.size() > passwordHistoryLength)
                history.removeLast();
            request.insert(QStringLiteral("passwordHistory"), history);
        }
        login.insert(QStringLiteral("passwordRevisionDate"), now);
    }
    login.insert(QStringLiteral("password"), encryptedField(password, key));
    password.fill(QChar(0));

    // Only the first URI is the form's. Its checksum lets clients detect a
    // URI swapped between items, so it is rewritten along with it.
    QJsonArray uris = login.value(QStringLiteral("uris")).toArray();
    if (data.url.isEmpty()) {
        if (!uris.isEmpty())
            uris.removeFirst();
    } else {
        QJsonObject first = uris.isEmpty() ? QJsonObject{{QStringLiteral("match"), QJsonValue::Null}}
                                           : uris.first().toObject();
        first.insert(QStringLiteral("uri"), encryptedField(data.url, key));
        const QByteArray checksum =
            QCryptographicHash::hash(data.url.toUtf8(), QCryptographicHash::Sha256).toBase64();
        first.insert(QStringLiteral("uriChecksum"), encryptedField(QString::fromLatin1(checksum), key));
        if (uris.isEmpty())
            uris.append(first);
        else
            uris.replace(0, first);
    }
    login.insert(QStringLiteral("uris"), uris);
    request.insert(QStringLiteral("login"), login);
    return request;
}

QJsonObject BwAccount::folderRequest(const QString &name, const BwKey &user) {
    return {{QStringLiteral("name"), encryptedField(name, user)}};
}

void BwAccount::decryptVault(const BwAccountState &state, const BwKeys &keys,
                             QHash<QString, QJsonObject> *items, QHash<QString, QString> *folders) {
    items->clear();
    folders->clear();

    for (const QJsonValue &value : state.folders) {
        const QJsonObject folder = value.toObject();
        const QString id = folder.value(QStringLiteral("id")).toString();
        const QString name = decryptFolder(folder, keys.user);
        if (!id.isEmpty() && !name.isEmpty())
            folders->insert(id, name);
    }

    for (const QJsonValue &value : state.ciphers) {
        const QJsonObject cipher = value.toObject();
        if (const std::optional<QJsonObject> item = decryptCipher(cipher, keys))
            items->insert(item->value(QStringLiteral("id")).toString(), *item);
    }
}
