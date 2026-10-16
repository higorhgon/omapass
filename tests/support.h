#pragma once

// What the test classes share: the fixtures, the fake `op`, and the registry
// that lets every tst_*.cpp add its class to the one test binary.

#include <QtTest>

#include <QList>
#include <QTemporaryDir>

#include <utility>

#include "bwaccount.h"
#include "bwcrypto.h"

// ---------------------------------------------------------------- registry

using TestFactory = QObject *(*)();

// Every class registered with OMAPASS_TEST, by name; main.cpp runs them all.
QList<std::pair<QByteArray, TestFactory>> &testRegistry();

struct TestRegistration {
    TestRegistration(const char *name, TestFactory factory) {
        testRegistry().append({QByteArray(name), factory});
    }
};

#define OMAPASS_TEST(Class)                                                                          \
    static const TestRegistration registration##Class(#Class, []() -> QObject * { return new Class; });

// ---------------------------------------------------------------- fixtures

inline QJsonObject bwFixture(const char *name) {
    QFile file(QStringLiteral(OMAPASS_BW_FIXTURES "/") + QLatin1String(name));
    if (!file.open(QIODevice::ReadOnly))
        qFatal("missing fixture %s", name);
    return QJsonDocument::fromJson(file.readAll()).object();
}

// What `bw list items` / `bw list folders` printed, keyed by id the way the
// vault keeps them; the index tests are written against those shapes.
inline QHash<QString, QJsonObject> bwItemsById(const QByteArray &json) {
    QHash<QString, QJsonObject> items;
    for (const QJsonValue &value : QJsonDocument::fromJson(json).array())
        items.insert(value.toObject().value("id").toString(), value.toObject());
    return items;
}

inline QHash<QString, QString> bwFoldersById(const QByteArray &json) {
    QHash<QString, QString> folders;
    for (const QJsonValue &value : QJsonDocument::fromJson(json).array()) {
        const QString id = value.toObject().value("id").toString();
        if (!id.isEmpty())
            folders.insert(id, value.toObject().value("name").toString());
    }
    return folders;
}

// The SDK-made fixture (a data.json as the official CLI writes it) in the
// shape omapass keeps an account in: the same encrypted strings, so the
// reference implementation still decides what decrypting them must give.
inline BwAccountState bwStateFromFixture() {
    const QJsonObject root = bwFixture("data.json");
    const QString prefix = QStringLiteral("user_") + root.value("global_account_activeAccountId").toString() + '_';
    const auto user = [&](const char *key) { return root.value(prefix + QLatin1String(key)); };

    BwAccountState state;
    state.email = QStringLiteral("teste@exemplo.com");
    const QJsonObject unlock = user("masterPasswordUnlock_masterPasswordUnlockKey").toObject();
    const QJsonObject kdf = unlock.value("kdf").toObject();
    state.kdf.type = kdf.value("kdfType").toInt();
    state.kdf.iterations = kdf.value("iterations").toInt();
    state.kdf.memory = kdf.value("memory").toInt();
    state.kdf.parallelism = kdf.value("parallelism").toInt();
    state.salt = unlock.value("salt").toString();
    state.userKey = unlock.value("masterKeyWrappedUserKey").toString();
    state.privateKey = user("crypto_accountCryptographicState").toObject().value("V1").toObject()
                           .value("private_key").toString();

    const QJsonObject organizations = user("crypto_organizationKeys").toObject();
    for (auto it = organizations.constBegin(); it != organizations.constEnd(); ++it)
        state.organizationKeys.insert(it.key(), it.value().toObject().value("key"));

    const QJsonObject folders = user("folder_folders").toObject();
    for (auto it = folders.constBegin(); it != folders.constEnd(); ++it) {
        QJsonObject folder = it.value().toObject();
        folder.insert("id", it.key());
        state.folders.append(folder);
    }
    const QJsonObject ciphers = user("ciphers_ciphers").toObject();
    for (auto it = ciphers.constBegin(); it != ciphers.constEnd(); ++it) {
        QJsonObject cipher = it.value().toObject();
        cipher.insert("id", it.key());
        state.ciphers.append(cipher);
    }
    return state;
}

inline QJsonObject cipherById(const BwAccountState &state, const QString &id) {
    for (const QJsonValue &value : state.ciphers) {
        if (value.toObject().value("id").toString() == id)
            return value.toObject();
    }
    return QJsonObject();
}

inline QString decrypted(const QJsonValue &value, const BwKey &key) {
    return BwCrypto::decryptString(value.toString(), key).value_or(QStringLiteral("<undecryptable>"));
}

// The fake `op` (tests/fakes/op) ahead of the real one, with its state in a
// directory of the test's own. It is the only way to drive the parts that
// talk to a CLI — prompts, sessions, removing an account — without an
// account, a network, or luck.
struct FakeOp {
    QTemporaryDir directory;
    QByteArray originalPath;

    FakeOp() {
        originalPath = qgetenv("PATH");
        qputenv("PATH", QByteArray(OMAPASS_FAKE_CLIS ":") + originalPath);
        qputenv("OP_FAKE_ACCOUNTS", accountsFile().toUtf8());
        qputenv("OP_FAKE_SESSION", sessionFile().toUtf8());
        setAccounts({QStringLiteral("teste")});
    }

    ~FakeOp() {
        qputenv("PATH", originalPath);
        qunsetenv("OP_FAKE_ACCOUNTS");
        qunsetenv("OP_FAKE_SESSION");
    }

    QString accountsFile() const { return directory.filePath(QStringLiteral("accounts")); }
    QString sessionFile() const { return directory.filePath(QStringLiteral("session")); }

    void setAccounts(const QStringList &accounts) {
        QFile file(accountsFile());
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
            qFatal("cannot write the fake op accounts");
        file.write(accounts.join(QLatin1Char('\n')).toUtf8() + '\n');
    }

    void setSignedIn(bool signedIn) {
        if (!signedIn) {
            QFile::remove(sessionFile());
            return;
        }
        QFile file(sessionFile());
        if (!file.open(QIODevice::WriteOnly))
            qFatal("cannot write the fake op session");
    }

    bool signedIn() const { return QFile::exists(sessionFile()); }
};

// The fake `secret-tool` (tests/fakes/secret-tool) ahead of any real one,
// keeping its "keyring" in a directory of the test's own.
struct FakeSecretTool {
    QTemporaryDir directory;
    QByteArray originalPath;

    FakeSecretTool() {
        originalPath = qgetenv("PATH");
        qputenv("PATH", QByteArray(OMAPASS_FAKE_CLIS ":") + originalPath);
        qputenv("SECRET_TOOL_FAKE_DIR", QFile::encodeName(directory.path()));
    }

    ~FakeSecretTool() {
        qputenv("PATH", originalPath);
        qunsetenv("SECRET_TOOL_FAKE_DIR");
    }

    // Every command line the fake was run with, one per line.
    QString arguments() const {
        QFile file(directory.filePath(QStringLiteral("argv.log")));
        return file.open(QIODevice::ReadOnly) ? QString::fromUtf8(file.readAll()) : QString();
    }
};

// PATH replaced for the lifetime of the object, for the cases where a
// program has to be missing.
struct PathOverride {
    QByteArray originalPath;

    explicit PathOverride(const QByteArray &path) : originalPath(qgetenv("PATH")) {
        qputenv("PATH", path);
    }
    ~PathOverride() { qputenv("PATH", originalPath); }
};

inline QByteArray opFixture(const char *name) {
    QFile file(QStringLiteral(OMAPASS_OP_FIXTURES "/") + QLatin1String(name));
    if (!file.open(QIODevice::ReadOnly))
        qFatal("missing fixture %s", name);
    return file.readAll();
}

inline BwBytes bwHex(const QString &hex) {
    const QByteArray bytes = QByteArray::fromHex(hex.toLatin1());
    return BwBytes(bytes.cbegin(), bytes.cend());
}

inline constexpr char bwFolders[] =
    "["
    "{\"object\":\"folder\",\"id\":\"f1\",\"name\":\"Work/Mail\"},"
    "{\"object\":\"folder\",\"id\":\"f2\",\"name\":\"Empty\"},"
    "{\"object\":\"folder\",\"id\":null,\"name\":\"No Folder\"}]";

inline constexpr char bwItems[] =
    "["
    "{\"id\":\"i1\",\"type\":1,\"name\":\"Gmail\",\"folderId\":\"f1\",\"login\":{\"password\":\"x\"}},"
    "{\"id\":\"i2\",\"type\":1,\"name\":\"Bank\",\"folderId\":null},"
    "{\"id\":\"i3\",\"type\":2,\"name\":\"A note\",\"folderId\":null},"
    "{\"id\":\"i4\",\"type\":1,\"name\":\"Lost\",\"folderId\":\"gone\"}]";

inline constexpr char bwDuplicateItems[] =
    "["
    "{\"id\":\"aaaaaaaa-1111\",\"type\":1,\"name\":\"Mail\",\"folderId\":null},"
    "{\"id\":\"bbbbbbbb-2222\",\"type\":1,\"name\":\"Mail\",\"folderId\":null},"
    "{\"id\":\"cccccccc-3333\",\"type\":1,\"name\":\"a/b\",\"folderId\":null}]";

inline constexpr char bwItemWithExtras[] =
    "{\"id\":\"i1\",\"type\":1,\"name\":\"Old\",\"folderId\":\"f1\",\"notes\":\"n\","
    "\"organizationId\":\"o1\",\"fields\":[{\"name\":\"pin\",\"value\":\"1234\",\"type\":1}],"
    "\"login\":{\"username\":\"u\",\"password\":\"p\",\"totp\":\"otpauth://x\","
    "\"uris\":[{\"match\":null,\"uri\":\"https://a\"},{\"match\":null,\"uri\":\"https://b\"}]}}";
