#include <QtTest>

#include "bitwardenjson.h"
#include "bwaccount.h"
#include "bwapi.h"
#include "pin.h"
#include "bwcrypto.h"
#include "config.h"
#include "filter.h"
#include "generator.h"
#include "history.h"
#include "i18n.h"
#include "kdbx2pass.h"
#include "onepasswordlogin.h"
#include "onepasswordvault.h"
#include "opjson.h"
#include "passstore.h"
#include "secret.h"

namespace {

QJsonObject bwFixture(const char *name) {
    QFile file(QStringLiteral(OMAPASS_BW_FIXTURES "/") + QLatin1String(name));
    if (!file.open(QIODevice::ReadOnly))
        qFatal("missing fixture %s", name);
    return QJsonDocument::fromJson(file.readAll()).object();
}

// What `bw list items` / `bw list folders` printed, keyed by id the way the
// vault keeps them; the index tests are written against those shapes.
QHash<QString, QJsonObject> bwItemsById(const QByteArray &json) {
    QHash<QString, QJsonObject> items;
    for (const QJsonValue &value : QJsonDocument::fromJson(json).array())
        items.insert(value.toObject().value("id").toString(), value.toObject());
    return items;
}

QHash<QString, QString> bwFoldersById(const QByteArray &json) {
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
BwAccountState bwStateFromFixture() {
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

QJsonObject cipherById(const BwAccountState &state, const QString &id) {
    for (const QJsonValue &value : state.ciphers) {
        if (value.toObject().value("id").toString() == id)
            return value.toObject();
    }
    return QJsonObject();
}

QString decrypted(const QJsonValue &value, const BwKey &key) {
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
        file.open(QIODevice::WriteOnly | QIODevice::Truncate);
        file.write(accounts.join(QLatin1Char('\n')).toUtf8() + '\n');
    }

    void setSignedIn(bool signedIn) {
        if (!signedIn) {
            QFile::remove(sessionFile());
            return;
        }
        QFile file(sessionFile());
        file.open(QIODevice::WriteOnly);
    }

    bool signedIn() const { return QFile::exists(sessionFile()); }
};

QByteArray opFixture(const char *name) {
    QFile file(QStringLiteral(OMAPASS_OP_FIXTURES "/") + QLatin1String(name));
    if (!file.open(QIODevice::ReadOnly))
        qFatal("missing fixture %s", name);
    return file.readAll();
}

BwBytes bwHex(const QString &hex) {
    const QByteArray bytes = QByteArray::fromHex(hex.toLatin1());
    return BwBytes(bytes.cbegin(), bytes.cend());
}

const char bwFolders[] =
    "["
    "{\"object\":\"folder\",\"id\":\"f1\",\"name\":\"Work/Mail\"},"
    "{\"object\":\"folder\",\"id\":\"f2\",\"name\":\"Empty\"},"
    "{\"object\":\"folder\",\"id\":null,\"name\":\"No Folder\"}]";

const char bwItems[] =
    "["
    "{\"id\":\"i1\",\"type\":1,\"name\":\"Gmail\",\"folderId\":\"f1\",\"login\":{\"password\":\"x\"}},"
    "{\"id\":\"i2\",\"type\":1,\"name\":\"Bank\",\"folderId\":null},"
    "{\"id\":\"i3\",\"type\":2,\"name\":\"A note\",\"folderId\":null},"
    "{\"id\":\"i4\",\"type\":1,\"name\":\"Lost\",\"folderId\":\"gone\"}]";

const char bwDuplicateItems[] =
    "["
    "{\"id\":\"aaaaaaaa-1111\",\"type\":1,\"name\":\"Mail\",\"folderId\":null},"
    "{\"id\":\"bbbbbbbb-2222\",\"type\":1,\"name\":\"Mail\",\"folderId\":null},"
    "{\"id\":\"cccccccc-3333\",\"type\":1,\"name\":\"a/b\",\"folderId\":null}]";

const char bwItemWithExtras[] =
    "{\"id\":\"i1\",\"type\":1,\"name\":\"Old\",\"folderId\":\"f1\",\"notes\":\"n\","
    "\"organizationId\":\"o1\",\"fields\":[{\"name\":\"pin\",\"value\":\"1234\",\"type\":1}],"
    "\"login\":{\"username\":\"u\",\"password\":\"p\",\"totp\":\"otpauth://x\","
    "\"uris\":[{\"match\":null,\"uri\":\"https://a\"},{\"match\":null,\"uri\":\"https://b\"}]}}";

}

class TestOmapass : public QObject {
    Q_OBJECT

private slots:
    void initTestCase() {
        I18n::load(QStringLiteral("pt-BR"));
    }

    void filterEmptyQueryReturnsEverything() {
        const QStringList items = {QStringLiteral("a"), QStringLiteral("b")};
        QCOMPARE(filterItems(items, QString()), items);
    }

    void filterIsCaseInsensitive() {
        const QStringList items = {QStringLiteral("GitHub/user"), QStringLiteral("Bank/acct")};
        QCOMPARE(filterItems(items, QStringLiteral("github")),
                 QStringList{QStringLiteral("GitHub/user")});
    }

    void filterRequiresEveryTerm() {
        const QStringList items = {QStringLiteral("Work/GitHub"), QStringLiteral("Personal/GitHub"),
                                   QStringLiteral("Work/GitLab")};
        QCOMPARE(filterItems(items, QStringLiteral("work github")),
                 QStringList{QStringLiteral("Work/GitHub")});
    }

    void filterWithoutMatchesReturnsNothing() {
        QVERIFY(filterItems({QStringLiteral("a")}, QStringLiteral("zzz")).isEmpty());
    }

    void languageFromConfigBeatsEnvironment() {
        QCOMPARE(Config::resolveLanguage(QStringLiteral("en"), QStringLiteral("pt_BR.UTF-8"), QString()),
                 QStringLiteral("en"));
        QCOMPARE(Config::resolveLanguage(QStringLiteral("pt-BR"), QStringLiteral("en_US.UTF-8"), QString()),
                 QStringLiteral("pt-BR"));
    }

    void languageIsDetectedFromEnvironment() {
        QCOMPARE(Config::resolveLanguage(QString(), QStringLiteral("en_US.UTF-8"), QString()),
                 QStringLiteral("en"));
        QCOMPARE(Config::resolveLanguage(QStringLiteral("auto"), QStringLiteral("pt_PT.UTF-8"), QString()),
                 QStringLiteral("pt-BR"));
    }

    void languageFallsBackToLcAllThenEnglish() {
        QCOMPARE(Config::resolveLanguage(QString(), QString(), QStringLiteral("pt_BR.UTF-8")),
                 QStringLiteral("pt-BR"));
        QCOMPARE(Config::resolveLanguage(QString(), QString(), QString()), QStringLiteral("en"));
        QCOMPARE(Config::resolveLanguage(QString(), QStringLiteral("fr_FR.UTF-8"), QString()),
                 QStringLiteral("en"));
    }

    void tomlEditsKeepEverythingElseInPlace() {
        const QString original = QStringLiteral(
            "[general]\n"
            "# quanto tempo até travar\n"
            "path = \"~/\"  # comentário do valor\n"
            "lock_minutes = 10\n"
            "algo_que_nao_conheco = 1\n"
            "\n"
            "[generator]\n"
            "wordlist = \"auto\"\n");

        QMap<QString, QString> values;
        values.insert(QStringLiteral("general.path"), Config::tomlString(QStringLiteral("~/docs")));
        values.insert(QStringLiteral("general.recency"), QStringLiteral("false"));
        values.insert(QStringLiteral("generator.wordlist"), Config::tomlString(QStringLiteral("pt-BR")));

        const QString edited = Config::applyTomlEdits(original, values);

        // Changed values, with the comment after the value kept.
        QVERIFY(edited.contains(QStringLiteral("path = \"~/docs\"  # comentário do valor")));
        QVERIFY(edited.contains(QStringLiteral("wordlist = \"pt-BR\"")));
        // A key that did not exist lands in its own section, not at the end.
        QVERIFY(edited.indexOf(QStringLiteral("recency = false")) > edited.indexOf(QStringLiteral("[general]")));
        QVERIFY(edited.indexOf(QStringLiteral("recency = false")) < edited.indexOf(QStringLiteral("[generator]")));
        // Comments, untouched keys and the rest stay as they were.
        QVERIFY(edited.contains(QStringLiteral("# quanto tempo até travar")));
        QVERIFY(edited.contains(QStringLiteral("algo_que_nao_conheco = 1")));
        QVERIFY(edited.contains(QStringLiteral("lock_minutes = 10")));

        const QHash<QString, QString> reread = [&edited]() {
            QTemporaryDir dir;
            const QString path = dir.filePath(QStringLiteral("config.toml"));
            QFile file(path);
            file.open(QIODevice::WriteOnly);
            file.write(edited.toUtf8());
            file.close();
            return Config::readFlatToml(path);
        }();
        QCOMPARE(reread.value(QStringLiteral("general.path")), QStringLiteral("~/docs"));
        QCOMPARE(reread.value(QStringLiteral("general.recency")), QStringLiteral("false"));
        QCOMPARE(reread.value(QStringLiteral("generator.wordlist")), QStringLiteral("pt-BR"));
    }

    void tomlEditsCreateAMissingSection() {
        const QString edited = Config::applyTomlEdits(
            QStringLiteral("[general]\npath = \"~/\"\n"),
            {{QStringLiteral("generator.wordlist"), Config::tomlString(QStringLiteral("en"))}});

        QVERIFY(edited.contains(QStringLiteral("[generator]")));
        QVERIFY(edited.indexOf(QStringLiteral("wordlist = \"en\"")) > edited.indexOf(QStringLiteral("[generator]")));

        // An empty file still comes out readable.
        const QString fromEmpty = Config::applyTomlEdits(
            QString(), {{QStringLiteral("general.recency"), QStringLiteral("true")}});
        QVERIFY(fromEmpty.contains(QStringLiteral("[general]")));
        QVERIFY(fromEmpty.endsWith(QLatin1Char('\n')));
    }

    void flatTomlReadsSectionsAndStripsQuotes() {
        QTemporaryFile file;
        QVERIFY(file.open());
        file.write("# a comment\n[general]\npath = \"~/docs\"\nrecency = true\n\n"
                   "[colors]\nTitle = '#00AAAA'  \n");
        file.close();

        const QHash<QString, QString> values = Config::readFlatToml(file.fileName());
        QCOMPARE(values.value(QStringLiteral("general.path")), QStringLiteral("~/docs"));
        QCOMPARE(values.value(QStringLiteral("general.recency")), QStringLiteral("true"));
        QCOMPARE(values.value(QStringLiteral("colors.Title")), QStringLiteral("#00AAAA"));

        // A quoted value keeps a '#' of its own and drops a comment after it.
        QTemporaryFile withComments;
        QVERIFY(withComments.open());
        withComments.write("[general]\npath = \"~/a#b\"  # comentário\nrecency = true # outro\n");
        withComments.close();

        const QHash<QString, QString> parsed = Config::readFlatToml(withComments.fileName());
        QCOMPARE(parsed.value(QStringLiteral("general.path")), QStringLiteral("~/a#b"));
        QCOMPARE(parsed.value(QStringLiteral("general.recency")), QStringLiteral("true"));
    }

    void lockMinutesDefaultsToTenWhenAbsent() {
        QCOMPARE(Config::parseLockMinutes(QString()), std::optional<int>(10));
    }

    void lockMinutesFalseDisablesAutoLock() {
        QCOMPARE(Config::parseLockMinutes(QStringLiteral("false")), std::optional<int>());
    }

    void lockMinutesAcceptsAPositiveInteger() {
        QCOMPARE(Config::parseLockMinutes(QStringLiteral("30")), std::optional<int>(30));
        QCOMPARE(Config::parseLockMinutes(QStringLiteral("1")), std::optional<int>(1));
    }

    void lockMinutesFallsBackToDefaultOnInvalidValues() {
        const std::optional<int> tenMinutes(10);
        QCOMPARE(Config::parseLockMinutes(QStringLiteral("0")), tenMinutes);
        QCOMPARE(Config::parseLockMinutes(QStringLiteral("-5")), tenMinutes);
        QCOMPARE(Config::parseLockMinutes(QStringLiteral("true")), tenMinutes);
        QCOMPARE(Config::parseLockMinutes(QStringLiteral("nunca")), tenMinutes);
    }

    void translationsInterpolateArguments() {
        const QString text = I18n::t(QStringLiteral("cli.version"), QStringLiteral("version"),
                                     QStringLiteral("9.9.9"));
        QVERIFY(text.contains(QStringLiteral("9.9.9")));
        QVERIFY(!text.contains(QStringLiteral("%{")));
    }

    void unknownTranslationKeyFallsBackToItself() {
        QCOMPARE(I18n::t(QStringLiteral("no.such.key")), QStringLiteral("no.such.key"));
    }

    void passEntryParsesEveryModelledField() {
        const PassEntryData data = parsePassEntry(
            QStringLiteral("s3cr3t\nusername: fulano\nurl: https://exemplo.com.br\nnotes: vip\n"));
        QCOMPARE(data.password.toString(), QStringLiteral("s3cr3t"));
        QCOMPARE(data.username, QStringLiteral("fulano"));
        QCOMPARE(data.url, QStringLiteral("https://exemplo.com.br"));
        QCOMPARE(data.extra, QStringList{QStringLiteral("notes: vip")});
    }

    void passEntryAcceptsAlternativeUsernameKeys() {
        QCOMPARE(parsePassEntry(QStringLiteral("x\nlogin: hg\n")).username, QStringLiteral("hg"));
        QCOMPARE(parsePassEntry(QStringLiteral("x\nUser: HG\n")).username, QStringLiteral("HG"));
    }

    void passEntryWithOnlyAPasswordHasNoMetadata() {
        const PassEntryData data = parsePassEntry(QStringLiteral("apenas-a-senha\n"));
        QCOMPARE(data.password.toString(), QStringLiteral("apenas-a-senha"));
        QVERIFY(data.username.isEmpty());
        QVERIFY(data.url.isEmpty());
        QVERIFY(data.extra.isEmpty());
    }

    void passEntryRoundTripsThroughBuild() {
        const QString original =
            QStringLiteral("senha\nusername: hg\nurl: https://a.b\ncustom: data\n");
        QCOMPARE(QString::fromUtf8(buildPassEntryContent(parsePassEntry(original))), original);
    }

    void passEntryBuildKeepsUnmodelledLines() {
        PassEntryData data;
        data.password = Secret(QStringLiteral("p"));
        data.username = QStringLiteral("u");
        data.url = QStringLiteral("https://x");
        data.extra = {QStringLiteral("otp: ABCDEF"), QStringLiteral("notes: manter")};
        QCOMPARE(QString::fromUtf8(buildPassEntryContent(data)),
                 QStringLiteral("p\nusername: u\nurl: https://x\notp: ABCDEF\nnotes: manter\n"));
    }

    void csvParsesPlainRows() {
        const QVector<QStringList> rows = Kdbx2Pass::parseCsv(QStringLiteral("a,b,c\n1,2,3\n"));
        QCOMPARE(rows.size(), 2);
        QCOMPARE(rows.at(0), QStringList({QStringLiteral("a"), QStringLiteral("b"), QStringLiteral("c")}));
        QCOMPARE(rows.at(1), QStringList({QStringLiteral("1"), QStringLiteral("2"), QStringLiteral("3")}));
    }

    void csvKeepsCommasAndNewlinesInsideQuotes() {
        const QVector<QStringList> rows =
            Kdbx2Pass::parseCsv(QStringLiteral("Title,Notes\nfoo,\"linha1,\nlinha2\"\n"));
        QCOMPARE(rows.size(), 2);
        QCOMPARE(rows.at(1).at(1), QStringLiteral("linha1,\nlinha2"));
    }

    void csvUnescapesDoubledQuotes() {
        const QVector<QStringList> rows =
            Kdbx2Pass::parseCsv(QStringLiteral("Title\n\"ele disse \"\"oi\"\"\"\n"));
        QCOMPARE(rows.at(1).at(0), QStringLiteral("ele disse \"oi\""));
    }

    void csvAcceptsAMissingTrailingNewline() {
        const QVector<QStringList> rows = Kdbx2Pass::parseCsv(QStringLiteral("a,b\n1,2"));
        QCOMPARE(rows.size(), 2);
        QCOMPARE(rows.at(1), QStringList({QStringLiteral("1"), QStringLiteral("2")}));
    }

    void titlesAreSanitisedForTheFilesystem() {
        QCOMPARE(Kdbx2Pass::sanitizeTitle(QStringLiteral("Banco: Conta #1")),
                 QStringLiteral("Banco_ Conta _1"));
        QCOMPARE(Kdbx2Pass::sanitizeTitle(QStringLiteral("café")), QStringLiteral("café"));
    }

    void blankTitlesFallBackToThePlaceholder() {
        const QString placeholder = I18n::t(QStringLiteral("kdbx2pass.no_title"));
        QCOMPARE(Kdbx2Pass::sanitizeTitle(QStringLiteral("  ")), placeholder);
        QCOMPARE(Kdbx2Pass::sanitizeTitle(QString()), placeholder);
    }

    void frecencyWeightDecaysWithAge() {
        QCOMPARE(weightForAge(0), 100u);
        QCOMPARE(weightForAge(86399), 100u);
        QCOMPARE(weightForAge(86400), 50u);
        QCOMPARE(weightForAge(604800), 20u);
        QCOMPARE(weightForAge(2592000), 5u);
    }

    void bitwardenServerIsNormalised() {
        // bitwarden.com, however it is written, is bw's default.
        for (const char *cloud : {"", "  ", "bitwarden.com", "vault.bitwarden.com",
                                  "https://vault.bitwarden.com/", "HTTPS://Bitwarden.com"})
            QCOMPARE(normalizeBwServer(QString::fromUtf8(cloud)), std::optional<QString>(QString()));

        QCOMPARE(normalizeBwServer(QStringLiteral("bitwarden.eu")),
                 std::optional<QString>(QStringLiteral("https://vault.bitwarden.eu")));
        QCOMPARE(normalizeBwServer(QStringLiteral(" vault.example.com ")),
                 std::optional<QString>(QStringLiteral("https://vault.example.com")));
        QCOMPARE(normalizeBwServer(QStringLiteral("https://Vault.Example.com:8443/bw/")),
                 std::optional<QString>(QStringLiteral("https://vault.example.com:8443/bw")));
        QCOMPARE(normalizeBwServer(QStringLiteral("localhost:8099")),
                 std::optional<QString>(QStringLiteral("https://localhost:8099")));

        // bw refuses plain http, and anything that is not an address.
        QVERIFY(!normalizeBwServer(QStringLiteral("http://vault.example.com")));
        QVERIFY(!normalizeBwServer(QStringLiteral("ftp://vault.example.com")));
        QVERIFY(!normalizeBwServer(QStringLiteral("https://")));
        QVERIFY(!normalizeBwServer(QStringLiteral("https://user:pw@vault.example.com")));
        QVERIFY(!normalizeBwServer(QStringLiteral("vault example com")));

        QCOMPARE(bwServerLabel(QString()), QStringLiteral("bitwarden.com"));
        QCOMPARE(bwServerLabel(QStringLiteral("https://vw.lan")), QStringLiteral("https://vw.lan"));
    }

    void bitwardenEntryDataReadsTheFirstUri() {
        const EntryData data = bwEntryData(QJsonDocument::fromJson(bwItemWithExtras).object());
        QCOMPARE(data.username, QStringLiteral("u"));
        QCOMPARE(data.password.toString(), QStringLiteral("p"));
        QCOMPARE(data.url, QStringLiteral("https://a"));
        QCOMPARE(data.notes, QStringLiteral("n"));
    }

    void bitwardenIndexMapsFoldersToGroups() {
        const QByteArray folders(bwFolders);
        const QByteArray items(bwItems);

        const BwIndex index = buildBwIndex(bwItemsById(items), bwFoldersById(folders));
        QCOMPARE(index.groups, QStringList({QStringLiteral("Empty"), QStringLiteral("Work"),
                                            QStringLiteral("Work/Mail")}));
        QCOMPARE(index.entries, QStringList({QStringLiteral("Bank"), QStringLiteral("Lost"),
                                             QStringLiteral("Work/Mail/Gmail")}));
        QCOMPARE(index.items.value(QStringLiteral("Work/Mail/Gmail")).id, QStringLiteral("i1"));
        QCOMPARE(index.folders.value(QStringLiteral("Work/Mail")), QStringLiteral("f1"));
        QVERIFY(!index.folders.contains(QStringLiteral("Work")));
        QVERIFY(!index.folders.contains(QStringLiteral("No Folder")));
    }

    void bitwardenIndexDisambiguatesDuplicateNames() {
        const QByteArray items(bwDuplicateItems);

        const BwIndex index = buildBwIndex(bwItemsById(items), {});
        QVERIFY(index.items.contains(QStringLiteral("Mail [aaaaaaaa]")));
        QVERIFY(index.items.contains(QStringLiteral("Mail [bbbbbbbb]")));
        QVERIFY(!index.items.contains(QStringLiteral("Mail")));
        const QString slashed = QStringLiteral("a") + QChar(0x2215) + QStringLiteral("b");
        QCOMPARE(index.items.value(slashed).name, QStringLiteral("a/b"));
    }

    void onePasswordAccountsFallBackToTheUserId() {
        const QVector<OpAccount> accounts = parseOpAccounts(opFixture("accounts.json"));
        QCOMPARE(accounts.size(), 2);
        QCOMPARE(accounts.at(0).key(), QStringLiteral("minha"));
        QCOMPARE(accounts.at(0).email, QStringLiteral("pessoa@exemplo.com"));
        QCOMPARE(accounts.at(1).key(), accounts.at(1).userUuid);
    }

    void onePasswordSignInAnswersTheTwoStepPrompt() {
        FakeOp op;

        OnePasswordLogin login;
        QString variable;
        QString token;
        QString error;
        bool finished = false;
        connect(&login, &OnePasswordLogin::promptShown, &login, [&login](OpPrompt prompt) {
            if (prompt == OpPrompt::TwoFactorCode)
                login.sendCode(QStringLiteral("123456"));
        });
        connect(&login, &OnePasswordLogin::succeeded, &login,
                [&](const QString &, const QString &sessionVariable, const Secret &session) {
            variable = sessionVariable;
            token = session.toString();
            finished = true;
        });
        connect(&login, &OnePasswordLogin::failed, &login, [&](const QString &message, OpError) {
            error = message;
            finished = true;
        });

        login.startSignIn(QStringLiteral("teste"), Secret(QStringLiteral("senha-certa")));

        QTRY_VERIFY_WITH_TIMEOUT(finished, 20000);
        QVERIFY2(error.isEmpty(), qPrintable(error));
        // The name comes from what op printed, not from the account: naming
        // it here is how a session ends up unused.
        QCOMPARE(variable, QStringLiteral("OP_SESSION_qwertyuiopasdfgh"));
        QCOMPARE(token, QStringLiteral("TOKEN-DE-SESSAO"));
    }

    void onePasswordAddKeepsGoingWhenOpComplainsAboutAnAccountItAdded() {
        FakeOp op;
        op.setAccounts({});

        OnePasswordLogin login;
        QString token;
        QString error;
        bool finished = false;
        connect(&login, &OnePasswordLogin::promptShown, &login, [&login](OpPrompt prompt) {
            if (prompt == OpPrompt::TwoFactorCode)
                login.sendCode(QStringLiteral("123456"));
        });
        connect(&login, &OnePasswordLogin::succeeded, &login,
                [&](const QString &, const QString &, const Secret &session) {
            token = session.toString();
            finished = true;
        });
        connect(&login, &OnePasswordLogin::failed, &login, [&](const QString &message, OpError) {
            error = message;
            finished = true;
        });

        login.start(QStringLiteral("my.1password.com"), QStringLiteral("teste@exemplo.com"),
                    Secret(QStringLiteral("A3-CHAVE")), Secret(QStringLiteral("senha-certa")),
                    QStringLiteral("teste"));

        QTRY_VERIFY_WITH_TIMEOUT(finished, 20000);
        // `op account add` ends with something to say over an account it did
        // add; what settles it is op listing the account, and the session
        // follows.
        QVERIFY2(error.isEmpty(), qPrintable(error));
        QCOMPARE(token, QStringLiteral("TOKEN-DE-SESSAO"));
    }

    void onePasswordLogoutRemovesTheAccountEitherWay() {
        FakeOp op;

        // With no session, `op account forget` is the one that removes it.
        QString error;
        QVERIFY2(OnePasswordVault::logout(QStringLiteral("teste"), &error), qPrintable(error));
        QVERIFY(!OnePasswordVault::hasAccount(QStringLiteral("teste")));

        // With one, op refuses that and points at the sign-out instead.
        op.setAccounts({QStringLiteral("teste")});
        op.setSignedIn(true);
        QVERIFY2(OnePasswordVault::logout(QStringLiteral("teste"), &error), qPrintable(error));
        QVERIFY(!OnePasswordVault::hasAccount(QStringLiteral("teste")));
    }

    void onePasswordLogoutSaysSoWhenOpWillNotLetGo() {
        FakeOp op;
        // op believes a session is live and no sign-out can end it without
        // the token: the state omapass cannot talk its way out of.
        op.setSignedIn(true);
        qputenv("OP_FAKE_STUCK", "1");

        QString error;
        QVERIFY(!OnePasswordVault::logout(QStringLiteral("teste"), &error));
        QVERIFY(!error.isEmpty());
        QVERIFY(OnePasswordVault::hasAccount(QStringLiteral("teste")));
        qunsetenv("OP_FAKE_STUCK");
    }

    void onePasswordShellCommandQuotesItsArguments() {
        QCOMPARE(opShellCommand({QStringLiteral("signin"), QStringLiteral("--account"),
                                 QStringLiteral("minha")}),
                 QStringLiteral("op 'signin' '--account' 'minha'"));
        // A shorthand with a quote in it would otherwise end the string and
        // let the rest be read as more shell.
        QCOMPARE(opShellCommand({QStringLiteral("account"), QStringLiteral("forget"),
                                 QStringLiteral("a'b")}),
                 QStringLiteral("op 'account' 'forget' 'a'\\''b'"));
    }

    void onePasswordSignInNamesItsOwnSessionVariable() {
        // What `op signin` prints without --raw, comments and all.
        const OpSession named = parseOpSignIn(QStringLiteral(
            "export OP_SESSION_abcdefghij=\"token-de-sessao\"\n"
            "# This command is meant to be used with your shell's eval function.\n"
            "# Run 'eval $(op signin --account minha)' to sign in.\n"));
        QCOMPARE(named.variable, QStringLiteral("OP_SESSION_abcdefghij"));
        QCOMPARE(named.token, QStringLiteral("token-de-sessao"));

        // With --raw, or under a terminal that echoed the prompts back, only
        // the token is there and the caller names the variable itself.
        const OpSession raw = parseOpSignIn(QStringLiteral(
            "Enter the password for pessoa@exemplo.com at my.1password.com: \r\n"
            "token-de-sessao\r\n"));
        QVERIFY(raw.variable.isEmpty());
        QCOMPARE(raw.token, QStringLiteral("token-de-sessao"));

        QVERIFY(parseOpSignIn(QString()).token.isEmpty());
    }

    void onePasswordShorthandComesFromTheEmail() {
        // `op` would name the account after the address; the e-mail says
        // whose it is.
        QCOMPARE(opShorthandFor(QStringLiteral("Pessoa.Sobrenome@exemplo.com"),
                                QStringLiteral("my.1password.com")),
                 QStringLiteral("pessoa_sobrenome"));
        QCOMPARE(opShorthandFor(QStringLiteral("pessoa+trabalho@exemplo.com"),
                                QStringLiteral("my.1password.com")),
                 QStringLiteral("pessoa_trabalho"));
        // Nothing usable in the e-mail: back to what op itself would do.
        QCOMPARE(opShorthandFor(QString(), QStringLiteral("Empresa.1password.com")),
                 QStringLiteral("empresa"));

        // The same person on two domains would collide, and op refuses the
        // second account.
        const QStringList taken{QStringLiteral("pessoa"), QStringLiteral("pessoa2")};
        QCOMPARE(opUniqueShorthand(QStringLiteral("outra"), taken), QStringLiteral("outra"));
        QCOMPARE(opUniqueShorthand(QStringLiteral("pessoa"), taken), QStringLiteral("pessoa3"));
    }

    void onePasswordIndexNestsTagsUnderTheVault() {
        const OpIndex index = buildOpIndex(opFixture("items.json"), opFixture("vaults.json"));

        QCOMPARE(index.groups, QStringList({QStringLiteral("Pessoal"),
                                            QStringLiteral("Pessoal/Streaming"),
                                            QStringLiteral("Trabalho"),
                                            QStringLiteral("Trabalho/Assinaturas"),
                                            QStringLiteral("Trabalho/Trabalho"),
                                            QStringLiteral("Trabalho/Trabalho/Deploy"),
                                            QStringLiteral("Vazio")}));

        // A password item sits at its vault's root; a credit card is not
        // shown at all; a tag with stray spaces and empty segments is the
        // same group as the tidy one.
        QVERIFY(index.items.contains(QStringLiteral("Pessoal/Cofre do roteador")));
        QVERIFY(index.items.contains(QStringLiteral("Trabalho/Trabalho/Deploy/Servidor")));
        for (const QString &entry : std::as_const(index.entries))
            QVERIFY(!entry.contains(QStringLiteral("Cartao")));

        QCOMPARE(index.vaults.value(QStringLiteral("Pessoal")), QStringLiteral("v1"));
        QCOMPARE(index.vaults.value(QStringLiteral("Vazio")), QStringLiteral("v3"));
    }

    void onePasswordIndexFilesAnItemUnderItsFirstTag() {
        const OpIndex index = buildOpIndex(opFixture("items.json"), opFixture("vaults.json"));

        // "GitLab / CI" carries both "Trabalho/Deploy" and "Assinaturas";
        // the first in alphabetical order is the one that places it, and the
        // slash in the title is shown as a look-alike.
        const QString path = QStringLiteral("Trabalho/Assinaturas/GitLab ") + QChar(0x2215)
            + QStringLiteral(" CI");
        QVERIFY(index.items.contains(path));
        const OpItemRef ref = index.items.value(path);
        QCOMPARE(ref.title, QStringLiteral("GitLab / CI"));
        QCOMPARE(ref.vaultId, QStringLiteral("v2"));
        QCOMPARE(ref.tagPath, QStringLiteral("Assinaturas"));
    }

    void onePasswordIndexDisambiguatesDuplicateTitles() {
        const OpIndex index = buildOpIndex(opFixture("items.json"), opFixture("vaults.json"));
        QVERIFY(index.items.contains(QStringLiteral("Pessoal/Streaming/Netflix [i1]")));
        QVERIFY(index.items.contains(QStringLiteral("Pessoal/Streaming/Netflix [i2]")));
        QVERIFY(!index.items.contains(QStringLiteral("Pessoal/Streaming/Netflix")));
    }

    void onePasswordEntryDataReadsThePrimaryUrl() {
        const QJsonObject item = QJsonDocument::fromJson(opFixture("item.json")).object();
        const EntryData data = opEntryData(item);
        QCOMPARE(data.username, QStringLiteral("pessoa@empresa.com"));
        QCOMPARE(data.password.toString(), QStringLiteral("senha-antiga"));
        QCOMPARE(data.url, QStringLiteral("https://gitlab.exemplo.com"));
        QCOMPARE(data.notes, QStringLiteral("nota antiga"));
        QVERIFY(!opHasPasskey(item));
    }

    void onePasswordEditKeepsFieldsItDoesNotModel() {
        EntryData data;
        data.username = QStringLiteral("nova-pessoa");
        data.password = Secret(QStringLiteral("nova-senha"));
        data.url = QStringLiteral("https://novo.exemplo.com");
        data.notes = QStringLiteral("nota nova");

        const QJsonObject item = QJsonDocument::fromJson(
            applyOpEntryData(opFixture("item.json"), QStringLiteral("GitLab"),
                             QStringLiteral("Producao"), data)).object();

        QCOMPARE(item.value(QStringLiteral("title")).toString(), QStringLiteral("GitLab"));
        // The tag that placed the item gives way to the new group; the other
        // one is the user's own filing and stays.
        QCOMPARE(item.value(QStringLiteral("tags")).toVariant().toStringList(),
                 QStringList({QStringLiteral("Producao"), QStringLiteral("Trabalho/Deploy")}));
        QCOMPARE(item.value(QStringLiteral("sections")).toArray().size(), 1);

        const QJsonArray fields = item.value(QStringLiteral("fields")).toArray();
        QCOMPARE(fields.size(), 5);
        QCOMPARE(fields.at(0).toObject().value(QStringLiteral("value")).toString(),
                 QStringLiteral("nova-pessoa"));
        QCOMPARE(fields.at(1).toObject().value(QStringLiteral("value")).toString(),
                 QStringLiteral("nova-senha"));
        QVERIFY(fields.at(1).toObject().contains(QStringLiteral("password_details")));
        QCOMPARE(fields.at(3).toObject().value(QStringLiteral("type")).toString(),
                 QStringLiteral("OTP"));
        QCOMPARE(fields.at(4).toObject().value(QStringLiteral("value")).toString(),
                 QStringLiteral("producao"));

        const QJsonArray urls = item.value(QStringLiteral("urls")).toArray();
        QCOMPARE(urls.size(), 2);
        QCOMPARE(urls.at(0).toObject().value(QStringLiteral("href")).toString(),
                 QStringLiteral("https://novo.exemplo.com"));
        QCOMPARE(urls.at(1).toObject().value(QStringLiteral("href")).toString(),
                 QStringLiteral("https://espelho.exemplo.com"));
    }

    void onePasswordNewItemCarriesTheVaultAndTheTag() {
        EntryData data;
        data.password = Secret(QStringLiteral("p"));

        const QJsonObject item = QJsonDocument::fromJson(
            opNewItemJson(QStringLiteral("Site"), QStringLiteral("v1"),
                          QStringLiteral(" Casa / Rede "), data)).object();

        QCOMPARE(item.value(QStringLiteral("category")).toString(), QStringLiteral("LOGIN"));
        QCOMPARE(item.value(QStringLiteral("vault")).toObject().value(QStringLiteral("id")).toString(),
                 QStringLiteral("v1"));
        QCOMPARE(item.value(QStringLiteral("tags")).toVariant().toStringList(),
                 QStringList({QStringLiteral("Casa/Rede")}));
        // Only the password was filled in, so no empty username or notes
        // field is invented.
        const QJsonArray fields = item.value(QStringLiteral("fields")).toArray();
        QCOMPARE(fields.size(), 1);
        QCOMPARE(fields.at(0).toObject().value(QStringLiteral("purpose")).toString(),
                 QStringLiteral("PASSWORD"));
        QVERIFY(item.value(QStringLiteral("urls")).toArray().isEmpty());
    }

    void onePasswordErrorsAreClassified() {
        QCOMPARE(classifyOpError(QStringLiteral(
                     "[ERROR] 2026/09/17 12:00:00 session expired, sign in to create a new session")),
                 OpError::SessionExpired);
        QCOMPARE(classifyOpError(QStringLiteral(
                     "You are not currently signed in. Please run `op signin --help` for instructions")),
                 OpError::NotSignedIn);
        QCOMPARE(classifyOpError(QStringLiteral("No accounts configured for use with 1Password CLI.")),
                 OpError::NoAccount);
        QCOMPARE(classifyOpError(QStringLiteral("[ERROR] Incorrect Secret Key")), OpError::WrongSecretKey);
        QCOMPARE(classifyOpError(QStringLiteral("[ERROR] username/password authentication failed")),
                 OpError::WrongPassword);
        QCOMPARE(classifyOpError(QStringLiteral("[ERROR] rate limit exceeded")), OpError::RateLimited);
        QCOMPARE(classifyOpError(QStringLiteral("outra coisa qualquer")), OpError::Other);
        QCOMPARE(classifyOpError(QString()), OpError::None);
    }

    void onePasswordPromptsAreDetected() {
        QCOMPARE(detectOpPrompt(QStringLiteral("Enter your sign-in address (example.1password.com): ")),
                 OpPrompt::SignInAddress);
        QCOMPARE(detectOpPrompt(QStringLiteral(
                     "Enter the email address for your account on minha.1password.com: ")),
                 OpPrompt::Email);
        QCOMPARE(detectOpPrompt(QStringLiteral(
                     "Enter the Secret Key for pessoa@exemplo.com on minha.1password.com: ")),
                 OpPrompt::SecretKey);
        QCOMPARE(detectOpPrompt(QStringLiteral(
                     "Enter the Secret Key for pessoa@exemplo.com on minha.1password.com: \n"
                     "Enter the password for pessoa@exemplo.com at minha.1password.com: ")),
                 OpPrompt::Password);
        QCOMPARE(detectOpPrompt(QStringLiteral(
                     "Enter the password for pessoa@exemplo.com at minha.1password.com: \n"
                     "Enter your 6-digit authentication code: ")),
                 OpPrompt::TwoFactorCode);
        // What `op signin` actually prints for an account with two-step
        // verification, spelled out rather than in digits.
        QCOMPARE(detectOpPrompt(QStringLiteral(
                     "Enter the password for pessoa@exemplo.com at my.1password.com:\r\n"
                     "Enter your six-digit authentication code:")),
                 OpPrompt::TwoFactorCode);
        // Other wordings the code has been asked for: a prompt that goes
        // unrecognised is a prompt nobody answers, and the run hangs.
        QCOMPARE(detectOpPrompt(QStringLiteral("Enter your one-time password: ")),
                 OpPrompt::TwoFactorCode);
        QCOMPARE(detectOpPrompt(QStringLiteral("Enter the verification code we sent you: ")),
                 OpPrompt::TwoFactorCode);
        QCOMPARE(detectOpPrompt(QStringLiteral("carregando")), OpPrompt::None);
    }

    void bitwardenKdfMatchesTheSdk() {
        const QJsonObject v = bwFixture("vectors.json");
        const Secret password(v.value("password").toString());
        const QString salt = v.value("salt").toString();

        const QJsonObject pbkdf2 = v.value("pbkdf2").toObject();
        BwKdf kdf;
        kdf.type = 0;
        kdf.iterations = pbkdf2.value("iterations").toInt();
        QCOMPARE(BwCrypto::deriveKdfMaterial(password, salt, kdf), bwHex(pbkdf2.value("masterKey").toString()));

        const QJsonObject argon2 = v.value("argon2id").toObject();
        kdf.type = 1;
        kdf.iterations = argon2.value("iterations").toInt();
        kdf.memory = argon2.value("memory").toInt();
        kdf.parallelism = argon2.value("parallelism").toInt();
        QCOMPARE(BwCrypto::deriveKdfMaterial(password, salt, kdf), bwHex(argon2.value("masterKey").toString()));

        kdf.type = 7;
        QVERIFY(!BwCrypto::deriveKdfMaterial(password, salt, kdf));
    }

    void bitwardenEncStringsDecryptAndRejectTampering() {
        const QJsonObject v = bwFixture("vectors.json").value("encString").toObject();
        const std::optional<BwKey> key = BwCrypto::keyFromBytes(bwHex(v.value("key").toString()));
        QVERIFY(key);

        const QString encrypted = v.value("encrypted").toString();
        QCOMPARE(BwCrypto::decryptString(encrypted, *key), std::optional<QString>(v.value("plaintext").toString()));

        // A flipped bit anywhere fails the MAC before decryption.
        QString tampered = encrypted;
        const int dataStart = tampered.indexOf(QLatin1Char('|')) + 1;
        tampered[dataStart] = tampered[dataStart] == QLatin1Char('A') ? QLatin1Char('B') : QLatin1Char('A');
        QVERIFY(!BwCrypto::decryptString(tampered, *key));

        BwKey wrongKey = *key;
        wrongKey.mac[0] ^= 1;
        QVERIFY(!BwCrypto::decryptString(encrypted, wrongKey));

        QVERIFY(!BwCrypto::decryptString(QStringLiteral("7.") + encrypted.mid(2), *key));
        QVERIFY(!BwCrypto::decryptString(QStringLiteral("garbage"), *key));
    }

    void bitwardenEncryptRoundTripsAndSaltsEachTime() {
        const std::optional<BwKey> key = BwCrypto::keyFromBytes(BwCrypto::randomBytes(64));
        QVERIFY(key);

        const QByteArray plaintext = QByteArrayLiteral("senha mestra com acentuação");
        const std::optional<QString> first = BwCrypto::encrypt(plaintext, *key);
        const std::optional<QString> second = BwCrypto::encrypt(plaintext, *key);
        QVERIFY(first && second);
        QVERIFY(first->startsWith(QLatin1String("2.")));
        // A fresh IV every time, so the same text never looks the same twice.
        QVERIFY(*first != *second);

        QCOMPARE(BwCrypto::decryptString(*first, *key),
                 std::optional<QString>(QString::fromUtf8(plaintext)));

        QString tampered = *first;
        const int macStart = tampered.lastIndexOf(QLatin1Char('|')) + 1;
        tampered[macStart] = tampered[macStart] == QLatin1Char('A') ? QLatin1Char('B') : QLatin1Char('A');
        QVERIFY(!BwCrypto::decryptString(tampered, *key));

        const std::optional<BwKey> otherKey = BwCrypto::keyFromBytes(BwCrypto::randomBytes(64));
        QVERIFY(!BwCrypto::decryptString(*first, *otherKey));
    }

    void bitwardenMasterPasswordUnwrapsTheUserKey() {
        const QJsonObject v = bwFixture("vectors.json");
        const QJsonObject wrapped = v.value("userKeyArgon2id").toObject();
        const QJsonObject argon2 = v.value("argon2id").toObject();
        BwKdf kdf;
        kdf.type = 1;
        kdf.iterations = argon2.value("iterations").toInt();
        kdf.memory = argon2.value("memory").toInt();
        kdf.parallelism = argon2.value("parallelism").toInt();

        const std::optional<BwKey> masterKey =
            BwCrypto::deriveMasterKey(Secret(v.value("password").toString()), v.value("salt").toString(), kdf);
        QVERIFY(masterKey);
        const std::optional<BwKey> userKey = BwCrypto::unwrapKey(wrapped.value("wrapped").toString(), *masterKey);
        QVERIFY(userKey);
        BwBytes joined = userKey->enc;
        joined.insert(joined.end(), userKey->mac.begin(), userKey->mac.end());
        QCOMPARE(joined, bwHex(wrapped.value("userKey").toString()));

        const std::optional<BwKey> wrongMaster =
            BwCrypto::deriveMasterKey(Secret(QStringLiteral("errada")), v.value("salt").toString(), kdf);
        QVERIFY(!BwCrypto::unwrapKey(wrapped.value("wrapped").toString(), *wrongMaster));
    }

    void bitwardenLoginErrorsAreClassified() {
        QCOMPARE(classifyBwLoginMessage(QStringLiteral("Username or password is incorrect. Try again"), false),
                 BwLoginError::WrongPassword);
        QCOMPARE(classifyBwLoginMessage(QStringLiteral("invalid_username_or_password"), false),
                 BwLoginError::WrongPassword);
        // Once the password went through, a refusal is about the code.
        QCOMPARE(classifyBwLoginMessage(QStringLiteral("Two-step token is invalid. Try again."), true),
                 BwLoginError::InvalidCode);
        QCOMPARE(classifyBwLoginMessage(QStringLiteral("Invalid TOTP code"), true), BwLoginError::InvalidCode);
        QCOMPARE(classifyBwLoginMessage(QStringLiteral("Something else"), false), BwLoginError::Other);
        QCOMPARE(classifyBwLoginMessage(QString(), false), BwLoginError::Other);
    }

    void bitwardenTwoStepMethodsOmapassCanAskFor() {
        // Authenticator, e-mail and YubiKey OTP, in that order; Duo (2),
        // passkeys (7) and the rest are left out.
        QCOMPARE(bwSupportedTwoFactor({7, 3, 1, 0, 2}), QList<int>({0, 1, 3}));
        QCOMPARE(bwSupportedTwoFactor({1}), QList<int>({1}));
        QVERIFY(bwSupportedTwoFactor({2, 7}).isEmpty());
    }

    void bitwardenApiAddressesFollowTheServer() {
        QCOMPARE(BwApi::identityUrl(QString()), QStringLiteral("https://identity.bitwarden.com"));
        QCOMPARE(BwApi::apiUrl(QString()), QStringLiteral("https://api.bitwarden.com"));
        QCOMPARE(BwApi::identityUrl(QStringLiteral("https://vault.bitwarden.eu")),
                 QStringLiteral("https://identity.bitwarden.eu"));
        QCOMPARE(BwApi::apiUrl(QStringLiteral("https://vault.bitwarden.eu")), QStringLiteral("https://api.bitwarden.eu"));
        QCOMPARE(BwApi::identityUrl(QStringLiteral("https://vw.lan:8443/bw")),
                 QStringLiteral("https://vw.lan:8443/bw/identity"));
        QCOMPARE(BwApi::apiUrl(QStringLiteral("https://vw.lan")), QStringLiteral("https://vw.lan/api"));
    }

    void bitwardenResponsesAreReadInCamelCase() {
        // How Bitwarden answers a login that needs a second step.
        const QJsonObject json = BwApi::camelized(QJsonDocument::fromJson(
            R"({"TwoFactorProviders2":{"0":null,"1":{"Email":"a***@b.com"}},"SsoEmail2faSessionToken":"t",
                "ErrorModel":{"Message":"Two factor required.","Object":"error"},"error_description":"x"})").object());
        QVERIFY(json.contains("twoFactorProviders2"));
        QVERIFY(json.value("twoFactorProviders2").toObject().contains("1"));
        QCOMPARE(json.value("twoFactorProviders2").toObject().value("1").toObject().value("email").toString(),
                 QStringLiteral("a***@b.com"));
        QCOMPARE(json.value("ssoEmail2faSessionToken").toString(), QStringLiteral("t"));

        BwResponse response;
        response.failure = BwResponse::Failure::Http;
        response.status = 400;
        response.json = json;
        QCOMPARE(response.message(), QStringLiteral("Two factor required."));

        response.json = QJsonObject{{"message", "The model state is invalid."},
                                    {"validationErrors", QJsonObject{{"Name", QJsonArray{"Name is too long."}}}}};
        QCOMPARE(response.message(), QStringLiteral("Name is too long."));

        response.json = QJsonObject();
        response.networkError = QStringLiteral("boom");
        QCOMPARE(response.message(), QStringLiteral("boom"));
    }

    void bitwardenMasterPasswordHashMatchesTheReference() {
        // base64(PBKDF2-SHA256(masterKey, password, 1)), computed apart from
        // omapass from the SDK's own master key.
        const QJsonObject v = bwFixture("vectors.json");
        const Secret hash = BwCrypto::masterPasswordHash(bwHex(v.value("pbkdf2").toObject().value("masterKey").toString()),
                                                         Secret(v.value("password").toString()));
        QCOMPARE(hash.toString(), QStringLiteral("ds9ELf+Hij7EVdmNphywwCy4tksKVEFsC9KhOdpTHBs="));
    }

    void bitwardenAccountDecryptsEveryKindOfLogin() {
        const BwAccountState state = bwStateFromFixture();
        const QJsonObject v = bwFixture("vectors.json");
        BwKeys keys;
        QCOMPARE(BwAccount::unlock(state, Secret(v.value("password").toString()), &keys), BwAccount::Unlock::Ok);
        QCOMPARE(keys.organizations.size(), 1);

        QHash<QString, QJsonObject> items;
        QHash<QString, QString> folders;
        BwAccount::decryptVault(state, keys, &items, &folders);

        const QJsonObject expected = bwFixture("expected.json");
        QCOMPARE(folders.value(QStringLiteral("f1")), QStringLiteral("Trabalho/Email"));
        QCOMPARE(folders.size(), 1);

        const QJsonArray expectedItems = expected.value("items").toArray();
        // The secure note and the login in the trash are left out.
        QCOMPARE(items.size(), expectedItems.size());
        for (const QJsonValue &value : expectedItems) {
            const QJsonObject want = value.toObject();
            const QString id = want.value("id").toString();
            QVERIFY2(items.contains(id), qPrintable(id));

            const QJsonObject item = items.value(id);
            const EntryData data = bwEntryData(item);
            QCOMPARE(item.value("name").toString(), want.value("name").toString());
            QCOMPARE(item.value("folderId"), want.value("folderId"));
            QCOMPARE(item.value("organizationId"), want.value("organizationId"));
            QCOMPARE(data.username, want.value("username").toString());
            QCOMPARE(data.password.toString(), want.value("password").toString());
            QCOMPARE(data.url, want.value("uri").toString());
            QCOMPARE(data.notes, want.value("notes").toString());
            QCOMPARE(item.value("login").toObject().value("totp"), want.value("totp"));
        }

        const BwIndex index = buildBwIndex(items, folders);
        QVERIFY(index.items.contains(QStringLiteral("Trabalho/Email/Gmail")));
        QVERIFY(index.items.contains(QStringLiteral("Servidor")));
    }

    void bitwardenAccountRejectsAWrongPassword() {
        BwKeys keys;
        QCOMPARE(BwAccount::unlock(bwStateFromFixture(), Secret(QStringLiteral("errada")), &keys),
                 BwAccount::Unlock::WrongPassword);

        BwAccountState unknownKdf = bwStateFromFixture();
        unknownKdf.kdf.type = 9;
        QCOMPARE(BwAccount::unlock(unknownKdf, Secret(QStringLiteral("x")), &keys), BwAccount::Unlock::Unsupported);
    }

    void bitwardenAccountSkipsOnlyWhatDoesNotDecrypt() {
        // One login in a format this does not read: it is left out, and the
        // rest of the vault still opens — there is no other client to fall
        // back to.
        BwAccountState state = bwStateFromFixture();
        for (int i = 0; i < state.ciphers.size(); ++i) {
            QJsonObject cipher = state.ciphers.at(i).toObject();
            if (cipher.value("id").toString() == QLatin1String("c2")) {
                cipher.insert("name", QStringLiteral("7.bmV3LWZvcm1hdA=="));
                state.ciphers.replace(i, cipher);
            }
        }
        BwKeys keys;
        QCOMPARE(BwAccount::unlock(state, Secret(bwFixture("vectors.json").value("password").toString()), &keys),
                 BwAccount::Unlock::Ok);
        QHash<QString, QJsonObject> items;
        QHash<QString, QString> folders;
        BwAccount::decryptVault(state, keys, &items, &folders);
        QVERIFY(!items.contains(QStringLiteral("c2")));
        QCOMPARE(items.size(), bwFixture("expected.json").value("items").toArray().size() - 1);
    }

    void bitwardenEditKeepsWhatItDoesNotModel() {
        const BwAccountState state = bwStateFromFixture();
        BwKeys keys;
        QCOMPARE(BwAccount::unlock(state, Secret(bwFixture("vectors.json").value("password").toString()), &keys),
                 BwAccount::Unlock::Ok);

        // The organisation login: its own item key, wrapped with the
        // organisation's, and what the server has in it beyond the form.
        QJsonObject original;
        for (const QJsonValue &value : state.ciphers) {
            if (!value.toObject().value("organizationId").toString().isEmpty())
                original = value.toObject();
        }
        QVERIFY(!original.isEmpty());
        original.insert("revisionDate", QStringLiteral("2026-01-01T00:00:00.000Z"));
        original.insert("fields", QJsonArray{QJsonObject{{"name", "2.keep|me|intact"}, {"type", 1}}});
        QJsonObject login = original.value("login").toObject();
        QJsonArray uris = login.value("uris").toArray();
        uris.append(QJsonObject{{"uri", "2.second|uri|kept"}, {"match", 3}});
        login.insert("uris", uris);
        login.insert("totp", QStringLiteral("2.totp|kept|asis"));
        original.insert("login", login);

        const std::optional<BwKey> key = BwAccount::cipherKey(original, keys);
        QVERIFY(key);

        EntryData data;
        data.username = QStringLiteral("novo-usuario");
        data.password = Secret(QStringLiteral("senha-nova"));
        data.url = QStringLiteral("https://c.example");
        const QJsonObject request = BwAccount::cipherRequest(original, QStringLiteral("senha-velha"),
                                                             QStringLiteral("Novo nome"), QStringLiteral("f1"),
                                                             data, *key, QStringLiteral("user-1"));

        QCOMPARE(request.value("encryptedFor").toString(), QStringLiteral("user-1"));
        QCOMPARE(request.value("lastKnownRevisionDate").toString(), QStringLiteral("2026-01-01T00:00:00.000Z"));
        QCOMPARE(request.value("organizationId"), original.value("organizationId"));
        QCOMPARE(request.value("key"), original.value("key"));
        QCOMPARE(request.value("folderId").toString(), QStringLiteral("f1"));
        QCOMPARE(decrypted(request.value("name"), *key), QStringLiteral("Novo nome"));
        QVERIFY(request.value("notes").isNull());
        QCOMPARE(request.value("fields"), original.value("fields"));

        const QJsonObject newLogin = request.value("login").toObject();
        QCOMPARE(decrypted(newLogin.value("username"), *key), QStringLiteral("novo-usuario"));
        QCOMPARE(decrypted(newLogin.value("password"), *key), QStringLiteral("senha-nova"));
        QCOMPARE(newLogin.value("totp").toString(), QStringLiteral("2.totp|kept|asis"));
        QVERIFY(!newLogin.value("passwordRevisionDate").toString().isEmpty());

        const QJsonArray newUris = newLogin.value("uris").toArray();
        QCOMPARE(newUris.size(), uris.size());
        QCOMPARE(decrypted(newUris.at(0).toObject().value("uri"), *key), QStringLiteral("https://c.example"));
        QCOMPARE(decrypted(newUris.at(0).toObject().value("uriChecksum"), *key),
                 QString::fromLatin1(QCryptographicHash::hash("https://c.example", QCryptographicHash::Sha256).toBase64()));
        QCOMPARE(newUris.last().toObject().value("uri").toString(), QStringLiteral("2.second|uri|kept"));

        // The old password goes into the history, newest first.
        const QJsonArray history = request.value("passwordHistory").toArray();
        QCOMPARE(history.size(), 1);
        QCOMPARE(decrypted(history.at(0).toObject().value("password"), *key), QStringLiteral("senha-velha"));

        // The same password again leaves the history alone.
        data.password = Secret(QStringLiteral("senha-velha"));
        const QJsonObject unchanged = BwAccount::cipherRequest(original, QStringLiteral("senha-velha"),
                                                               QStringLiteral("x"), QString(), data, *key,
                                                               QStringLiteral("user-1"));
        QVERIFY(unchanged.value("passwordHistory").toArray().isEmpty());
        QVERIFY(unchanged.value("folderId").isNull());
    }

    void bitwardenNewItemStartsFromABlankLogin() {
        const std::optional<BwKey> key = BwCrypto::keyFromBytes(BwCrypto::randomBytes(64));
        EntryData data;
        data.password = Secret(QStringLiteral("p"));
        const QJsonObject request = BwAccount::cipherRequest(QJsonObject(), QString(), QStringLiteral("Site"),
                                                             QString(), data, *key, QStringLiteral("u"));
        QCOMPARE(request.value("type").toInt(), 1);
        QVERIFY(request.value("organizationId").isNull());
        QVERIFY(!request.contains("lastKnownRevisionDate"));
        QCOMPARE(decrypted(request.value("name"), *key), QStringLiteral("Site"));
        const QJsonObject login = request.value("login").toObject();
        QVERIFY(login.value("uris").toArray().isEmpty());
        QVERIFY(login.value("username").isNull());
        QCOMPARE(decrypted(login.value("password"), *key), QStringLiteral("p"));
        QVERIFY(request.value("passwordHistory").isNull());
    }

    void bitwardenSyncUpdatesTheAccount() {
        BwAccountState state;
        state.salt = QStringLiteral("a@b.com");
        state.kdf.type = 0;
        state.kdf.iterations = 600000;
        const QJsonObject sync = BwApi::camelized(QJsonDocument::fromJson(R"({
            "Profile": {"Id": "u1", "Key": "2.user|key|x", "PrivateKey": "2.private|key|x",
                        "Organizations": [{"Id": "o1", "Key": "4.orgkey"}, {"Id": "o2", "Key": null}]},
            "UserDecryption": {"MasterPasswordUnlock": {"Kdf": {"KdfType": 1, "Iterations": 3, "Memory": 64,
                               "Parallelism": 4}, "Salt": "a@b.com", "MasterKeyEncryptedUserKey": "2.newer|key|x"}},
            "Folders": [{"Id": "f1", "Name": "2.n|a|me"}],
            "Ciphers": [{"Id": "c1", "Type": 1}]})").object());
        BwAccount::applySync(&state, sync);

        QCOMPARE(state.userId, QStringLiteral("u1"));
        QCOMPARE(state.userKey, QStringLiteral("2.newer|key|x"));
        QCOMPARE(state.privateKey, QStringLiteral("2.private|key|x"));
        QCOMPARE(state.kdf.type, 1);
        QCOMPARE(state.kdf.memory, 64);
        QCOMPARE(state.kdf.parallelism, 4);
        QCOMPARE(state.organizationKeys, QJsonObject({{"o1", "4.orgkey"}}));
        QCOMPARE(state.folders.size(), 1);
        QCOMPARE(state.ciphers.first().toObject().value("id").toString(), QStringLiteral("c1"));
    }

    void bitwardenAccountIsSavedPerServer() {
        QStandardPaths::setTestModeEnabled(true);
        QDir(BwAccount::directory()).removeRecursively();

        QCOMPARE(BwAccount::refPath(QStringLiteral("a@b.com"), QString()), QStringLiteral("bitwarden:a@b.com"));
        const QString selfHosted = BwAccount::refPath(QStringLiteral("a@b.com"), QStringLiteral("https://vw.lan"));
        QCOMPARE(selfHosted, QStringLiteral("bitwarden:a@b.com|https://vw.lan"));
        QCOMPARE(BwAccount::emailOf(selfHosted), QStringLiteral("a@b.com"));
        QCOMPARE(BwAccount::serverOf(selfHosted), QStringLiteral("https://vw.lan"));
        QCOMPARE(BwAccount::serverOf(QStringLiteral("bitwarden:a@b.com")), QString());

        BwAccountState state = bwStateFromFixture();
        state.server = QStringLiteral("https://vw.lan");
        state.userId = QStringLiteral("u1");
        state.refreshToken = QStringLiteral("2.refresh|token|x");
        QString error;
        QVERIFY2(BwAccount::save(state, &error), qPrintable(error));

        const QString path = BwAccount::refPath(state.email, state.server);
        QCOMPARE(BwAccount::refPaths(), QStringList({path}));
        const std::optional<BwAccountState> loaded = BwAccount::load(path);
        QVERIFY(loaded);
        QCOMPARE(loaded->userKey, state.userKey);
        QCOMPARE(loaded->refreshToken, state.refreshToken);
        QCOMPARE(loaded->userId, state.userId);
        QCOMPARE(loaded->kdf.iterations, state.kdf.iterations);
        QCOMPARE(loaded->ciphers, state.ciphers);
        QVERIFY(!BwAccount::load(BwAccount::refPath(state.email, QString())));

        // Readable by the user only.
        const QFileInfo dir(BwAccount::directory());
        QCOMPARE(dir.permissions() & (QFileDevice::ReadGroup | QFileDevice::ReadOther), QFileDevice::Permissions());

        BwAccount::remove(path);
        QVERIFY(BwAccount::refPaths().isEmpty());
        QDir(BwAccount::directory()).removeRecursively();
        QStandardPaths::setTestModeEnabled(false);
    }

    void pinBlobRoundTrips() {
        const Pin::Blob blob{QStringLiteral("c2FsdA=="), 600000,
                               QStringLiteral("2.aXY=|Y3Q=|bWFj")};
        const QString text = Pin::buildBlob(blob);
        QVERIFY(text.startsWith(QLatin1String("omapass-pin.v1|")));

        const std::optional<Pin::Blob> parsed = Pin::parseBlob(text);
        QVERIFY(parsed);
        QCOMPARE(parsed->salt, blob.salt);
        QCOMPARE(parsed->iterations, blob.iterations);
        // The EncString has separators of its own; they survive the parse.
        QCOMPARE(parsed->encrypted, blob.encrypted);

        // Another version, a missing field or a body that is not an EncString
        // leave the PIN unused rather than half understood.
        QVERIFY(!Pin::parseBlob(QStringLiteral("omapass-pin.v2|c2FsdA==|600000|2.aXY=|Y3Q=|bWFj")));
        QVERIFY(!Pin::parseBlob(QStringLiteral("omapass-pin.v1|c2FsdA==|600000")));
        QVERIFY(!Pin::parseBlob(QStringLiteral("omapass-pin.v1|c2FsdA==|0|2.aXY=|Y3Q=|bWFj")));
        QVERIFY(!Pin::parseBlob(QStringLiteral("omapass-pin.v1|c2FsdA==|600000|7.aXY=|Y3Q=|bWFj")));
        QVERIFY(!Pin::parseBlob(QString()));
    }

    void pinValidationAndWeakWarning() {
        QVERIFY(Pin::validate(QStringLiteral("123456")).isEmpty());
        QVERIFY(!Pin::validate(QStringLiteral("123")).isEmpty());
        QVERIFY(Pin::validate(QStringLiteral("1234"), QStringLiteral("1234")).isEmpty());
        QVERIFY(!Pin::validate(QStringLiteral("1234"), QStringLiteral("4321")).isEmpty());

        // Letters and symbols are refused unless they were asked for; the
        // length rule holds either way.
        QVERIFY(!Pin::validate(QStringLiteral("12ab")).isEmpty());
        QVERIFY(Pin::validate(QStringLiteral("12ab"), QString(), true).isEmpty());
        QVERIFY(Pin::validate(QStringLiteral("k7$w"), QString(), true).isEmpty());
        QVERIFY(!Pin::validate(QStringLiteral("ab"), QString(), true).isEmpty());

        // The warning goes by how many combinations the PIN gives, not by
        // how long it is: six digits are a million and pass, five are not.
        QVERIFY(!Pin::weakWarning(QStringLiteral("1234")).isEmpty());
        QVERIFY(!Pin::weakWarning(QStringLiteral("12345")).isEmpty());
        QVERIFY(Pin::weakWarning(QStringLiteral("123456")).isEmpty());
        // Four lowercase letters are 456976 — still short of it.
        QVERIFY(!Pin::weakWarning(QStringLiteral("abcd")).isEmpty());
        // The same four with a digit and a symbol are 69^4, over 22 million.
        QVERIFY(Pin::weakWarning(QStringLiteral("k7$w")).isEmpty());
        // Nothing flashes up while a PIN is still being typed.
        QVERIFY(Pin::weakWarning(QStringLiteral("12")).isEmpty());
    }

    void pinKeysAreScopedToEachDatabase() {
        const QString kdbx = QStringLiteral("/home/user/cofre.kdbx");
        const QString store = QStringLiteral("/home/user/.password-store");
        const QString bitwarden = QStringLiteral("bitwarden:pessoa@exemplo.com");
        const QString onePassword = QStringLiteral("1password:minha");

        // The keyring attribute carries the path, so two databases never
        // share a PIN and the entry says which one it belongs to.
        QCOMPARE(Pin::accountAttribute(kdbx), QStringLiteral("pin:") + kdbx);
        QCOMPARE(Pin::accountAttribute(bitwarden), QStringLiteral("pin:") + bitwarden);
        QVERIFY(Pin::accountAttribute(store) != Pin::accountAttribute(onePassword));

        // The attempt counter hangs off a digest instead: a settings key
        // cannot hold slashes, and the file has no business listing where
        // every database is.
        const QString key = Pin::attemptsKey(kdbx);
        QVERIFY(key.startsWith(QLatin1String("pin/attempts/")));
        QVERIFY(!key.contains(QLatin1String("cofre")));
        QCOMPARE(key, Pin::attemptsKey(kdbx));
        QVERIFY(key != Pin::attemptsKey(store));
    }

    void generatorArgumentsFollowTheOptions() {
        GeneratorOptions options;
        options.length = 24;
        options.special = false;
        options.excludeSimilar = true;
        options.exclude = QStringLiteral("aeiou");

        const QStringList args = Generator::arguments(options, QString());
        QCOMPARE(args.first(), QStringLiteral("generate"));
        QVERIFY(args.contains(QStringLiteral("-L")));
        QCOMPARE(args.at(args.indexOf(QStringLiteral("-L")) + 1), QStringLiteral("24"));
        QVERIFY(args.contains(QStringLiteral("-l")));
        QVERIFY(args.contains(QStringLiteral("-U")));
        QVERIFY(args.contains(QStringLiteral("-n")));
        QVERIFY(!args.contains(QStringLiteral("-s")));
        QVERIFY(args.contains(QStringLiteral("--exclude-similar")));
        QCOMPARE(args.at(args.indexOf(QStringLiteral("-x")) + 1), QStringLiteral("aeiou"));
    }

    void generatorCustomSetReplacesTheClasses() {
        GeneratorOptions options;
        options.custom = QStringLiteral("abc123");

        const QStringList args = Generator::arguments(options, QString());
        QCOMPARE(args.at(args.indexOf(QStringLiteral("-c")) + 1), QStringLiteral("abc123"));
        QVERIFY(!args.contains(QStringLiteral("-l")));
        QVERIFY(!args.contains(QStringLiteral("-U")));
    }

    void generatorPassphraseAsksForWordsAndWordlist() {
        GeneratorOptions options;
        options.passphrase = true;
        options.words = 7;

        const QStringList args = Generator::arguments(options, QStringLiteral("/tmp/eff.wordlist"));
        QCOMPARE(args.first(), QStringLiteral("diceware"));
        QCOMPARE(args.at(args.indexOf(QStringLiteral("-W")) + 1), QStringLiteral("7"));
        QCOMPARE(args.at(args.indexOf(QStringLiteral("-w")) + 1), QStringLiteral("/tmp/eff.wordlist"));
    }

    void generatorWordlistFollowsConfigAndLanguage() {
        const QString english = QStringLiteral("eff_large.wordlist");

        // "auto": the interface language first, English behind it.
        QCOMPARE(Generator::wordlistNames(QStringLiteral("auto"), QStringLiteral("pt-BR")),
                 QStringList({QStringLiteral("pt-BR.wordlist"), english}));
        QCOMPARE(Generator::wordlistNames(QStringLiteral("auto"), QStringLiteral("en")),
                 QStringList({english}));

        // A named list still falls back to English; "en" is the English one.
        QCOMPARE(Generator::wordlistNames(QStringLiteral("pt-BR"), QStringLiteral("en")),
                 QStringList({QStringLiteral("pt-BR.wordlist"), english}));
        QCOMPARE(Generator::wordlistNames(QStringLiteral("en"), QStringLiteral("pt-BR")),
                 QStringList({english}));

        // A path is taken as it is, with nothing behind it.
        QCOMPARE(Generator::wordlistNames(QStringLiteral("/tmp/minha.txt"), QStringLiteral("pt-BR")),
                 QStringList({QStringLiteral("/tmp/minha.txt")}));

        QVERIFY(!Generator::wordlistDirectories().isEmpty());
    }

    void generatorOptionsAreBounded() {
        GeneratorOptions options;
        options.length = 2;
        options.words = 99;
        options.lower = options.upper = options.numbers = options.special = false;

        const GeneratorOptions bounded = Generator::normalize(options);
        QCOMPARE(bounded.length, 4);
        QCOMPARE(bounded.words, 16);
        // Nothing selected would leave keepassxc-cli with no characters.
        QVERIFY(bounded.lower);

        GeneratorOptions custom;
        custom.custom = QStringLiteral("xyz");
        custom.lower = custom.upper = custom.numbers = custom.special = false;
        QVERIFY(!Generator::normalize(custom).lower);
    }

    void secretsWipeTheirOwnStorage() {
        Secret secret(QStringLiteral("hunter2"));
        QCOMPARE(secret.toString(), QStringLiteral("hunter2"));
        QCOMPARE(secret.length(), 7);

        secret.clear();
        QVERIFY(secret.isEmpty());
    }

    void copiedSecretsDoNotShareStorage() {
        Secret original(QStringLiteral("hunter2"));
        Secret copy = original;
        QCOMPARE(copy.toString(), QStringLiteral("hunter2"));

        original.clear();
        QCOMPARE(copy.toString(), QStringLiteral("hunter2"));
    }
};

QTEST_MAIN(TestOmapass)
#include "tst_omapass.moc"
