#include <QtTest>

#include "bitwardenjson.h"
#include "config.h"
#include "filter.h"
#include "history.h"
#include "i18n.h"
#include "kdbx2pass.h"
#include "passstore.h"
#include "secret.h"

namespace {

// Output of `bw`, as plain string literals: moc does not cope with raw
// strings in this file.
const char bwStatusLocked[] =
    "{\"serverUrl\":null,\"lastSync\":\"2026-09-17T10:00:00.000Z\",\"userEmail\":\"a@b.com\",\"userId\":\"u1\",\"status\":\"locked\"}";

const char bwStatusLoggedOut[] =
    "{\"serverUrl\":null,\"lastSync\":null,\"status\":\"unauthenticated\"}";

const char bwDataFileLoggedIn[] =
    "{\"global_account_activeAccountId\":\"u1\","
    "\"global_account_accounts\":{\"u1\":{\"email\":\"a@b.com\",\"emailVerified\":true}},"
    "\"user_u1_token_accessToken\":\"secret\"}";

const char bwDataFileLoggedOut[] =
    "{\"global_account_activeAccountId\":null,\"global_account_accounts\":{}}";

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

    void bitwardenStatusReadsStateAndEmail() {
        const BwStatus locked = parseBwStatus(QString::fromUtf8(bwStatusLocked));
        QCOMPARE(locked.status, QStringLiteral("locked"));
        QCOMPARE(locked.userEmail, QStringLiteral("a@b.com"));
        QVERIFY(locked.loggedIn());

        const BwStatus out = parseBwStatus(QString::fromUtf8(bwStatusLoggedOut));
        QVERIFY(!out.loggedIn());
        QVERIFY(parseBwStatus(QStringLiteral("garbage")).status.isEmpty());
    }

    void bitwardenDataFileTellsWhoIsLoggedIn() {
        const BwStatus in = parseBwDataFile(bwDataFileLoggedIn);
        QVERIFY(in.loggedIn());
        QCOMPARE(in.userEmail, QStringLiteral("a@b.com"));

        const BwStatus out = parseBwDataFile(bwDataFileLoggedOut);
        QCOMPARE(out.status, QStringLiteral("unauthenticated"));

        QVERIFY(parseBwDataFile("not json").status.isEmpty());
        QVERIFY(parseBwDataFile("{\"global_account_activeAccountId\":\"u9\"}").status.isEmpty());
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

        const BwIndex index = buildBwIndex(items, folders);
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

        const BwIndex index = buildBwIndex(items, "[]");
        QVERIFY(index.items.contains(QStringLiteral("Mail [aaaaaaaa]")));
        QVERIFY(index.items.contains(QStringLiteral("Mail [bbbbbbbb]")));
        QVERIFY(!index.items.contains(QStringLiteral("Mail")));
        const QString slashed = QStringLiteral("a") + QChar(0x2215) + QStringLiteral("b");
        QCOMPARE(index.items.value(slashed).name, QStringLiteral("a/b"));
    }

    void bitwardenEditKeepsFieldsItDoesNotModel() {
        const QByteArray original(bwItemWithExtras);

        EntryData data;
        data.username = QStringLiteral("new-user");
        data.password = Secret(QStringLiteral("new-pass"));
        data.url = QStringLiteral("https://c");

        const QJsonObject item =
            QJsonDocument::fromJson(applyBwEntryData(original, QStringLiteral("New"), QString(), data)).object();
        const QJsonObject login = item.value(QStringLiteral("login")).toObject();

        QCOMPARE(item.value(QStringLiteral("name")).toString(), QStringLiteral("New"));
        QVERIFY(item.value(QStringLiteral("folderId")).isNull());
        QVERIFY(item.value(QStringLiteral("notes")).isNull());
        QCOMPARE(item.value(QStringLiteral("organizationId")).toString(), QStringLiteral("o1"));
        QCOMPARE(item.value(QStringLiteral("fields")).toArray().size(), 1);
        QCOMPARE(login.value(QStringLiteral("username")).toString(), QStringLiteral("new-user"));
        QCOMPARE(login.value(QStringLiteral("password")).toString(), QStringLiteral("new-pass"));
        QCOMPARE(login.value(QStringLiteral("totp")).toString(), QStringLiteral("otpauth://x"));
        const QJsonArray uris = login.value(QStringLiteral("uris")).toArray();
        QCOMPARE(uris.size(), 2);
        QCOMPARE(uris.at(0).toObject().value(QStringLiteral("uri")).toString(), QStringLiteral("https://c"));
        QCOMPARE(uris.at(1).toObject().value(QStringLiteral("uri")).toString(), QStringLiteral("https://b"));
    }

    void bitwardenNewItemStartsFromABlankLogin() {
        EntryData data;
        data.password = Secret(QStringLiteral("p"));
        const QJsonObject item =
            QJsonDocument::fromJson(applyBwEntryData({}, QStringLiteral("Site"), QStringLiteral("f1"), data)).object();
        QCOMPARE(item.value(QStringLiteral("type")).toInt(), 1);
        QCOMPARE(item.value(QStringLiteral("folderId")).toString(), QStringLiteral("f1"));
        QVERIFY(item.value(QStringLiteral("login")).toObject().value(QStringLiteral("uris")).toArray().isEmpty());
    }

    void bitwardenErrorsAreClassified() {
        QCOMPARE(classifyBwError(QStringLiteral("Username or password is incorrect. Try again.")),
                 BwLoginError::WrongPassword);
        QCOMPARE(classifyBwError(QStringLiteral("Invalid master password.")), BwLoginError::WrongPassword);
        QCOMPARE(classifyBwError(QStringLiteral("Two-step token is invalid. Try again.")),
                 BwLoginError::InvalidCode);
        QCOMPARE(classifyBwError(QStringLiteral("You are already logged in as a@b.com.")),
                 BwLoginError::AlreadyLoggedIn);
        QCOMPARE(classifyBwError(QStringLiteral("Something else")), BwLoginError::Other);
        QCOMPARE(classifyBwError(QString()), BwLoginError::None);
    }

    void bitwardenPromptsAreDetected() {
        QCOMPARE(detectBwPrompt(QStringLiteral("? Two-step login method: (Use arrow keys)")),
                 BwPrompt::TwoFactorMethod);
        QCOMPARE(detectBwPrompt(QStringLiteral("\x1b[2K? Two-step login code: ")), BwPrompt::TwoFactorCode);
        QCOMPARE(detectBwPrompt(QStringLiteral(
                     "? Two-step login code: 123\n? New device verification required. Enter OTP sent to login email:")),
                 BwPrompt::NewDeviceCode);
        QCOMPARE(detectBwPrompt(QStringLiteral("loading")), BwPrompt::None);
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
