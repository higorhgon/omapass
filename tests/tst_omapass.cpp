#include <QtTest>

#include "bitwardenjson.h"
#include "bwcache.h"
#include "pin.h"
#include "bwcrypto.h"
#include "config.h"
#include "filter.h"
#include "generator.h"
#include "history.h"
#include "i18n.h"
#include "kdbx2pass.h"
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

    void onePasswordAccountsFallBackToTheUserId() {
        const QVector<OpAccount> accounts = parseOpAccounts(opFixture("accounts.json"));
        QCOMPARE(accounts.size(), 2);
        QCOMPARE(accounts.at(0).key(), QStringLiteral("minha"));
        QCOMPARE(accounts.at(0).email, QStringLiteral("pessoa@exemplo.com"));
        QCOMPARE(accounts.at(1).key(), accounts.at(1).userUuid);
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

    void bitwardenCacheDecryptsEveryKindOfLogin() {
        const std::optional<BwCache> cache = BwCache::load(QStringLiteral(OMAPASS_BW_FIXTURES "/data.json"));
        QVERIFY(cache);
        QCOMPARE(cache->email(), QStringLiteral("teste@exemplo.com"));

        const QJsonObject v = bwFixture("vectors.json");
        QHash<QString, QJsonObject> items;
        QHash<QString, QString> folders;
        QCOMPARE(cache->decrypt(Secret(v.value("password").toString()), &items, &folders), BwCache::Result::Ok);

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

    void bitwardenCacheRejectsAWrongPassword() {
        const std::optional<BwCache> cache = BwCache::load(QStringLiteral(OMAPASS_BW_FIXTURES "/data.json"));
        QVERIFY(cache);
        QHash<QString, QJsonObject> items;
        QHash<QString, QString> folders;
        QCOMPARE(cache->decrypt(Secret(QStringLiteral("errada")), &items, &folders),
                 BwCache::Result::WrongPassword);
        QVERIFY(items.isEmpty());
    }

    void bitwardenCacheFallsBackOnUnknownShapes() {
        QTemporaryDir dir;
        const QString path = dir.filePath(QStringLiteral("data.json"));
        const auto write = [&path](const QJsonObject &root) {
            QFile file(path);
            QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
            file.write(QJsonDocument(root).toJson());
        };
        const QString password = bwFixture("vectors.json").value("password").toString();
        const QJsonObject original = bwFixture("data.json");
        const QString prefix = QStringLiteral("user_") + original.value("global_account_activeAccountId").toString() + '_';
        QHash<QString, QJsonObject> items;
        QHash<QString, QString> folders;

        QVERIFY(!BwCache::load(dir.filePath(QStringLiteral("missing.json"))));

        // No master password unlock data (an SSO account, say).
        QJsonObject root = original;
        root.remove(prefix + "masterPasswordUnlock_masterPasswordUnlockKey");
        write(root);
        QVERIFY(!BwCache::load(path));

        // An unknown KDF.
        root = original;
        QJsonObject unlock = root.value(prefix + "masterPasswordUnlock_masterPasswordUnlockKey").toObject();
        unlock.insert("kdf", QJsonObject{{"kdfType", 9}, {"iterations", 1}});
        root.insert(prefix + "masterPasswordUnlock_masterPasswordUnlockKey", unlock);
        write(root);
        QCOMPARE(BwCache::load(path)->decrypt(Secret(password), &items, &folders), BwCache::Result::Unsupported);

        // One login encrypted in a format this does not read: the whole vault
        // is refused rather than shown without it.
        root = original;
        QJsonObject ciphers = root.value(prefix + "ciphers_ciphers").toObject();
        QJsonObject cipher = ciphers.value("c2").toObject();
        cipher.insert("name", QStringLiteral("7.bmV3LWZvcm1hdA=="));
        ciphers.insert("c2", cipher);
        root.insert(prefix + "ciphers_ciphers", ciphers);
        write(root);
        QCOMPARE(BwCache::load(path)->decrypt(Secret(password), &items, &folders), BwCache::Result::Unsupported);
        QVERIFY(items.isEmpty());
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
