// The pass entry format and the kdbx2pass import.

#include "support.h"

#include "i18n.h"
#include "kdbx2pass.h"
#include "passstore.h"
#include "passvault.h"
#include "process.h"

#include <QStandardPaths>

namespace {

// A GnuPG home of the test's own, with one key protected by `passphrase`,
// so `pass` and `gpg` can run for real without touching the user's keyring.
struct TemporaryGnupg {
    QTemporaryDir home;
    QByteArray originalHome;
    QString keyId;

    static constexpr const char *passphrase = "frase-certa";

    TemporaryGnupg() : originalHome(qgetenv("GNUPGHOME")) {
        qputenv("GNUPGHOME", QFile::encodeName(home.path()));
        QFile::setPermissions(home.path(), QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
        QFile conf(home.filePath(QStringLiteral("gpg-agent.conf")));
        if (conf.open(QIODevice::WriteOnly))
            conf.write("allow-loopback-pinentry\n");
        conf.close();

        const ProcResult generated = runProcess(
            QStringLiteral("gpg"),
            {QStringLiteral("--batch"), QStringLiteral("--pinentry-mode"), QStringLiteral("loopback"),
             QStringLiteral("--passphrase"), QString::fromLatin1(passphrase), QStringLiteral("--quick-gen-key"),
             QStringLiteral("omapass teste <teste@exemplo.com>"), QStringLiteral("default"),
             QStringLiteral("default"), QStringLiteral("never")});
        const auto keys = PassStore::listSecretKeys();
        if (generated.success && !keys.isEmpty())
            keyId = keys.first().first;
    }

    ~TemporaryGnupg() {
        // The agent (and keyboxd, on newer GnuPG) go, and so does the socket
        // directory gpg made for this home under /run/user.
        runProcess(QStringLiteral("gpgconf"), {QStringLiteral("--kill"), QStringLiteral("all")});
        runProcess(QStringLiteral("gpgconf"), {QStringLiteral("--remove-socketdir")});
        if (originalHome.isNull())
            qunsetenv("GNUPGHOME");
        else
            qputenv("GNUPGHOME", originalHome);
    }
};

}

class TestPass : public QObject {
    Q_OBJECT

private slots:
    void passEntryKeepsBlankLinesAndRepeatedKeys() {
        const QString content = QStringLiteral(
            "senha\nusername: ana\nnota 1\n\nnota 2\nusername: outra\nurl: https://a\nurl: https://b\n\n");
        const PassEntryData data = parsePassEntry(content);
        QCOMPARE(data.username, QStringLiteral("ana"));
        QCOMPARE(data.url, QStringLiteral("https://a"));
        QCOMPARE(data.extra, QStringList({QStringLiteral("nota 1"), QString(), QStringLiteral("nota 2"),
                                          QStringLiteral("username: outra"), QStringLiteral("url: https://b")}));

        // Written back, nothing but the trailing blank line is gone.
        QCOMPARE(QString::fromUtf8(buildPassEntryContent(data)),
                 QStringLiteral("senha\nusername: ana\nurl: https://a\nnota 1\n\nnota 2\n"
                                "username: outra\nurl: https://b\n"));
    }

    void passRefusesAPasswordWithALineBreak() {
        const PassVault vault(QStringLiteral("/nenhum/lugar"), Secret());
        for (const char *password : {"duas\nlinhas", "duas\rlinhas"}) {
            EntryData data;
            data.password = Secret(QString::fromLatin1(password));
            QString error;
            QVERIFY(!vault.addEntry(QStringLiteral("x"), QString(), data, &error));
            QCOMPARE(error, I18n::t(QStringLiteral("pass.multiline_password")));
            error.clear();
            QVERIFY(!vault.editEntry(QStringLiteral("x"), QStringLiteral("x"), QString(), data, &error));
            QCOMPARE(error, I18n::t(QStringLiteral("pass.multiline_password")));
        }
    }

    void passStoreRunsThroughRealGpg() {
        if (QStandardPaths::findExecutable(QStringLiteral("pass")).isEmpty()
            || QStandardPaths::findExecutable(QStringLiteral("gpg")).isEmpty())
            QSKIP("pass and gpg are not both available");

        const TemporaryGnupg gnupg;
        if (gnupg.keyId.isEmpty())
            QSKIP("gpg could not generate a key here");

        QTemporaryDir stores;
        const QString root = stores.filePath(QStringLiteral("loja"));
        QString error;
        QVERIFY2(PassStore::initStore(root, gnupg.keyId, &error), qPrintable(error));
        QVERIFY(PassStore::isStore(root));
        QVERIFY(!PassStore::initStore(root, gnupg.keyId, &error));

        const PassStore store(root);
        PassEntryData entry;
        entry.password = Secret(QStringLiteral("s3nh4"));
        entry.username = QStringLiteral("ana");
        entry.extra = {QStringLiteral("nota"), QString(), QStringLiteral("depois do branco")};
        QVERIFY2(store.insert(QStringLiteral("Email/gmail"), entry, &error), qPrintable(error));
        // A name that looks like an option is still a name.
        QVERIFY2(store.insert(QStringLiteral("-r"), entry, &error), qPrintable(error));

        QStringList entries, groups;
        store.list(&entries, &groups);
        QCOMPARE(entries, QStringList({QStringLiteral("-r"), QStringLiteral("Email/gmail")}));
        QCOMPARE(groups, QStringList{QStringLiteral("Email")});

        // The agent cache is cleared first, so a wrong passphrase is caught
        // even right after the right one was used.
        const Secret right(QString::fromLatin1(TemporaryGnupg::passphrase));
        QVERIFY2(store.verifyPassphrase(right, &error), qPrintable(error));
        QVERIFY(!store.verifyPassphrase(Secret(QStringLiteral("frase-errada")), &error));
        QCOMPARE(error, I18n::t(QStringLiteral("pass.wrong_gpg_password")));

        PassEntryData read;
        QVERIFY2(store.show(QStringLiteral("Email/gmail"), right, &read, &error), qPrintable(error));
        QCOMPARE(read.password.toString(), QStringLiteral("s3nh4"));
        QCOMPARE(read.username, QStringLiteral("ana"));
        QCOMPARE(read.extra, entry.extra);
        QVERIFY(!store.show(QStringLiteral("nao-existe"), right, &read, &error));

        QVERIFY2(store.move(QStringLiteral("-r"), QStringLiteral("Email/-r"), &error), qPrintable(error));
        QVERIFY2(store.remove(QStringLiteral("Email/-r"), &error), qPrintable(error));
        entries.clear();
        groups.clear();
        store.list(&entries, &groups);
        QCOMPARE(entries, QStringList{QStringLiteral("Email/gmail")});
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
};

OMAPASS_TEST(TestPass)
#include "tst_pass.moc"
