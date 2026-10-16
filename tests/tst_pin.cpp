// The PIN blob, its validation and its scope per database.

#include "support.h"

#include "pin.h"
#include "process.h"

#include <QSettings>

class TestPin : public QObject {
    Q_OBJECT

private slots:
    void pinStoresAndRecoversThePassword() {
        FakeSecretTool keyring;
        const QString vault = QStringLiteral("/home/user/cofre.kdbx");
        QVERIFY(Pin::isAvailable());
        QVERIFY(!Pin::hasPin(vault));

        QString error;
        QVERIFY2(Pin::store(vault, QStringLiteral("482916"), Secret(QStringLiteral("senha-mestra")), &error),
                 qPrintable(error));
        QVERIFY(Pin::hasPin(vault));

        Secret password;
        QCOMPARE(Pin::recover(vault, QStringLiteral("482916"), &password), Pin::Result::Ok);
        QCOMPARE(password.toString(), QStringLiteral("senha-mestra"));

        // A wrong PIN fails the MAC and leaves nothing behind.
        Secret untouched;
        QCOMPARE(Pin::recover(vault, QStringLiteral("482917"), &untouched), Pin::Result::WrongPin);
        QVERIFY(untouched.isEmpty());

        // Neither the PIN nor the password went through argv.
        const QString arguments = keyring.arguments();
        QVERIFY(!arguments.isEmpty());
        QVERIFY(!arguments.contains(QStringLiteral("482916")));
        QVERIFY(!arguments.contains(QStringLiteral("senha-mestra")));
    }

    void pinIsDeletedAfterTooManyWrongTries() {
        FakeSecretTool keyring;
        const QString vault = QStringLiteral("/home/user/cofre.kdbx");
        QString error;
        QVERIFY2(Pin::store(vault, QStringLiteral("482916"), Secret(QStringLiteral("x")), &error),
                 qPrintable(error));

        for (int attempt = 1; attempt < Pin::maxAttempts; ++attempt) {
            QCOMPARE(Pin::registerFailure(vault), Pin::maxAttempts - attempt);
            QCOMPARE(Pin::failedAttempts(vault), attempt);
            QVERIFY(Pin::hasPin(vault));
        }
        QCOMPARE(Pin::registerFailure(vault), 0);
        QVERIFY(!Pin::hasPin(vault));
        QCOMPARE(Pin::failedAttempts(vault), 0);

        Secret password;
        QCOMPARE(Pin::recover(vault, QStringLiteral("482916"), &password), Pin::Result::Missing);
    }

    void pinStoredAgainStartsTheCountOver() {
        FakeSecretTool keyring;
        const QString vault = QStringLiteral("/home/user/cofre.kdbx");
        QString error;
        QVERIFY(Pin::store(vault, QStringLiteral("482916"), Secret(QStringLiteral("x")), &error));
        Pin::registerFailure(vault);
        Pin::registerFailure(vault);
        QCOMPARE(Pin::failedAttempts(vault), 2);

        QVERIFY(Pin::store(vault, QStringLiteral("739105"), Secret(QStringLiteral("x")), &error));
        QCOMPARE(Pin::failedAttempts(vault), 0);
        Pin::clear(vault);
        QVERIFY(!Pin::hasPin(vault));
    }

    void pinWithoutAKeyringIsUnavailable() {
        const QTemporaryDir empty;
        const PathOverride path(QFile::encodeName(empty.path()));
        QVERIFY(!Pin::isAvailable());

        const QString vault = QStringLiteral("/home/user/cofre.kdbx");
        QVERIFY(!Pin::hasPin(vault));
        QString error;
        QVERIFY(!Pin::store(vault, QStringLiteral("482916"), Secret(QStringLiteral("x")), &error));
        QVERIFY(!error.isEmpty());
        // Called without somewhere to put the reason, it still just fails.
        QVERIFY(!Pin::store(vault, QStringLiteral("482916"), Secret(QStringLiteral("x")), nullptr));

        Secret password;
        QCOMPARE(Pin::recover(vault, QStringLiteral("482916"), &password), Pin::Result::Unavailable);
    }

    void pinFromBeforePerDatabaseIsMovedOver() {
        FakeSecretTool keyring;
        const QString vault = QStringLiteral("bitwarden:pessoa@exemplo.com");
        QString error;
        QVERIFY(Pin::store(vault, QStringLiteral("482916"), Secret(QStringLiteral("senha")), &error));

        // Put the blob where the single-account version kept it.
        const QStringList current = {QStringLiteral("service"), QStringLiteral("omapass"),
                                     QStringLiteral("account"), Pin::accountAttribute(vault)};
        const QStringList legacy = {QStringLiteral("service"), QStringLiteral("omapass"),
                                    QStringLiteral("account"), QStringLiteral("bitwarden-pin:pessoa@exemplo.com")};
        const ProcResult blob = runProcess(QStringLiteral("secret-tool"), QStringList{QStringLiteral("lookup")} + current);
        QVERIFY(blob.success);
        runProcess(QStringLiteral("secret-tool"), QStringList{QStringLiteral("clear")} + current);
        QVERIFY(runProcess(QStringLiteral("secret-tool"),
                           QStringList{QStringLiteral("store"), QStringLiteral("--label"), QStringLiteral("x")} + legacy,
                           blob.out.toUtf8()).success);
        QSettings().setValue(QStringLiteral("bitwarden/pinAttempts"), 2);

        Secret password;
        QCOMPARE(Pin::recover(vault, QStringLiteral("482916"), &password), Pin::Result::Ok);
        QCOMPARE(password.toString(), QStringLiteral("senha"));
        QVERIFY(!runProcess(QStringLiteral("secret-tool"), QStringList{QStringLiteral("lookup")} + legacy).success);
        QVERIFY(runProcess(QStringLiteral("secret-tool"), QStringList{QStringLiteral("lookup")} + current).success);
        QCOMPARE(Pin::failedAttempts(vault), 2);
        QVERIFY(!QSettings().contains(QStringLiteral("bitwarden/pinAttempts")));

        Pin::clear(vault);
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
};

OMAPASS_TEST(TestPin)
#include "tst_pin.moc"
