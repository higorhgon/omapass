// The PIN blob, its validation and its scope per database.

#include "support.h"

#include "pin.h"
#include "bwcrypto.h"

class TestPin : public QObject {
    Q_OBJECT

private slots:
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
