// The buffer that wipes its own storage.

#include "support.h"

#include "secret.h"

class TestSecret : public QObject {
    Q_OBJECT

private slots:
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

OMAPASS_TEST(TestSecret)
#include "tst_secret.moc"
