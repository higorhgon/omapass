// The frecency engine.

#include "support.h"

#include "history.h"

class TestHistory : public QObject {
    Q_OBJECT

private slots:
    void frecencyWeightDecaysWithAge() {
        QCOMPARE(weightForAge(0), 100u);
        QCOMPARE(weightForAge(86399), 100u);
        QCOMPARE(weightForAge(86400), 50u);
        QCOMPARE(weightForAge(604800), 20u);
        QCOMPARE(weightForAge(2592000), 5u);
    }
};

OMAPASS_TEST(TestHistory)
#include "tst_history.moc"
