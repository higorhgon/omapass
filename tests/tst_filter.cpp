// The multi-term search over the entry list.

#include "support.h"

#include "filter.h"
#include "bitwardenjson.h"

class TestFilter : public QObject {
    Q_OBJECT

private slots:
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

    void filterIndexesMatchesEveryTermAnywhereInTheHaystack() {
        const QStringList rows = {QStringLiteral("Deploy ssh ci@host https://git.example"),
                                  QStringLiteral("Gmail senha pessoa https://mail.google.com")};
        QCOMPARE(filterIndexes(rows, QStringLiteral("SSH git")), QList<int>({0}));
        QCOMPARE(filterIndexes(rows, QStringLiteral("senha google")), QList<int>({1}));
        QCOMPARE(filterIndexes(rows, QString()), QList<int>({0, 1}));
        QVERIFY(filterIndexes(rows, QStringLiteral("zzz")).isEmpty());
    }
};

OMAPASS_TEST(TestFilter)
#include "tst_filter.moc"
