// Copying a password and taking it back off the clipboard. The suite runs on
// the offscreen platform, so this is Qt's own clipboard; the wl-copy path
// needs a Wayland compositor and is not exercised here.

#include "support.h"

#include "clipboard.h"

#include <QClipboard>
#include <QGuiApplication>
#include <QMimeData>

class TestClipboard : public QObject {
    Q_OBJECT

private slots:
    void cleanup() {
        // Whatever a test left pending must not reach the next one.
        Clipboard::clearPending();
        QGuiApplication::clipboard()->clear();
    }

    void historyPreviewMatchesOnlyWhatCouldBeTheSecret() {
        QVERIFY(Clipboard::previewMayBe(QStringLiteral("s3nh4"), QStringLiteral("s3nh4")));
        // cliphist collapses whitespace in the preview.
        QVERIFY(Clipboard::previewMayBe(QStringLiteral("cavalo bateria grampo"),
                                        QStringLiteral(" cavalo  bateria\tgrampo ")));
        // A long entry is cut short with an ellipsis.
        const QString longSecret = QString(150, QLatin1Char('x')) + QStringLiteral("fim");
        QVERIFY(Clipboard::previewMayBe(QString(100, QLatin1Char('x')) + QStringLiteral("…"), longSecret));

        QVERIFY(!Clipboard::previewMayBe(QStringLiteral("s3nh4-e-mais"), QStringLiteral("s3nh4")));
        QVERIFY(!Clipboard::previewMayBe(QStringLiteral("outra…"), QStringLiteral("s3nh4")));
        QVERIFY(!Clipboard::previewMayBe(QStringLiteral("…"), QStringLiteral("s3nh4")));
        QVERIFY(!Clipboard::previewMayBe(QString(), QString()));
    }

    void copiedPasswordIsMarkedSensitive() {
        QVERIFY(Clipboard::copy(QStringLiteral("segredo")));
        const QClipboard *clipboard = QGuiApplication::clipboard();
        QCOMPARE(clipboard->text(), QStringLiteral("segredo"));
        QVERIFY(clipboard->mimeData()->hasFormat(QStringLiteral("x-kde-passwordManagerHint")));
    }

    void quittingClearsAPasswordStillOnTheClipboard() {
        QVERIFY(Clipboard::copy(QStringLiteral("segredo")));
        Clipboard::scheduleClear(Secret(QStringLiteral("segredo")));
        Clipboard::clearPending();
        QVERIFY(QGuiApplication::clipboard()->text().isEmpty());
    }

    void quittingLeavesWhatTheUserCopiedSince() {
        QVERIFY(Clipboard::copy(QStringLiteral("segredo")));
        Clipboard::scheduleClear(Secret(QStringLiteral("segredo")));
        QGuiApplication::clipboard()->setText(QStringLiteral("um link qualquer"));
        Clipboard::clearPending();
        QCOMPARE(QGuiApplication::clipboard()->text(), QStringLiteral("um link qualquer"));
    }

    void nothingPendingClearsNothing() {
        QGuiApplication::clipboard()->setText(QStringLiteral("um link qualquer"));
        Clipboard::clearPending();
        QCOMPARE(QGuiApplication::clipboard()->text(), QStringLiteral("um link qualquer"));
    }

    void onlyTheLatestCopyClearsTheClipboard() {
        // The first copy's timer fires halfway through the second one's
        // countdown, with the same password back on the clipboard: it must
        // leave it for the second timer.
        QVERIFY(Clipboard::copy(QStringLiteral("segredo")));
        Clipboard::scheduleClear(Secret(QStringLiteral("segredo")));
        QTest::qWait(Clipboard::clearSecs * 500);
        QVERIFY(Clipboard::copy(QStringLiteral("segredo")));
        Clipboard::scheduleClear(Secret(QStringLiteral("segredo")));

        QTest::qWait(Clipboard::clearSecs * 500 + 500);
        QCOMPARE(QGuiApplication::clipboard()->text(), QStringLiteral("segredo"));
        QTRY_VERIFY_WITH_TIMEOUT(QGuiApplication::clipboard()->text().isEmpty(), Clipboard::clearSecs * 1000);
    }
};

OMAPASS_TEST(TestClipboard)
#include "tst_clipboard.moc"
