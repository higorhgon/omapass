// Closing omapass when the desktop session locks. The logind half needs the
// system bus and is built only with D-Bus; what is tested is the Hyprland
// probe, through a fake omarchy-hyprland-session-locked.

#include "support.h"

#include "sessionlock.h"

#include <QSignalSpy>

namespace {

// Two polls and a little: the watcher asks every two seconds.
constexpr int twoPollsMs = 4500;

}

class TestSessionLock : public QObject {
    Q_OBJECT

private slots:
    void init() {
        m_path = qgetenv("PATH");
        m_signature = qgetenv("HYPRLAND_INSTANCE_SIGNATURE");
        qputenv("PATH", QByteArray(OMAPASS_FAKE_CLIS ":") + m_path);
        qputenv("HYPRLAND_INSTANCE_SIGNATURE", "teste");
        qputenv("SESSION_LOCKED_FAKE_EXIT", "1");
    }

    void cleanup() {
        qputenv("PATH", m_path);
        if (m_signature.isNull())
            qunsetenv("HYPRLAND_INSTANCE_SIGNATURE");
        else
            qputenv("HYPRLAND_INSTANCE_SIGNATURE", m_signature);
        qunsetenv("SESSION_LOCKED_FAKE_EXIT");
    }

    void lockingTheSessionFiresOnce() {
        SessionLockWatcher watcher;
        QSignalSpy locked(&watcher, &SessionLockWatcher::locked);

        // Unlocked, and then a probe that cannot tell: nothing happens.
        QTest::qWait(twoPollsMs);
        qputenv("SESSION_LOCKED_FAKE_EXIT", "2");
        QTest::qWait(twoPollsMs);
        QCOMPARE(locked.count(), 0);

        qputenv("SESSION_LOCKED_FAKE_EXIT", "0");
        QVERIFY(locked.wait(twoPollsMs));
        // The application is on its way out; one signal is all it gets.
        QTest::qWait(twoPollsMs);
        QCOMPARE(locked.count(), 1);
    }

    void outsideHyprlandNothingIsPolled() {
        qunsetenv("HYPRLAND_INSTANCE_SIGNATURE");
        qputenv("SESSION_LOCKED_FAKE_EXIT", "0");
        SessionLockWatcher watcher;
        QSignalSpy locked(&watcher, &SessionLockWatcher::locked);
        QTest::qWait(twoPollsMs);
        QCOMPARE(locked.count(), 0);
    }

private:
    QByteArray m_path;
    QByteArray m_signature;
};

OMAPASS_TEST(TestSessionLock)
#include "tst_sessionlock.moc"
