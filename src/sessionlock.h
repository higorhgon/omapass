#pragma once

#include <QObject>

class QProcess;

// Detects the desktop session getting locked, so the caller can close the
// app entirely — an unlocked vault should never sit behind the lock screen.
// Two independent sources feed the same signal, because no single one covers
// every setup:
//
// - logind's `Lock` signal (org.freedesktop.login1.Session), the D-Bus
//   session GNOME, KDE and anything running `loginctl lock-session` ends up
//   emitting.
// - Hyprland/Omarchy: the compositor locks purely through the Wayland
//   ext-session-lock protocol and never touches logind (confirmed reading
//   Omarchy's own shell — omarchy-system-lock forwards to its Quickshell
//   lock plugin, no `loginctl` anywhere in the chain), so this polls
//   `omarchy-hyprland-session-locked` — the script Omarchy ships to answer
//   exactly this question — every couple seconds, and only when both a
//   Hyprland session and that binary are present.
class SessionLockWatcher : public QObject {
    Q_OBJECT

public:
    explicit SessionLockWatcher(QObject *parent = nullptr);

signals:
    void locked();

private slots:
    // Matches logind's Session.Lock D-Bus signal, which carries no arguments.
    void handleLogindLock();
    void pollHyprlandOnce();

private:
    void watchLogind();
    void subscribeToLogindLock(const QString &sessionPath);
    void startHyprlandPollingIfApplicable();
    void fire();

    QProcess *m_hyprlandProcess = nullptr;
    bool m_fired = false;
};
