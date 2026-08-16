#include "sessionlock.h"

#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusObjectPath>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QProcess>
#include <QStandardPaths>
#include <QTimer>

namespace {

const auto logindService = QStringLiteral("org.freedesktop.login1");
const auto logindManagerPath = QStringLiteral("/org/freedesktop/login1");
const auto logindManagerInterface = QStringLiteral("org.freedesktop.login1.Manager");
const auto logindSessionInterface = QStringLiteral("org.freedesktop.login1.Session");

// omarchy-hyprland-session-locked itself wraps a single hyprctl round-trip
// (see its own header comment), so this is cheap; the compositor's lock
// already protects the screen in the meantime — this is reinforcement, not
// the first line of defence.
constexpr int hyprlandPollIntervalMs = 2000;

}

SessionLockWatcher::SessionLockWatcher(QObject *parent) : QObject(parent) {
    watchLogind();
    startHyprlandPollingIfApplicable();
}

void SessionLockWatcher::watchLogind() {
    const QDBusConnection bus = QDBusConnection::systemBus();
    if (!bus.isConnected())
        return;

    // $XDG_SESSION_ID is the reliable way to know our own session; falls
    // back to GetSessionByPID only when it is unset. GetSessionByPID alone
    // fails whenever the process has no session cgroup of its own
    // (containers, sandboxes, some CI setups), which is why the order here
    // matters.
    QDBusMessage request;
    const QString sessionId = qEnvironmentVariable("XDG_SESSION_ID");
    if (!sessionId.isEmpty()) {
        request = QDBusMessage::createMethodCall(logindService, logindManagerPath,
                                                  logindManagerInterface,
                                                  QStringLiteral("GetSession"));
        request << sessionId;
    } else {
        request = QDBusMessage::createMethodCall(logindService, logindManagerPath,
                                                  logindManagerInterface,
                                                  QStringLiteral("GetSessionByPID"));
        request << static_cast<uint>(QCoreApplication::applicationPid());
    }

    auto *watcher = new QDBusPendingCallWatcher(bus.asyncCall(request), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this,
            [this](QDBusPendingCallWatcher *finished) {
        const QDBusPendingReply<QDBusObjectPath> reply(*finished);
        finished->deleteLater();
        if (!reply.isValid())
            return; // sem logind, ou fora de qualquer sessão rastreada — sem problema
        subscribeToLogindLock(reply.value().path());
    });
}

void SessionLockWatcher::subscribeToLogindLock(const QString &sessionPath) {
    QDBusConnection::systemBus().connect(
        logindService, sessionPath, logindSessionInterface, QStringLiteral("Lock"),
        this, SLOT(handleLogindLock()));
}

void SessionLockWatcher::handleLogindLock() {
    fire();
}

void SessionLockWatcher::startHyprlandPollingIfApplicable() {
    if (qEnvironmentVariableIsEmpty("HYPRLAND_INSTANCE_SIGNATURE"))
        return;
    if (QStandardPaths::findExecutable(QStringLiteral("omarchy-hyprland-session-locked")).isEmpty())
        return;

    auto *timer = new QTimer(this);
    timer->setInterval(hyprlandPollIntervalMs);
    connect(timer, &QTimer::timeout, this, &SessionLockWatcher::pollHyprlandOnce);
    timer->start();
}

void SessionLockWatcher::pollHyprlandOnce() {
    if (m_fired || m_hyprlandProcess)
        return; // já disparado, ou uma sondagem anterior ainda não voltou

    m_hyprlandProcess = new QProcess(this);
    connect(m_hyprlandProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this](int exitCode, QProcess::ExitStatus) {
        m_hyprlandProcess->deleteLater();
        m_hyprlandProcess = nullptr;
        if (exitCode == 0) // 0 = travado; 1 destravado e 2 indeterminado seguem sondando
            fire();
    });
    m_hyprlandProcess->start(QStringLiteral("omarchy-hyprland-session-locked"), {});
}

void SessionLockWatcher::fire() {
    if (m_fired)
        return;
    m_fired = true;
    emit locked();
}
