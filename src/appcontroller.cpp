#include "appcontroller.h"

#include "bitwardenvault.h"
#include "pin.h"
#include "bwcache.h"
#include "clipboard.h"
#include "filter.h"
#include "generator.h"
#include "i18n.h"
#include "onepasswordvault.h"
#include "passstore.h"

#include <QCoreApplication>
#include <QDir>
#include <QEvent>
#include <QFutureWatcher>
#include <QRect>
#include <QFileInfo>
#include <QSettings>
#include <QUrl>
#include <QtConcurrent/QtConcurrentRun>

namespace {

// Como o timer só precisa perceber o estouro do timeout dentro de uma folga
// perceptível (o padrão é de minutos), não há necessidade de checar a cada
// segundo — 5s mantém o custo irrelevante sem atrasar visivelmente o lock.
constexpr int lockCheckIntervalMs = 5000;

const auto windowGeometrySetting = QStringLiteral("window/geometry");

// Outcome of a backend call run in the background.
struct TaskResult {
    bool ok = false;
    QString error;
};

struct OpenResult {
    Vault *vault = nullptr;
    QString error;
};

QVariantMap describe(const DbRef &ref) {
    // `label` is what the list shows: the file's own path for a database on
    // disk, which says which one it is, and the account's name for the
    // backends whose path is an internal identifier ("1password:my").
    const bool account = ref.kind == VaultKind::Bitwarden || ref.kind == VaultKind::OnePassword;
    return {{QStringLiteral("path"), ref.path},
            {QStringLiteral("name"), Vault::displayName(ref)},
            {QStringLiteral("label"), account ? Vault::displayName(ref) : ref.path},
            {QStringLiteral("kind"), Vault::kindLabel(ref.kind)}};
}

}

AppController::AppController(const AppConfig &config, QObject *parent)
    : QObject(parent), m_config(config), m_history(config.recencyEnabled) {
    m_messageTimer.setInterval(1000);
    connect(&m_messageTimer, &QTimer::timeout, this, [this]() {
        if (m_clipboardCountdown > 0) {
            m_clipboardCountdown -= 1;
            if (m_clipboardCountdown > 0) {
                emit messageChanged();
                return;
            }
        }
        clearMessage();
    });

    connect(&m_bitwardenLogin, &BitwardenLogin::promptShown, this, [this](BwPrompt prompt) {
        setBusy(false);
        setUnlockError(QString());
        switch (prompt) {
        case BwPrompt::TwoFactorMethod:
            setLoginStep(QStringLiteral("method"));
            break;
        case BwPrompt::TwoFactorCode:
            setLoginStep(QStringLiteral("code"));
            break;
        case BwPrompt::NewDeviceCode:
            setLoginStep(QStringLiteral("deviceCode"));
            break;
        case BwPrompt::None:
            break;
        }
    });
    connect(&m_bitwardenLogin, &BitwardenLogin::succeeded, this, [this](const Secret &session) {
        const QString email = m_loginEmail;
        setBusy(false);
        setLoginStep(QString());

        BitwardenVault::rememberAccount(email);
        refreshDatabases();
        emit databaseCreated();

        // The account is in the list from here on; loading it goes through
        // the unlock sheet's busy state, like any other open.
        const DbRef ref{BitwardenVault::refPath(email), VaultKind::Bitwarden};
        m_pendingDatabase = ref;
        m_hasPendingDatabase = true;
        refreshPinState();
        emit pendingDatabaseChanged();

        runInBackground(
            [email, session]() {
                OpenResult result;
                result.vault = BitwardenVault::openWithSession(email, session, &result.error);
                return result;
            },
            [this, ref](const OpenResult &result) {
                if (result.vault)
                    adoptVault(ref, result.vault);
                else
                    setUnlockError(result.error);
            });
    });
    connect(&m_bitwardenLogin, &BitwardenLogin::failed, this,
            [this](const QString &error, BwLoginError kind) {
        setBusy(false);
        m_loginPassword.clear();

        switch (kind) {
        case BwLoginError::WrongPassword:
            setUnlockError(I18n::t(QStringLiteral("backend.wrong_password")));
            break;
        case BwLoginError::InvalidEmail:
            setUnlockError(I18n::t(QStringLiteral("bitwarden.invalid_email")));
            break;
        case BwLoginError::InvalidCode:
            setUnlockError(I18n::t(QStringLiteral("bitwarden.invalid_code")));
            break;
        case BwLoginError::AlreadyLoggedIn:
            // Logged in from a terminal meanwhile: nothing left to do here
            // but unlock, which the account's own entry does.
            setLoginStep(QString());
            addBitwardenAccount();
            return;
        default:
            setUnlockError(error.isEmpty() ? I18n::t(QStringLiteral("bitwarden.login_failed")) : error);
            break;
        }
        // Every failure ends the bw process, so the next try starts over from
        // the credentials, e-mail kept.
        setLoginStep(QStringLiteral("credentials"));
    });

    connect(&m_onePasswordLogin, &OnePasswordLogin::promptShown, this, [this](OpPrompt prompt) {
        setBusy(false);
        setUnlockError(QString());
        if (prompt == OpPrompt::TwoFactorCode)
            setLoginStep(QStringLiteral("opCode"));
    });
    connect(&m_onePasswordLogin, &OnePasswordLogin::succeeded, this,
            [this](const QString &account, const QString &sessionVariable, const Secret &session) {
        const bool adding = m_onePasswordAdding;
        if (adding) {
            refreshDatabases();
            emit databaseCreated();
        }

        // Whatever sheet asked for the password stays up, busy, until the
        // vault is open: swapping to another one in between would ask for
        // something that was just given.
        const DbRef ref{OnePasswordVault::refPath(account), VaultKind::OnePassword};
        runInBackground(
            [account, sessionVariable, session]() {
                OpenResult result;
                result.vault = OnePasswordVault::openWithSession(account, session, sessionVariable,
                                                                 &result.error);
                return result;
            },
            [this, ref, adding](const OpenResult &result) {
                if (!result.vault) {
                    setUnlockError(result.error);
                    setLoginStep(adding ? QStringLiteral("opCredentials") : QString());
                    return;
                }
                setLoginStep(QString());
                adoptVault(ref, result.vault);
            });
    });
    connect(&m_onePasswordLogin, &OnePasswordLogin::failed, this,
            [this](const QString &error, OpError kind) {
        setBusy(false);

        switch (kind) {
        case OpError::WrongPassword:
            setUnlockError(I18n::t(QStringLiteral("backend.wrong_password")));
            break;
        case OpError::WrongSecretKey:
            setUnlockError(I18n::t(QStringLiteral("onepassword.wrong_secret_key")));
            break;
        case OpError::WrongCode:
            setUnlockError(I18n::t(QStringLiteral("onepassword.invalid_code")));
            break;
        default:
            setUnlockError(error.isEmpty() ? I18n::t(QStringLiteral("onepassword.login_failed")) : error);
            break;
        }
        // The process is over either way: adding an account starts over from
        // the credentials, opening one goes back to the unlock sheet, where
        // the error is shown.
        setLoginStep(m_onePasswordAdding ? QStringLiteral("opCredentials") : QString());
    });

    refreshDatabases();

    // With exactly one database there is nothing to choose: go straight to
    // its unlock prompt.
    if (m_databases.size() == 1)
        selectDatabase(0);

    m_lastActivity.start();
    qApp->installEventFilter(this);

    m_lockTimer.setInterval(lockCheckIntervalMs);
    connect(&m_lockTimer, &QTimer::timeout, this, [this]() {
        if (m_config.lockMinutes && m_lastActivity.hasExpired(qint64(*m_config.lockMinutes) * 60 * 1000))
            lock();
    });
    applyLockSettings();
}

// The timer only runs while auto-lock is on, so turning it off in the
// settings stops it rather than leaving it ticking for nothing.
void AppController::applyLockSettings() {
    if (m_config.lockMinutes) {
        m_lastActivity.restart();
        m_lockTimer.start();
    } else {
        m_lockTimer.stop();
    }
}

AppController::~AppController() {
    m_bitwardenLogin.cancel();
    m_onePasswordLogin.cancel();
    m_task.waitForFinished();
    m_syncTask.waitForFinished();
    closeVault();
}

template <typename Work, typename Done>
void AppController::runInBackground(Work work, Done done) {
    using Result = decltype(work());

    setBusy(true);
    auto *watcher = new QFutureWatcher<Result>(this);
    connect(watcher, &QFutureWatcher<Result>::finished, this, [this, watcher, done]() {
        const Result result = watcher->result();
        watcher->deleteLater();
        setBusy(false);
        done(result);
    });

    const QFuture<Result> future = QtConcurrent::run(std::move(work));
    m_task = QFuture<void>(future);
    watcher->setFuture(future);
}

bool AppController::requireIdle() {
    if (!m_busy)
        return true;
    showMessage(I18n::t(QStringLiteral("app.working")), true);
    return false;
}

bool AppController::vaultReadyForChanges() {
    if (m_vault.isNull() || m_busy)
        return false;
    if (m_syncing) {
        showMessage(I18n::t(QStringLiteral("bitwarden.wait_sync")), true);
        return false;
    }
    return true;
}

void AppController::setSyncing(bool syncing) {
    if (m_syncing == syncing)
        return;
    m_syncing = syncing;
    emit syncingChanged();
}

void AppController::startBackgroundSync() {
    auto *vault = dynamic_cast<BitwardenVault *>(m_vault.data());
    if (!vault)
        return;

    setSyncing(true);
    auto *watcher = new QFutureWatcher<TaskResult>(this);
    connect(watcher, &QFutureWatcher<TaskResult>::finished, this, [this, watcher]() {
        const TaskResult result = watcher->result();
        watcher->deleteLater();
        setSyncing(false);

        // Locking waits for the sync, so the vault is still the one synced.
        if (result.ok)
            refreshEntries();
        else
            showMessage(I18n::t(QStringLiteral("bitwarden.sync_error"), QStringLiteral("err"), result.error),
                        true);
    });

    const QFuture<TaskResult> future = QtConcurrent::run([vault]() {
        TaskResult result;
        result.ok = vault->sync(&result.error);
        return result;
    });
    m_syncTask = QFuture<void>(future);
    watcher->setFuture(future);
}

bool AppController::eventFilter(QObject *watched, QEvent *event) {
    switch (event->type()) {
    case QEvent::KeyPress:
    case QEvent::MouseButtonPress:
    case QEvent::MouseMove:
    case QEvent::Wheel:
    case QEvent::TouchBegin:
        m_lastActivity.restart();
        break;
    default:
        break;
    }
    return QObject::eventFilter(watched, event);
}

void AppController::lock() {
    if (m_vault.isNull())
        return; // nada desbloqueado — nada a travar (tela de bancos, por exemplo)
    if (m_busy || m_syncing)
        return; // uma operação ainda usa o banco; o timer tenta de novo no próximo ciclo

    closeVault();
    // Nothing is open any more, so no database is the PIN's subject until
    // one is picked again.
    refreshPinState();
    m_query.clear();
    refreshEntries();

    m_stage = QStringLiteral("databases");
    emit stageChanged();
    refreshDatabases();
}

QVariantList AppController::databases() const {
    QVariantList list;
    list.reserve(m_filteredDatabases.size());
    for (const DbRef &ref : m_filteredDatabases)
        list.append(describe(ref));
    return list;
}

void AppController::setDatabaseQuery(const QString &query) {
    if (m_databaseQuery == query)
        return;

    m_databaseQuery = query;

    QStringList paths;
    for (const DbRef &ref : std::as_const(m_databases))
        paths.append(ref.path);
    const QStringList kept = filterItems(paths, query);

    m_filteredDatabases.clear();
    for (const DbRef &ref : std::as_const(m_databases)) {
        if (kept.contains(ref.path))
            m_filteredDatabases.append(ref);
    }

    emit databasesChanged();
}

QVariantMap AppController::pendingDatabase() const {
    if (!m_hasPendingDatabase)
        return {};
    return describe(m_pendingDatabase);
}

QString AppController::vaultLabel() const {
    if (m_vault.isNull())
        return QString();
    return Vault::displayName({m_vault->path(), m_vault->kind()});
}

bool AppController::bitwardenBackend() const {
    return !m_vault.isNull() && m_vault->kind() == VaultKind::Bitwarden;
}

QString AppController::bitwardenAccount() const {
    if (bitwardenBackend())
        return BitwardenVault::emailOf(m_vault->path());
    if (m_hasPendingDatabase && m_pendingDatabase.kind == VaultKind::Bitwarden)
        return BitwardenVault::emailOf(m_pendingDatabase.path);
    return QString();
}

DbRef AppController::pinTarget() const {
    if (!m_vault.isNull())
        return {m_vault->path(), m_vault->kind()};
    if (m_hasPendingDatabase)
        return m_pendingDatabase;
    return DbRef();
}

// Looking a PIN up costs one quick secret-tool call, so it is refreshed
// whenever the database in play changes rather than kept in sync by hand.
void AppController::refreshPinState() {
    const DbRef target = pinTarget();
    const bool configured = !target.path.isEmpty() && Pin::hasPin(target.path);

    m_pinAvailable = m_vault.isNull() && m_hasPendingDatabase && configured;

    if (m_pinConfigured != configured) {
        m_pinConfigured = configured;
        emit pinConfiguredChanged();
    }
}

bool AppController::onePasswordBackend() const {
    return !m_vault.isNull() && m_vault->kind() == VaultKind::OnePassword;
}

bool AppController::passBackend() const {
    return !m_vault.isNull() && m_vault->kind() == VaultKind::Pass;
}

void AppController::refreshDatabases() {
    m_databases = Vault::findDatabases(m_config.searchPath);

    // Most-used first, so the database you actually open is the one under the
    // cursor when the window appears.
    QStringList paths;
    for (const DbRef &ref : std::as_const(m_databases))
        paths.append(ref.path);
    m_history.sortItems(paths);

    QVector<DbRef> sorted;
    sorted.reserve(m_databases.size());
    for (const QString &path : std::as_const(paths)) {
        for (const DbRef &ref : std::as_const(m_databases)) {
            if (ref.path == path) {
                sorted.append(ref);
                break;
            }
        }
    }
    m_databases = sorted;

    m_filteredDatabases = m_databases;
    m_databaseQuery.clear();
    emit databasesChanged();
}

void AppController::selectDatabase(int index) {
    if (index < 0 || index >= m_filteredDatabases.size())
        return;

    const DbRef ref = m_filteredDatabases.at(index);
    const auto waitForPassword = [this, ref]() {
        m_pendingDatabase = ref;
        m_hasPendingDatabase = true;
        refreshPinState();
        emit pendingDatabaseChanged();
    };

    if (ref.kind != VaultKind::Bitwarden && ref.kind != VaultKind::OnePassword) {
        setUnlockError(QString());
        waitForPassword();
        return;
    }

    if (m_busy)
        return;

    // A 1Password account can have been dropped behind omapass' back (`op
    // account forget` in a terminal), and then the master password alone
    // cannot open it: back to the login sheet. Reading op's own
    // configuration takes milliseconds.
    if (ref.kind == VaultKind::OnePassword) {
        setUnlockError(QString());
        if (OnePasswordVault::hasAccount(OnePasswordVault::accountOf(ref.path))) {
            waitForPassword();
            return;
        }

        // Dropped from a terminal while omapass had it listed.
        showMessage(I18n::t(QStringLiteral("onepassword.account_gone")), true);
        refreshDatabases();
        return;
    }

    // A Bitwarden account can have been logged out behind omapass' back (bw
    // logout in a terminal, an expired login), in which case the master
    // password alone cannot unlock it: back to the login sheet.
    setUnlockError(QString());
    if (BitwardenVault::status().loggedIn()) {
        waitForPassword();
        return;
    }

    m_loginEmail = BitwardenVault::emailOf(ref.path);
    setLoginStep(QStringLiteral("credentials"));
}

void AppController::cancelUnlock() {
    // A sign-in waiting on a two-step code would otherwise sit there.
    m_onePasswordLogin.cancel();
    setBusy(false);
    m_hasPendingDatabase = false;
    setUnlockError(QString());
    emit pendingDatabaseChanged();
}

void AppController::unlock(const QString &password) {
    if (m_busy || !m_hasPendingDatabase)
        return;

    setUnlockError(QString());

    // `op signin` can stop to ask for a two-step code, and that needs the
    // process kept alive while the interface asks for it — which the
    // background open, a single blocking call, cannot do.
    if (m_pendingDatabase.kind == VaultKind::OnePassword) {
        m_onePasswordAdding = false;
        setBusy(true);
        m_onePasswordLogin.startSignIn(OnePasswordVault::accountOf(m_pendingDatabase.path),
                                       Secret(password));
        return;
    }

    const Secret secret(password);
    const DbRef ref = m_pendingDatabase;
    runInBackground(
        [ref, secret]() {
            OpenResult result;
            result.vault = Vault::open(ref, secret, &result.error);
            return result;
        },
        [this, ref](const OpenResult &result) {
            if (result.vault)
                adoptVault(ref, result.vault);
            else
                setUnlockError(result.error);
        });
}

// The PIN never reaches bw: it decrypts the master password kept in the
// keyring, and the usual unlock goes ahead with that.
void AppController::unlockWithPin(const QString &pin) {
    if (m_busy || !m_hasPendingDatabase || !m_pinAvailable)
        return;

    setUnlockError(QString());

    const DbRef ref = m_pendingDatabase;
    const QString target = ref.path;
    struct PinUnlock {
        Pin::Result result = Pin::Result::Missing;
        Secret password;
    };

    runInBackground(
        [target, pin]() {
            PinUnlock unlock;
            unlock.result = Pin::recover(target, pin, &unlock.password);
            return unlock;
        },
        [this, ref, target](const PinUnlock &unlock) {
            switch (unlock.result) {
            case Pin::Result::Ok:
                break;
            case Pin::Result::WrongPin: {
                const int left = Pin::registerFailure(target);
                refreshPinState();
                emit pendingDatabaseChanged();
                setUnlockError(left > 0
                    ? I18n::t(QStringLiteral("pin.wrong"), QStringLiteral("left"),
                              QString::number(left))
                    : I18n::t(QStringLiteral("pin.blocked")));
                return;
            }
            case Pin::Result::Missing:
            case Pin::Result::Unavailable:
                Pin::clear(target);
                refreshPinState();
                emit pendingDatabaseChanged();
                setUnlockError(I18n::t(QStringLiteral("pin.missing")));
                return;
            }

            Pin::resetAttempts(target);
            const Secret password = unlock.password;
            runInBackground(
                [ref, password]() {
                    OpenResult result;
                    result.vault = Vault::open(ref, password, &result.error);
                    return result;
                },
                [this, ref, target](const OpenResult &result) {
                    if (result.vault) {
                        adoptVault(ref, result.vault);
                        return;
                    }
                    // The stored password no longer opens the database (a
                    // changed master password, say): the PIN goes with it.
                    Pin::clear(target);
                    refreshPinState();
                    emit pendingDatabaseChanged();
                    setUnlockError(I18n::t(QStringLiteral("pin.stale")));
                });
        });
}

void AppController::openVault(const DbRef &ref, const Secret &secret) {
    QString error;
    Vault *vault = Vault::open(ref, secret, &error);
    if (!vault) {
        setUnlockError(error);
        return;
    }

    adoptVault(ref, vault);
}

void AppController::adoptVault(const DbRef &ref, Vault *vault) {
    m_vault.reset(vault);
    refreshPinState();
    m_history.recordUse(ref.path);

    m_hasPendingDatabase = false;
    emit pendingDatabaseChanged();

    m_query.clear();
    refreshEntries();

    m_stage = QStringLiteral("entries");
    emit stageChanged();

    // Opening read bw's local copy; what changed on the server since the
    // last sync arrives a moment later.
    if (vault->kind() == VaultKind::Bitwarden)
        startBackgroundSync();
}

void AppController::refreshEntries() {
    m_allEntries.clear();
    m_groups.clear();
    if (!m_vault.isNull())
        m_vault->list(&m_allEntries, &m_groups);

    m_history.sortItems(m_allEntries);
    applyEntryFilter();
}

void AppController::applyEntryFilter() {
    m_filteredEntries = filterItems(m_allEntries, m_query);
    emit entriesChanged();
}

void AppController::setQuery(const QString &query) {
    if (m_query == query)
        return;

    m_query = query;
    applyEntryFilter();
}

bool AppController::isEmptyGroup(const QString &entry) const {
    return entry.endsWith(Vault::emptyGroupSuffix());
}

QString AppController::groupNameOf(const QString &entry) const {
    const QString suffix = Vault::emptyGroupSuffix();
    return entry.endsWith(suffix) ? entry.chopped(suffix.size()) : entry;
}

void AppController::copyPassword(const QString &entry) {
    if (m_vault.isNull())
        return;

    if (isEmptyGroup(entry)) {
        showMessage(I18n::t(QStringLiteral("app.empty_group")), true);
        return;
    }

    m_history.recordUse(entry);

    Secret password;
    QString error;
    if (!m_vault->fetchPassword(entry, &password, &error)) {
        showMessage(I18n::t(QStringLiteral("app.copy_password_error")), true);
        return;
    }

    if (!Clipboard::copy(password.toString())) {
        showMessage(I18n::t(QStringLiteral("app.copy_password_error")), true);
        return;
    }

    showClipboardMessage(I18n::t(QStringLiteral("app.copied_entry"), QStringLiteral("entry"), entry));
    Clipboard::scheduleClear(password);
}

void AppController::copyText(const QString &text) {
    if (text.isEmpty())
        return;

    if (Clipboard::copy(text))
        showMessage(I18n::t(QStringLiteral("app.copied_to_clipboard")), false);
    else
        showMessage(I18n::t(QStringLiteral("app.copy_error")), true);
}

QVariantMap AppController::entryDetails(const QString &entry) {
    if (m_vault.isNull() || isEmptyGroup(entry)) {
        showMessage(I18n::t(QStringLiteral("app.empty_group")), true);
        return {};
    }

    const QString fallback = entry.section(QLatin1Char('/'), -1);

    EntryData data;
    QString error;
    m_vault->fetchEntry(entry, &data, &error);

    return {{QStringLiteral("title"), m_vault->titleFor(entry, fallback)},
            {QStringLiteral("url"), data.url},
            {QStringLiteral("notes"), data.notes}};
}

// The password comes back in the clear because an editable field has to hold
// it; it is the one place omapass cannot keep a secret inside `Secret` alone.
QVariantMap AppController::entryFields(const QString &entry) {
    QVariantMap fields;
    fields.insert(QStringLiteral("originalPath"), entry);

    const int slash = entry.lastIndexOf(QLatin1Char('/'));
    fields.insert(QStringLiteral("group"), slash < 0 ? QString() : entry.left(slash));
    fields.insert(QStringLiteral("title"), slash < 0 ? entry : entry.mid(slash + 1));

    if (m_vault.isNull())
        return fields;

    EntryData data;
    QString error;
    if (!m_vault->fetchEntry(entry, &data, &error)) {
        showMessage(I18n::t(QStringLiteral("app.read_entry_error"), QStringLiteral("err"), error), true);
        return fields;
    }

    fields.insert(QStringLiteral("username"), data.username);
    fields.insert(QStringLiteral("password"), data.password.toString());
    fields.insert(QStringLiteral("url"), data.url);
    fields.insert(QStringLiteral("notes"), data.notes);
    fields.insert(QStringLiteral("extra"), data.extra);
    return fields;
}

void AppController::saveEntry(const QVariantMap &fields) {
    if (!vaultReadyForChanges())
        return;

    QString group = fields.value(QStringLiteral("group")).toString().trimmed();
    while (group.endsWith(QLatin1Char('/')))
        group.chop(1);

    const QString title = fields.value(QStringLiteral("title")).toString().trimmed();
    if (title.isEmpty()) {
        showMessage(I18n::t(QStringLiteral("app.title_empty")), true);
        return;
    }

    const QString path = group.isEmpty() ? title : group + QLatin1Char('/') + title;
    const bool isEdit = fields.value(QStringLiteral("isEdit")).toBool();

    EntryData data;
    data.username = fields.value(QStringLiteral("username")).toString().trimmed();
    data.password = Secret(fields.value(QStringLiteral("password")).toString());
    data.url = fields.value(QStringLiteral("url")).toString().trimmed();
    data.notes = fields.value(QStringLiteral("notes")).toString();
    data.extra = fields.value(QStringLiteral("extra")).toStringList();

    // Locking waits while busy, so the vault outlives the task.
    const Vault *vault = m_vault.data();
    const QString originalPath = fields.value(QStringLiteral("originalPath")).toString();
    runInBackground(
        [vault, isEdit, originalPath, path, group, data]() {
            TaskResult result;
            result.ok = isEdit ? vault->editEntry(originalPath, path, group, data, &result.error)
                               : vault->addEntry(path, group, data, &result.error);
            return result;
        },
        [this, isEdit, path](const TaskResult &result) {
            if (result.ok) {
                if (!isEdit)
                    m_history.recordUse(path);
                showMessage(I18n::t(isEdit ? QStringLiteral("app.entry_edited")
                                           : QStringLiteral("app.entry_added")),
                            false);
            } else {
                showMessage(I18n::t(isEdit ? QStringLiteral("app.edit_error")
                                           : QStringLiteral("app.add_error")),
                            true);
            }
            refreshEntries();
        });
}

void AppController::deleteEntry(const QString &entry) {
    if (!vaultReadyForChanges())
        return;

    const bool emptyGroup = isEmptyGroup(entry);
    const QString group = groupNameOf(entry);
    const Vault *vault = m_vault.data();
    runInBackground(
        [vault, emptyGroup, group, entry]() {
            TaskResult result;
            result.ok = emptyGroup ? vault->removeGroup(group, &result.error)
                                   : vault->removeEntry(entry, &result.error);
            return result;
        },
        [this, emptyGroup](const TaskResult &result) {
            if (result.ok) {
                showMessage(I18n::t(emptyGroup ? QStringLiteral("app.group_deleted")
                                               : QStringLiteral("app.entry_deleted")),
                            false);
                refreshEntries();
            } else {
                showMessage(I18n::t(QStringLiteral("app.delete_error"), QStringLiteral("err"),
                                    result.error),
                            true);
            }
        });
}

void AppController::renameGroup(const QString &entry, const QString &newName) {
    if (!vaultReadyForChanges())
        return;

    const QString trimmed = newName.trimmed();
    if (trimmed.isEmpty()) {
        showMessage(I18n::t(QStringLiteral("app.name_empty")), true);
        return;
    }

    const Vault *vault = m_vault.data();
    const QString group = groupNameOf(entry);
    runInBackground(
        [vault, group, trimmed]() {
            TaskResult result;
            result.ok = vault->renameGroup(group, trimmed, &result.error);
            return result;
        },
        [this](const TaskResult &result) {
            if (result.ok)
                showMessage(I18n::t(QStringLiteral("app.group_renamed")), false);
            else
                showMessage(I18n::t(QStringLiteral("app.rename_group_error"), QStringLiteral("err"),
                                    result.error),
                            true);
            refreshEntries();
        });
}

QStringList AppController::matchingGroups(const QString &prefix) const {
    return filterItems(m_groups, prefix);
}

void AppController::createKeepassDatabase(const QString &name, const QString &password) {
    if (m_busy || name.trimmed().isEmpty())
        return;

    setBusy(true);
    const Secret secret(password);
    const QString trimmedName = name.trimmed();
    QTimer::singleShot(0, this, [this, trimmedName, secret]() {
        QString path;
        QString error;
        if (!Vault::createKeepassDatabase(trimmedName, secret, &path, &error)) {
            setUnlockError(error);
            setBusy(false);
            return;
        }

        refreshDatabases();
        emit databaseCreated();
        openVault({path, VaultKind::Keepass}, secret);
        setBusy(false);
    });
}

QVariantList AppController::gpgKeys() const {
    QVariantList keys;
    const auto secretKeys = PassStore::listSecretKeys();
    for (const auto &key : secretKeys) {
        keys.append(QVariantMap{{QStringLiteral("id"), key.first},
                                {QStringLiteral("identity"), key.second}});
    }
    return keys;
}

QString AppController::defaultPassStoreDirectory() const {
    return QDir::homePath() + QStringLiteral("/.password-store");
}

// Completions for the directory field: the subdirectories matching the
// segment being typed (typing "/home/user/.pas" suggests folders under
// "/home/user/" starting with "pas"), hidden ones excluded.
QStringList AppController::directorySuggestions(const QString &path) const {
    const int slash = path.lastIndexOf(QLatin1Char('/'));
    const QString parent = slash < 0 ? QString() : path.left(slash + 1);
    const QString partial = slash < 0 ? path : path.mid(slash + 1);

    const QDir dir(parent.isEmpty() ? QStringLiteral(".") : parent);
    QStringList suggestions;
    const auto names = dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    for (const QString &name : names) {
        if (name.startsWith(QLatin1Char('.')))
            continue;
        if (name.startsWith(partial, Qt::CaseInsensitive))
            suggestions.append(parent + name);
    }
    return suggestions;
}

void AppController::createPassStore(const QString &directory, const QString &keyId) {
    if (m_busy)
        return;

    const QString dir = directory.trimmed();
    if (dir.isEmpty()) {
        setUnlockError(I18n::t(QStringLiteral("db_app.dir_empty")));
        return;
    }
    if (keyId.isEmpty()) {
        setUnlockError(I18n::t(QStringLiteral("db_app.no_gpg_key_selected")));
        return;
    }

    setBusy(true);
    QTimer::singleShot(0, this, [this, dir, keyId]() {
        QString error;
        if (!PassStore::initStore(dir, keyId, &error)) {
            setUnlockError(error);
            setBusy(false);
            return;
        }

        refreshDatabases();
        emit databaseCreated();

        // A brand-new store still needs its GPG passphrase, so it goes
        // through the same unlock prompt as any other database.
        m_pendingDatabase = {dir, VaultKind::Pass};
        m_hasPendingDatabase = true;
        setUnlockError(QString());
        emit pendingDatabaseChanged();
        setBusy(false);
    });
}

bool AppController::bitwardenAvailable() const {
    return BitwardenVault::isAvailable();
}

bool AppController::onePasswordAvailable() const {
    return OnePasswordVault::isAvailable();
}

void AppController::setLoginStep(const QString &step) {
    if (step.isEmpty())
        m_loginPassword.clear();
    m_loginStep = step;
    emit loginChanged();
}

void AppController::addBitwardenAccount() {
    if (!requireIdle())
        return;

    setUnlockError(QString());
    const BwStatus status = BitwardenVault::status();

    // `bw` holds one account at a time, so adding another is only possible
    // after leaving the current one.
    if (status.loggedIn() && !BitwardenVault::rememberedAccount().isEmpty()) {
        showMessage(I18n::t(QStringLiteral("bitwarden.one_account")), true);
        return;
    }

    // Already logged in with bw (from a terminal, say): the account only
    // needs adding to the list and unlocking.
    if (status.loggedIn() && !status.userEmail.isEmpty()) {
        BitwardenVault::rememberAccount(status.userEmail);
        refreshDatabases();
        emit databaseCreated();

        m_pendingDatabase = {BitwardenVault::refPath(status.userEmail), VaultKind::Bitwarden};
        m_hasPendingDatabase = true;
        refreshPinState();
        emit pendingDatabaseChanged();
        return;
    }

    m_loginEmail = BitwardenVault::rememberedAccount();
    setLoginStep(QStringLiteral("credentials"));
}

void AppController::bitwardenLogin(const QString &email, const QString &password) {
    if (m_busy)
        return;

    const QString trimmed = email.trimmed();
    if (trimmed.isEmpty()) {
        setUnlockError(I18n::t(QStringLiteral("bitwarden.invalid_email")));
        return;
    }

    m_loginEmail = trimmed;
    m_loginPassword = Secret(password);
    emit loginChanged();

    setBusy(true);
    setUnlockError(QString());
    m_bitwardenLogin.start(m_loginEmail, m_loginPassword);
}

void AppController::chooseBitwardenMethod(int method) {
    if (m_busy || m_loginPassword.isEmpty())
        return;

    setBusy(true);
    setUnlockError(QString());
    m_bitwardenLogin.start(m_loginEmail, m_loginPassword, method);
}

void AppController::sendBitwardenCode(const QString &code) {
    if (m_busy || code.trimmed().isEmpty())
        return;

    setBusy(true);
    setUnlockError(QString());
    m_bitwardenLogin.sendCode(code);
}

void AppController::cancelBitwardenLogin() {
    m_bitwardenLogin.cancel();
    setBusy(false);
    setUnlockError(QString());
    setLoginStep(QString());
}

bool AppController::isBitwardenDatabase(int index) const {
    return index >= 0 && index < m_filteredDatabases.size()
        && m_filteredDatabases.at(index).kind == VaultKind::Bitwarden;
}

void AppController::logoutBitwarden() {
    if (!requireIdle())
        return;

    const QString email = BitwardenVault::rememberedAccount();
    runInBackground(
        [email]() {
            BitwardenVault::logout();
            // An account nobody is signed into has no business leaving its
            // master password behind in the keyring.
            Pin::clear(BitwardenVault::refPath(email));
            return TaskResult{true, QString()};
        },
        [this](const TaskResult &) {
            BitwardenVault::forgetAccount();
            refreshPinState();
            refreshDatabases();
            showMessage(I18n::t(QStringLiteral("bitwarden.logged_out")), false);
        });
}

void AppController::addOnePasswordAccount() {
    if (!requireIdle())
        return;

    // Always the login sheet: every account `op` already has is in the list
    // on its own, so getting here means adding one more.
    setUnlockError(QString());
    m_onePasswordAdding = true;
    m_loginEmail.clear();
    m_loginAddress.clear();
    setLoginStep(QStringLiteral("opCredentials"));
}

void AppController::onePasswordLogin(const QString &address, const QString &email,
                                     const QString &secretKey, const QString &password,
                                     const QString &shorthand) {
    if (m_busy)
        return;

    const QString trimmedAddress = address.trimmed();
    const QString trimmedEmail = email.trimmed();
    if (trimmedAddress.isEmpty() || trimmedEmail.isEmpty()) {
        setUnlockError(I18n::t(QStringLiteral("onepassword.login_failed")));
        return;
    }

    // Without a nickname of their own, the account is filed under the part
    // of the e-mail before the @ — `op` would otherwise name it after the
    // address ("my"), which tells two accounts apart by nothing.
    QString nickname = shorthand.trimmed();
    if (nickname.isEmpty())
        nickname = opShorthandFor(trimmedEmail, trimmedAddress);

    QStringList taken;
    const QVector<OpAccount> known = OnePasswordVault::accounts();
    for (const OpAccount &account : known)
        taken.append(account.key());
    nickname = opUniqueShorthand(nickname, taken);

    m_loginAddress = trimmedAddress;
    m_loginEmail = trimmedEmail;
    emit loginChanged();

    m_onePasswordAdding = true;
    setBusy(true);
    setUnlockError(QString());
    m_onePasswordLogin.start(trimmedAddress, trimmedEmail, Secret(secretKey), Secret(password),
                             nickname);
}

void AppController::sendOnePasswordCode(const QString &code) {
    if (m_busy || code.trimmed().isEmpty())
        return;

    setBusy(true);
    setUnlockError(QString());
    m_onePasswordLogin.sendCode(code);
}

void AppController::cancelOnePasswordLogin() {
    m_onePasswordLogin.cancel();
    setBusy(false);
    setUnlockError(QString());
    setLoginStep(QString());
}

bool AppController::isOnePasswordDatabase(int index) const {
    return index >= 0 && index < m_filteredDatabases.size()
        && m_filteredDatabases.at(index).kind == VaultKind::OnePassword;
}

void AppController::logoutOnePassword(int index) {
    if (!requireIdle() || !isOnePasswordDatabase(index))
        return;

    const DbRef ref = m_filteredDatabases.at(index);
    const QString account = OnePasswordVault::accountOf(ref.path);
    const QString path = ref.path;
    runInBackground(
        [account, path]() {
            TaskResult result;
            result.ok = OnePasswordVault::logout(account, &result.error);
            if (result.ok)
                Pin::clear(path);
            return result;
        },
        [this](const TaskResult &result) {
            refreshPinState();
            refreshDatabases();
            showMessage(result.ok ? I18n::t(QStringLiteral("onepassword.logged_out")) : result.error,
                        !result.ok);
        });
}

void AppController::enablePin(const QString &password, const QString &pin, bool allowText) {
    const DbRef target = pinTarget();
    if (m_busy || target.path.isEmpty())
        return;

    const QString invalid = Pin::validate(pin, pin, allowText);
    if (!invalid.isEmpty()) {
        showMessage(invalid, true);
        return;
    }

    const Secret secret(password);
    struct PinSetup {
        bool ok = false;
        QString error;
    };

    runInBackground(
        [target, pin, secret]() {
            PinSetup setup;
            // Checked before being stored, so a typo does not end up behind
            // the PIN — without opening the database, which for an account
            // backend would cost (and invalidate) a session.
            if (!Vault::verifySecret(target, secret, &setup.error))
                return setup;
            setup.ok = Pin::store(target.path, pin, secret, &setup.error);
            return setup;
        },
        [this](const PinSetup &setup) {
            refreshPinState();
            showMessage(setup.ok ? I18n::t(QStringLiteral("pin.enabled")) : setup.error, !setup.ok);
        });
}

void AppController::disablePin() {
    const DbRef target = pinTarget();
    if (target.path.isEmpty())
        return;

    Pin::clear(target.path);
    refreshPinState();
    showMessage(I18n::t(QStringLiteral("pin.disabled")), false);
}

QString AppController::validatePin(const QString &pin, const QString &confirm,
                                   bool allowText) const {
    return Pin::validate(pin, confirm, allowText);
}

QString AppController::pinWeakWarning(const QString &pin) const {
    return Pin::weakWarning(pin);
}

void AppController::closeVault() {
    if (m_vault.isNull())
        return;
    m_vault->close();
    m_vault.reset();
}

QString AppController::message() const {
    if (m_messageText.isEmpty())
        return QString();

    if (m_clipboardCountdown < 0)
        return m_messageText;

    return I18n::t(QStringLiteral("ui.clipboard_clear_countdown"),
                   {{QStringLiteral("msg"), m_messageText},
                    {QStringLiteral("secs"), m_clipboardCountdown}});
}

void AppController::showMessage(const QString &text, bool isError) {
    m_messageText = text;
    m_messageIsError = isError;
    m_clipboardCountdown = -1;
    emit messageChanged();

    m_messageTimer.stop();
    QTimer::singleShot(3000, this, [this, text]() {
        // Only clears the message it was scheduled for; a newer one owns the
        // status line from the moment it is set.
        if (m_messageText == text && m_clipboardCountdown < 0)
            clearMessage();
    });
}

void AppController::showClipboardMessage(const QString &text) {
    m_messageText = text;
    m_messageIsError = false;
    m_clipboardCountdown = Clipboard::clearSecs;
    emit messageChanged();
    m_messageTimer.start();
}

void AppController::clearMessage() {
    m_messageTimer.stop();
    if (m_messageText.isEmpty())
        return;

    m_messageText.clear();
    m_clipboardCountdown = -1;
    emit messageChanged();
}

void AppController::setBusy(bool busy) {
    if (m_busy == busy)
        return;

    m_busy = busy;
    emit busyChanged();
}

void AppController::setUnlockError(const QString &error) {
    if (m_unlockError == error)
        return;

    m_unlockError = error;
    emit unlockErrorChanged();
}

QVariantMap AppController::settings() const {
    return {{QStringLiteral("path"), m_config.searchPath},
            {QStringLiteral("recency"), m_config.recencyEnabled},
            {QStringLiteral("lockEnabled"), m_config.lockMinutes.has_value()},
            {QStringLiteral("lockMinutes"), m_config.lockMinutes.value_or(10)},
            {QStringLiteral("wordlist"), m_config.wordlist},
            {QStringLiteral("wordlistInUse"), Generator::wordlistPath()},
            {QStringLiteral("configPath"), Config::configDir() + QStringLiteral("/config.toml")}};
}

// Saved to config.toml and applied right away — the sheet only offers the
// settings that can take effect without a restart.
void AppController::saveSettings(const QVariantMap &values) {
    QString path = values.value(QStringLiteral("path")).toString().trimmed();
    if (path.isEmpty())
        path = m_config.searchPath;
    if (path.startsWith(QStringLiteral("~/")))
        path = QDir::homePath() + path.mid(1);

    const bool recency = values.value(QStringLiteral("recency")).toBool();
    const bool lockEnabled = values.value(QStringLiteral("lockEnabled")).toBool();
    const int lockMinutes = qMax(1, values.value(QStringLiteral("lockMinutes")).toInt());
    QString wordlist = values.value(QStringLiteral("wordlist")).toString().trimmed();
    if (wordlist.isEmpty())
        wordlist = QStringLiteral("auto");

    QMap<QString, QString> toml;
    toml.insert(QStringLiteral("general.path"), Config::tomlString(path));
    toml.insert(QStringLiteral("general.recency"), recency ? QStringLiteral("true") : QStringLiteral("false"));
    toml.insert(QStringLiteral("general.lock_minutes"),
                lockEnabled ? QString::number(lockMinutes) : QStringLiteral("false"));
    toml.insert(QStringLiteral("generator.wordlist"), Config::tomlString(wordlist));

    if (!Config::writeValues(toml)) {
        showMessage(I18n::t(QStringLiteral("settings.write_error")), true);
        return;
    }

    const bool pathChanged = path != m_config.searchPath;
    const bool recencyChanged = recency != m_config.recencyEnabled;

    m_config.searchPath = path;
    m_config.recencyEnabled = recency;
    m_config.lockMinutes = lockEnabled ? std::optional<int>(lockMinutes) : std::nullopt;
    m_config.wordlist = wordlist;

    Generator::configure(m_config.wordlist, m_config.language);
    applyLockSettings();
    if (recencyChanged)
        m_history = History(recency);
    if (pathChanged || recencyChanged)
        refreshDatabases();

    showMessage(I18n::t(QStringLiteral("settings.saved")), false);
}

QString AppController::importWordlist(const QString &fileUrl) {
    const QString source = QUrl(fileUrl).isLocalFile() ? QUrl(fileUrl).toLocalFile() : fileUrl;

    QFile file(source);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        showMessage(I18n::t(QStringLiteral("settings.wordlist_unreadable")), true);
        return QString();
    }

    // keepassxc-cli refuses anything under 1296 words (6^4); saying so here
    // beats a passphrase mode that silently stops working.
    int words = 0;
    QTextStream in(&file);
    while (!in.atEnd()) {
        if (!in.readLine().trimmed().isEmpty())
            ++words;
    }
    if (words < Generator::minimumWordlistSize) {
        showMessage(I18n::t(QStringLiteral("settings.wordlist_too_small"),
                            {{QStringLiteral("words"), words},
                             {QStringLiteral("min"), Generator::minimumWordlistSize}}),
                    true);
        return QString();
    }

    const QString directory = Config::configDir() + QStringLiteral("/wordlists");
    if (!QDir().mkpath(directory)) {
        showMessage(I18n::t(QStringLiteral("settings.wordlist_copy_error")), true);
        return QString();
    }

    const QString target = directory + QLatin1Char('/') + QFileInfo(source).fileName();
    if (QFileInfo(source).absoluteFilePath() != QFileInfo(target).absoluteFilePath()) {
        QFile::remove(target);
        if (!QFile::copy(source, target)) {
            showMessage(I18n::t(QStringLiteral("settings.wordlist_copy_error")), true);
            return QString();
        }
    }

    showMessage(I18n::t(QStringLiteral("settings.wordlist_imported"), QStringLiteral("words"),
                        QString::number(words)),
                false);
    return target;
}

namespace {

const auto generatorSetting = QStringLiteral("generator/");

GeneratorOptions optionsFromMap(const QVariantMap &map) {
    const GeneratorOptions defaults;
    GeneratorOptions options;
    options.passphrase = map.value(QStringLiteral("passphrase"), defaults.passphrase).toBool();
    options.length = map.value(QStringLiteral("length"), defaults.length).toInt();
    options.lower = map.value(QStringLiteral("lower"), defaults.lower).toBool();
    options.upper = map.value(QStringLiteral("upper"), defaults.upper).toBool();
    options.numbers = map.value(QStringLiteral("numbers"), defaults.numbers).toBool();
    options.special = map.value(QStringLiteral("special"), defaults.special).toBool();
    options.excludeSimilar = map.value(QStringLiteral("excludeSimilar"), defaults.excludeSimilar).toBool();
    options.exclude = map.value(QStringLiteral("exclude")).toString();
    options.custom = map.value(QStringLiteral("custom")).toString();
    options.words = map.value(QStringLiteral("words"), defaults.words).toInt();
    options.separator = map.value(QStringLiteral("separator"), defaults.separator).toString();
    return options;
}

QVariantMap optionsToMap(const GeneratorOptions &options) {
    return {{QStringLiteral("passphrase"), options.passphrase},
            {QStringLiteral("length"), options.length},
            {QStringLiteral("lower"), options.lower},
            {QStringLiteral("upper"), options.upper},
            {QStringLiteral("numbers"), options.numbers},
            {QStringLiteral("special"), options.special},
            {QStringLiteral("excludeSimilar"), options.excludeSimilar},
            {QStringLiteral("exclude"), options.exclude},
            {QStringLiteral("custom"), options.custom},
            {QStringLiteral("words"), options.words},
            {QStringLiteral("separator"), options.separator}};
}

}

// The sheet's last settings, so generating a second password does not mean
// setting everything up again.
QVariantMap AppController::generatorOptions() const {
    QSettings settings;
    QVariantMap map = optionsToMap(GeneratorOptions());
    for (auto it = map.begin(); it != map.end(); ++it)
        *it = settings.value(generatorSetting + it.key(), *it);

    QVariantMap result = optionsToMap(Generator::normalize(optionsFromMap(map)));
    result.insert(QStringLiteral("passphraseAvailable"), !Generator::wordlistPath().isEmpty());
    return result;
}

// Generating takes about ten milliseconds, so it happens right here rather
// than on a worker thread: the sheet regenerates on every change.
QVariantMap AppController::generate(const QVariantMap &options) {
    // Only with a vault open: generating is one step of putting a password
    // somewhere, not a standalone tool.
    if (m_vault.isNull())
        return {};

    const GeneratorOptions wanted = Generator::normalize(optionsFromMap(options));

    QSettings settings;
    const QVariantMap map = optionsToMap(wanted);
    for (auto it = map.cbegin(); it != map.cend(); ++it)
        settings.setValue(generatorSetting + it.key(), it.value());

    Secret password;
    QString error;
    if (!Generator::generate(wanted, &password, &error)) {
        showMessage(error, true);
        return {};
    }

    QVariantMap result = map;
    result.insert(QStringLiteral("password"), password.toString());
    return result;
}

// Copies with the same treatment an entry's password gets: marked sensitive
// for the clipboard manager and wiped after the countdown.
void AppController::copySecret(const QString &password) {
    if (password.isEmpty())
        return;

    if (!Clipboard::copy(password)) {
        showMessage(I18n::t(QStringLiteral("app.copy_password_error")), true);
        return;
    }

    showClipboardMessage(I18n::t(QStringLiteral("generator.copied")));
    Clipboard::scheduleClear(Secret(password));
}

QVariantMap AppController::windowGeometry() const {
    QSettings settings;
    const QRect geometry = settings.value(windowGeometrySetting).toRect();

    // Positions are legitimately negative on monitors left of or above the
    // primary one, so validity travels separately instead of being encoded
    // as -1.
    return {{QStringLiteral("valid"), geometry.isValid()},
            {QStringLiteral("x"), geometry.x()},
            {QStringLiteral("y"), geometry.y()},
            {QStringLiteral("width"), geometry.width()},
            {QStringLiteral("height"), geometry.height()},
            {QStringLiteral("maximized"),
             settings.value(QStringLiteral("window/maximized"), false).toBool()}};
}

void AppController::saveWindowGeometry(int x, int y, int width, int height, bool maximized) {
    QSettings settings;
    settings.setValue(windowGeometrySetting, QRect(x, y, width, height));
    settings.setValue(QStringLiteral("window/maximized"), maximized);
}
