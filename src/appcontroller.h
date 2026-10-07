#pragma once

#include <QElapsedTimer>
#include <QFuture>
#include <QObject>
#include <QScopedPointer>
#include <QStringList>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>

#include "bitwardenlogin.h"
#include "config.h"
#include "generator.h"
#include "history.h"
#include "onepasswordlogin.h"
#include "vault.h"

class QEvent;

// Everything the interface talks to: the database list, the open vault, the
// filtered entries and the transient status line. The QML side holds no
// password-manager logic of its own — it renders these properties and calls
// these actions, the same split the TUI had between app.rs and ui.rs.
class AppController : public QObject {
    Q_OBJECT

    Q_PROPERTY(QString stage READ stage NOTIFY stageChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    // A Bitwarden vault pulling from the server after it opened: reading
    // stays available, changes wait for it to finish.
    Q_PROPERTY(bool syncing READ syncing NOTIFY syncingChanged)

    Q_PROPERTY(QVariantList databases READ databases NOTIFY databasesChanged)
    Q_PROPERTY(bool anyDatabaseFound READ anyDatabaseFound NOTIFY databasesChanged)
    // The search for databases is still running. The window is up and usable
    // meanwhile, so "nothing here" and "nothing found yet" have to be told
    // apart: only the first one offers to create a database.
    Q_PROPERTY(bool scanning READ scanning NOTIFY scanningChanged)
    // An account picked from the list whose backend is being asked whether
    // it is still logged in. Takes long enough to be worth saying so, and
    // the password prompt would be the wrong thing to show in the meantime.
    Q_PROPERTY(bool checkingAccount READ checkingAccount NOTIFY checkingAccountChanged)
    // Name of the account being checked, for the sheet that says so.
    Q_PROPERTY(QString checkingAccountName READ checkingAccountName NOTIFY checkingAccountChanged)
    Q_PROPERTY(QString databaseQuery READ databaseQuery WRITE setDatabaseQuery NOTIFY databasesChanged)
    Q_PROPERTY(QVariantMap pendingDatabase READ pendingDatabase NOTIFY pendingDatabaseChanged)
    Q_PROPERTY(QString unlockError READ unlockError NOTIFY unlockErrorChanged)
    // The database waiting to be unlocked has a PIN stored for it.
    Q_PROPERTY(bool pinAvailable READ pinAvailable NOTIFY pendingDatabaseChanged)

    Q_PROPERTY(bool onePasswordAvailable READ onePasswordAvailable CONSTANT)
    // Where a login sheet is: "" (closed); "credentials", "method", "code"
    // or "deviceCode" for Bitwarden; "opCredentials" or "opCode" for
    // 1Password.
    Q_PROPERTY(QString loginStep READ loginStep NOTIFY loginChanged)
    Q_PROPERTY(QString loginEmail READ loginEmail NOTIFY loginChanged)
    // The server the Bitwarden login sheet starts with: the last one logged
    // into, "bitwarden.com" by default.
    Q_PROPERTY(QString loginServer READ loginServer NOTIFY loginChanged)
    // The two-step methods to choose from on the "method" step, as
    // Bitwarden's TwoFactorProviderType numbers.
    Q_PROPERTY(QVariantList loginMethods READ loginMethods NOTIFY loginChanged)

    Q_PROPERTY(QString vaultLabel READ vaultLabel NOTIFY stageChanged)
    Q_PROPERTY(bool passBackend READ passBackend NOTIFY stageChanged)
    Q_PROPERTY(bool bitwardenBackend READ bitwardenBackend NOTIFY stageChanged)
    Q_PROPERTY(bool onePasswordBackend READ onePasswordBackend NOTIFY stageChanged)
    Q_PROPERTY(bool pinConfigured READ pinConfigured NOTIFY pinConfiguredChanged)

    Q_PROPERTY(QStringList entries READ entries NOTIFY entriesChanged)
    Q_PROPERTY(QString query READ query WRITE setQuery NOTIFY entriesChanged)
    Q_PROPERTY(QStringList groups READ groups NOTIFY entriesChanged)

    Q_PROPERTY(QString message READ message NOTIFY messageChanged)
    Q_PROPERTY(bool messageIsError READ messageIsError NOTIFY messageChanged)
    Q_PROPERTY(bool hasMessage READ hasMessage NOTIFY messageChanged)

public:
    explicit AppController(const AppConfig &config, QObject *parent = nullptr);
    ~AppController() override;

    // Application-wide activity watch for the auto-lock timer below: every
    // key/mouse event, anywhere in the app, counts as "still in use".
    bool eventFilter(QObject *watched, QEvent *event) override;

    QString stage() const { return m_stage; }
    bool busy() const { return m_busy; }
    bool syncing() const { return m_syncing; }

    QVariantList databases() const;
    bool anyDatabaseFound() const { return !m_databases.isEmpty(); }
    bool scanning() const { return m_scanning; }
    bool checkingAccount() const { return m_checkingAccount; }
    QString checkingAccountName() const { return m_checkingAccountName; }
    QString databaseQuery() const { return m_databaseQuery; }
    void setDatabaseQuery(const QString &query);
    QVariantMap pendingDatabase() const;
    QString unlockError() const { return m_unlockError; }

    bool onePasswordAvailable() const;
    QString loginStep() const { return m_loginStep; }
    QString loginEmail() const { return m_loginEmail; }
    QString loginServer() const { return m_loginServer; }
    QVariantList loginMethods() const;

    QString vaultLabel() const;
    bool passBackend() const;
    bool bitwardenBackend() const;
    bool onePasswordBackend() const;
    bool pinAvailable() const { return m_pinAvailable; }
    bool pinConfigured() const { return m_pinConfigured; }

    QStringList entries() const { return m_filteredEntries; }
    QString query() const { return m_query; }
    void setQuery(const QString &query);
    QStringList groups() const { return m_groups; }

    QString message() const;
    bool messageIsError() const { return m_messageIsError; }
    bool hasMessage() const { return !m_messageText.isEmpty(); }

    // Database selection
    Q_INVOKABLE void selectDatabase(int index);
    Q_INVOKABLE void unlock(const QString &password);
    Q_INVOKABLE void unlockWithPin(const QString &pin);
    Q_INVOKABLE void cancelUnlock();
    // Locks the open vault and goes back to the database list — the same
    // thing the inactivity timer does, on demand.
    Q_INVOKABLE void lock();

    // Database creation
    Q_INVOKABLE void createKeepassDatabase(const QString &name, const QString &password);
    Q_INVOKABLE QVariantList gpgKeys() const;
    Q_INVOKABLE QStringList directorySuggestions(const QString &path) const;
    Q_INVOKABLE QString defaultPassStoreDirectory() const;
    Q_INVOKABLE void createPassStore(const QString &directory, const QString &keyId);

    // Bitwarden account
    Q_INVOKABLE void addBitwardenAccount();
    Q_INVOKABLE void bitwardenLogin(const QString &server, const QString &email,
                                    const QString &password);
    Q_INVOKABLE void chooseBitwardenMethod(int method);
    Q_INVOKABLE void sendBitwardenCode(const QString &code);
    Q_INVOKABLE void cancelBitwardenLogin();
    Q_INVOKABLE bool isBitwardenDatabase(int index) const;
    Q_INVOKABLE void logoutBitwarden(int index);
    Q_INVOKABLE QString validatePin(const QString &pin, const QString &confirm,
                                    bool allowText = false) const;
    Q_INVOKABLE QString pinWeakWarning(const QString &pin) const;

    // PIN unlock, one PIN per database
    Q_INVOKABLE void enablePin(const QString &password, const QString &pin,
                               bool allowText = false);
    Q_INVOKABLE void disablePin();

    // 1Password account
    Q_INVOKABLE void addOnePasswordAccount();
    Q_INVOKABLE void onePasswordLogin(const QString &address, const QString &email,
                                      const QString &secretKey, const QString &password,
                                      const QString &shorthand);
    Q_INVOKABLE void sendOnePasswordCode(const QString &code);
    Q_INVOKABLE void cancelOnePasswordLogin();
    Q_INVOKABLE bool isOnePasswordDatabase(int index) const;
    Q_INVOKABLE void logoutOnePassword(int index);

    // Entries
    Q_INVOKABLE bool isEmptyGroup(const QString &entry) const;
    Q_INVOKABLE QString groupNameOf(const QString &entry) const;
    // Drops the wait for an account check; the list takes the keyboard back.
    Q_INVOKABLE void cancelAccountCheck();

    Q_INVOKABLE void copyPassword(const QString &entry);
    Q_INVOKABLE void copyText(const QString &text);
    // The entry's login or URL to the clipboard, and its URL to the browser.
    Q_INVOKABLE void copyUsername(const QString &entry);
    Q_INVOKABLE void copyUrl(const QString &entry);
    Q_INVOKABLE void openUrl(const QString &entry);
    Q_INVOKABLE QVariantMap entryDetails(const QString &entry);
    Q_INVOKABLE QVariantMap entryFields(const QString &entry);
    Q_INVOKABLE void saveEntry(const QVariantMap &fields);
    Q_INVOKABLE void deleteEntry(const QString &entry);
    Q_INVOKABLE void renameGroup(const QString &entry, const QString &newName);
    Q_INVOKABLE QStringList matchingGroups(const QString &prefix) const;

    // Settings sheet
    Q_INVOKABLE QVariantMap settings() const;
    Q_INVOKABLE void saveSettings(const QVariantMap &values);
    // Copies a wordlist of the user's into omapass' own directory and hands
    // back the path to keep in the settings, or "" when it cannot be used.
    Q_INVOKABLE QString importWordlist(const QString &fileUrl);

    // Password generator
    Q_INVOKABLE QVariantMap generatorOptions() const;
    Q_INVOKABLE QVariantMap generate(const QVariantMap &options);
    Q_INVOKABLE void copySecret(const QString &password);

    // Status line
    Q_INVOKABLE void showMessage(const QString &text, bool isError);
    Q_INVOKABLE void clearMessage();

    // Window geometry, remembered across runs like the rest of the family.
    Q_INVOKABLE QVariantMap windowGeometry() const;
    Q_INVOKABLE void saveWindowGeometry(int x, int y, int width, int height, bool maximized);

signals:
    void stageChanged();
    void busyChanged();
    void syncingChanged();
    void databasesChanged();
    void scanningChanged();
    void checkingAccountChanged();
    void pendingDatabaseChanged();
    void unlockErrorChanged();
    void entriesChanged();
    void messageChanged();
    void databaseCreated();
    void loginChanged();
    void pinConfiguredChanged();

private:
    void setBusy(bool busy);
    // Runs `work` on a worker thread with the app marked busy, then `done`
    // with its result back on this one. The backends block on external
    // processes and the network — `op` takes seconds per call — and the
    // window has to keep painting meanwhile.
    template <typename Work, typename Done>
    void runInBackground(Work work, Done done);
    // Whether the open vault can take a change right now; says why not on the
    // status line when it cannot.
    bool vaultReadyForChanges();
    // Whether nothing else is running. Account actions used to return in
    // silence while busy, which looks exactly like a shortcut that does
    // nothing.
    bool requireIdle();
    void startBackgroundSync();
    void applyLockSettings();
    void setSyncing(bool syncing);
    void setUnlockError(const QString &error);
    void refreshDatabases();
    // Applies what a scan found: ordering by history and the current filter
    // both belong here, on this thread, where the history lives.
    void adoptDatabases();
    void applyDatabaseFilter();
    void finishScanPart(quint64 generation, QVector<DbRef> *slot, const QVector<DbRef> &found);
    void setScanning(bool scanning);
    void setCheckingAccount(bool checking);
    // Puts the database up for unlocking, which is where selecting one ends
    // when there is nothing left to check.
    void askForPassword(const DbRef &ref);
    // Asks the backend whether the account is still usable before the
    // password is asked for, off this thread.
    void checkAccountThenAsk(const DbRef &ref);
    void refreshEntries();
    void applyEntryFilter();
    void openVault(const DbRef &ref, const Secret &secret);
    void adoptVault(const DbRef &ref, Vault *vault);
    // The entry's fields for a copy, recording the use; says why not when
    // they cannot be read.
    bool fetchForCopy(const QString &entry, EntryData *data);
    void setLoginStep(const QString &step);
    // Account of the open vault, or of the one waiting to be unlocked.
    // The database a PIN would belong to: the open one, or the one waiting
    // to be unlocked.
    DbRef pinTarget() const;
    void refreshPinState();
    void closeVault();
    void showClipboardMessage(const QString &text);

    AppConfig m_config;
    History m_history;

    // Auto-lock by inactivity: `m_config.lockMinutes` unset disables it
    // entirely (event filter never installed, timer never started).
    // `m_lastActivity` restarts on every key/mouse event app-wide (see
    // eventFilter); `m_lockTimer` periodically compares it against the
    // configured timeout.
    QElapsedTimer m_lastActivity;
    QTimer m_lockTimer;

    QString m_stage = QStringLiteral("databases");
    bool m_busy = false;
    bool m_syncing = false;
    // Waited on at shutdown, so no worker thread outlives the vault it uses.
    QFuture<void> m_task;
    QFuture<void> m_syncTask;
    QFuture<void> m_localScanTask;
    QFuture<void> m_accountScanTask;
    QFuture<void> m_accountCheckTask;

    bool m_scanning = false;
    // The two halves of a scan answer independently; the list is always
    // their union, and the scan is over when none is left outstanding.
    QVector<DbRef> m_localDatabases;
    QVector<DbRef> m_accountDatabases;
    int m_scansOutstanding = 0;
    // Scans are counted so a result that arrives after a newer one was asked
    // for is dropped instead of putting a stale list back on screen.
    quint64 m_scanGeneration = 0;
    // Only the first scan may open a lone database on its own: doing it
    // after a later scan would yank the interface out from under whoever is
    // using it.
    bool m_firstScan = true;

    bool m_checkingAccount = false;
    // Counts up and never resets, so a cancelled check cannot be mistaken
    // for a later one that happens to land on the same number.
    quint64 m_accountCheckGeneration = 0;
    // Whether the answer of the check in flight is still wanted.
    bool m_accountCheckPending = false;
    QString m_checkingAccountName;
    // The wait sheet is held back this long, so a check that answers at once
    // — the usual case — never flashes one up.
    QTimer m_accountCheckDelay;

    QVector<DbRef> m_databases;
    QVector<DbRef> m_filteredDatabases;
    QString m_databaseQuery;
    DbRef m_pendingDatabase;
    bool m_hasPendingDatabase = false;
    QString m_unlockError;
    bool m_pinAvailable = false;
    bool m_pinConfigured = false;

    QScopedPointer<Vault> m_vault;

    BitwardenLogin m_bitwardenLogin;
    OnePasswordLogin m_onePasswordLogin;
    QString m_loginStep;
    QString m_loginEmail;
    QString m_loginServer;
    // The 1Password sign-in address, kept while its login sheet is open.
    QString m_loginAddress;
    // Whether the 1Password run in flight is adding an account or opening
    // one that is already here: both can stop to ask for a two-step code,
    // and they go back to different places when they fail.
    bool m_onePasswordAdding = false;

    QStringList m_allEntries;
    QStringList m_filteredEntries;
    QStringList m_groups;
    QString m_query;

    QString m_messageText;
    bool m_messageIsError = false;
    int m_clipboardCountdown = -1;
    QTimer m_messageTimer;
};
