#pragma once

#include <QElapsedTimer>
#include <QFuture>
#include <QFutureWatcher>
#include <QPromise>
#include <QThreadPool>
#include <QObject>
#include <QSet>
#include <QSharedPointer>
#include <QStringList>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>

#include "bitwardenlogin.h"
#include "browserintegration.h"
#include "bwsync.h"
#include "config.h"
#include "entryicons.h"
#include "entryrowsmodel.h"
#include "generator.h"
#include "history.h"
#include "onepasswordlogin.h"
#include "siteicons.h"
#include "totp.h"
#include "vault.h"

class QEvent;

// Everything the interface talks to: the database list, the open vault, the
// filtered entries and the transient status line. The QML side holds no
// password-manager logic of its own — it renders these properties and calls
// these actions, the same split the TUI had between app.rs and ui.rs.
class AppController : public QObject, public BrowserApp {
    Q_OBJECT

    Q_PROPERTY(QString stage READ stage NOTIFY stageChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    // A Bitwarden vault pulling from the server after it opened: reading
    // stays available, changes wait for it to finish.
    Q_PROPERTY(bool syncing READ syncing NOTIFY syncingChanged)

    Q_PROPERTY(QVariantList databases READ databases NOTIFY databasesChanged)
    Q_PROPERTY(bool anyDatabaseFound READ anyDatabaseFound NOTIFY databasesChanged)
    Q_PROPERTY(bool autoSearch READ autoSearch NOTIFY autoSearchChanged)
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

    Q_PROPERTY(QVariantList openDatabases READ openDatabases NOTIFY stageChanged)
    Q_PROPERTY(QString vaultLabel READ vaultLabel NOTIFY stageChanged)
    Q_PROPERTY(bool passBackend READ passBackend NOTIFY stageChanged)
    Q_PROPERTY(bool bitwardenBackend READ bitwardenBackend NOTIFY stageChanged)
    Q_PROPERTY(bool onePasswordBackend READ onePasswordBackend NOTIFY stageChanged)
    Q_PROPERTY(bool pinConfigured READ pinConfigured NOTIFY pinConfiguredChanged)

    Q_PROPERTY(QStringList entries READ entries NOTIFY entriesChanged)
    // The same entries as a model, one map each (`modelData`) for the list's
    // columns: path, name, group, type ("login", "ssh" or "group"),
    // typeLabel, username and url.
    Q_PROPERTY(QObject *entryRows READ entryRows CONSTANT)
    Q_PROPERTY(QString query READ query WRITE setQuery NOTIFY entriesChanged)
    Q_PROPERTY(QStringList groups READ groups NOTIFY entriesChanged)
    Q_PROPERTY(QVariantList bitwardenCollections READ bitwardenCollections NOTIFY entriesChanged)
    Q_PROPERTY(QVariantList bitwardenOrganizations READ bitwardenOrganizations NOTIFY entriesChanged)
    Q_PROPERTY(QString activeSection READ activeSection NOTIFY entriesChanged)
    Q_PROPERTY(QVariantList sidebarItems READ sidebarItems NOTIFY sidebarChanged)

    // The browser extension's side: its questions to the user, and whether
    // it is being answered (see BrowserIntegration).
    Q_PROPERTY(QObject *browser READ browser CONSTANT)

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
    bool autoSearch() const { return m_config.autoSearch; }
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
    QObject *entryRows() { return &m_rowsModel; }
    // For the image provider that hands the list its site icons.
    SiteIcons *siteIcons() { return &m_siteIcons; }
    EntryIcons *entryIcons() { return &m_entryIcons; }
    QString query() const { return m_query; }
    // The path of the row at `index` in the shown list, empty out of range.
    Q_INVOKABLE QString entryPathAt(int index) const { return m_rowsModel.pathAt(index); }
    void setQuery(const QString &query);
    QStringList groups() const { return m_groups; }
    QVariantList bitwardenCollections() const;
    QVariantList bitwardenOrganizations() const;
    QString activeSection() const { return m_activeSection; }
    QVariantList sidebarItems() const { return m_sidebarItems; }

    QObject *browser() { return &m_browser; }

    // BrowserApp
    const Vault *browserVault() const override { return m_vault.data(); }
    QList<const Vault *> browserVaults() const override;
    QStringList entriesFor(const Vault *vault) const override;
    QHash<QString, EntryMeta> metaFor(const Vault *vault) const override;
    QStringList browserGroups() const override { return m_groups; }
    void browserLock() override { lock(); }
    Secret browserGeneratePassword() override;
    bool browserChange(const Vault *vault, std::function<bool(const Vault *, QString *)> work,
                       std::function<void(bool)> done) override;

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
    QVariantList openDatabases() const;
    Q_INVOKABLE void switchDatabase(const QString &path);
    Q_INVOKABLE void switchDatabaseAt(int index);
    Q_INVOKABLE void chooseAnotherDatabase();
    Q_INVOKABLE void lock();
    void lockAll();

    // Database creation & registration
    Q_INVOKABLE void createKeepassDatabase(const QString &name, const QString &password);
    Q_INVOKABLE void openExistingKeepassDatabase(const QString &fileUrlOrPath);
    Q_INVOKABLE void openExistingPassStore(const QString &dirUrlOrPath);
    Q_INVOKABLE bool openDatabasePath(const QString &pathOrUrl);
    Q_INVOKABLE void enableAutoSearch();
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
    Q_INVOKABLE bool isKeepassDatabase(int index) const;
    Q_INVOKABLE void unlistKeepassDatabase(int index);
    Q_INVOKABLE bool isBitwardenDatabase(int index) const;
    Q_INVOKABLE void logoutBitwarden(int index);
    Q_INVOKABLE void syncBitwarden();
    Q_INVOKABLE bool createBitwardenSend(const QVariantMap &fields);
    Q_INVOKABLE bool createGroup(const QString &name);
    Q_INVOKABLE bool createBitwardenCollection(const QString &organizationId, const QString &name);
    Q_INVOKABLE void selectSection(const QString &section);
    // Why a sidebar group or collection cannot be deleted, or empty when it
    // can: only one with no entries and no subgroups goes.
    Q_INVOKABLE QString sidebarDeleteBlocker(const QString &id) const;
    Q_INVOKABLE void deleteSidebarItem(const QString &id);
    Q_INVOKABLE void toggleSidebarNode(const QString &expandKey);
    Q_INVOKABLE void setSidebarNodeExpanded(const QString &expandKey, bool expanded);
    Q_INVOKABLE void restoreTrashEntry(const QString &cipherId);
    Q_INVOKABLE void purgeTrashEntry(const QString &cipherId);
    Q_INVOKABLE void deleteBitwardenSend(const QString &sendId);
    Q_INVOKABLE QString sendUrlFor(const QString &sendPath) const;
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
    Q_INVOKABLE bool isNoteEntry(const QString &entry) const;
    Q_INVOKABLE QString entryKind(const QString &entry) const;
    Q_INVOKABLE QString entryLabelFor(const QString &entry) const;
    Q_INVOKABLE QString groupNameOf(const QString &entry) const;
    // Drops the wait for an account check; the list takes the keyboard back.
    Q_INVOKABLE void cancelAccountCheck();

    Q_INVOKABLE void copyPassword(const QString &entry);
    Q_INVOKABLE QVariantMap entryMenuFields(const QString &entry) const;
    Q_INVOKABLE QVariantMap sshKeyOptions(const QString &entry) const;
    Q_INVOKABLE bool saveSshKeyOptions(const QString &entry, bool addOnUnlock,
                                      bool confirm, int lifetimeSeconds);
    Q_INVOKABLE void addSshKey(const QString &entry);
    Q_INVOKABLE void removeSshKey(const QString &entry);
    Q_INVOKABLE void copyText(const QString &text);
    // The entry's login or URL to the clipboard, and its URL to the browser.
    Q_INVOKABLE void copyUsername(const QString &entry);
    Q_INVOKABLE void copyUrl(const QString &entry);
    Q_INVOKABLE void openUrl(const QString &entry);
    // Any address in the browser, for the info sheet's additional URLs.
    Q_INVOKABLE void openAddress(const QString &address);
    // The entry's current one-time password to the clipboard, cleared like
    // a password.
    Q_INVOKABLE void copyOtp(const QString &entry);
    // Also keeps the entry's one-time password, parsed, for otpNow(): the
    // info sheet asks for the code every second and the secret never has
    // to leave this side. `hasOtp` says whether there is one.
    Q_INVOKABLE QVariantMap entryDetails(const QString &entry);
    // The code of the entry last shown by entryDetails(), with `secondsLeft`
    // and `period` for the countdown; empty when it has none.
    Q_INVOKABLE QVariantMap otpNow() const;
    Q_INVOKABLE void copyShownOtp();
    // Drops what entryDetails() kept, when the sheet closes.
    Q_INVOKABLE void forgetShownOtp();
    Q_INVOKABLE QVariantMap entryFields(const QString &entry);
    Q_INVOKABLE bool saveEntry(const QVariantMap &fields);
    Q_INVOKABLE void deleteEntry(const QString &entry);
    // An icon of the user's choosing for the entry, from an image file (a
    // file:// URL, as the file dialog gives it), or none. In the database for
    // KeePass, on this computer for the rest.
    Q_INVOKABLE void chooseEntryIcon(const QString &entry, const QString &fileUrl);
    Q_INVOKABLE void clearEntryIcon(const QString &entry);
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
    void autoSearchChanged();
    void scanningChanged();
    void checkingAccountChanged();
    void pendingDatabaseChanged();
    void unlockErrorChanged();
    void entriesChanged();
    void sidebarChanged();
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
    // Sets a row's `icon`: the one the user chose, or else its site's
    // (`origin` set, and the icon asked for when it is not cached yet, when
    // site icons are on).
    void applyIcon(QVariantMap *row, const QString &path, const QString &url);
    // Reads the open vault's icon choice, before its rows are built.
    void loadIconChoice();
    void storeEntryIcon(const QString &entry, const QByteArray &png);
    // A row of m_allRows changed: the shown copy, if it is shown, follows.
    void updateShownRow(int index);
    // Puts a one-time code on the clipboard, cleared like a password.
    void copyOtpCode(const QString &code, const QString &entry);
    // Whether nothing else is running. Account actions used to return in
    // silence while busy, which looks exactly like a shortcut that does
    // nothing.
    bool requireIdle();
    void startBackgroundSync(bool force = false);
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
    void showVaultWarning();
    void applyEntryFilter();
    void rebuildRows();
    void startMetaLoad();
    void stopMetaLoad();
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
    QString closeVault();
    void startSshKeys();
    void runSshTask(std::function<QString(const QPromise<QString> &)> work,
                    const QString &success = {});
    QString addSshIdentity(const Vault *vault, const QString &entry, const SshKeyConfig &key,
                           const SshKeyOptions &options);
    QString clearSshKeys();
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
    QFuture<void> m_bwRealtimeTask;
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

    struct ParkedVault {
        QSharedPointer<Vault> vault;
        SshAgent ssh;
        QStringList entries;
        QHash<QString, EntryMeta> meta;
    };
    QList<ParkedVault> m_parked;
    QStringList m_openOrder;
    QSharedPointer<Vault> m_vault;
    void parkVault();
    void displayVault();
    void resetVaultView();
    void closeParked();
    bool isOpen(const QString &path) const;
    bool m_lockAllPending = false;
    QString m_lockPendingPath;
    void finishPendingLock();
    SshAgent m_sshAgent;
    QFutureWatcher<QString> *m_sshTask = nullptr;

    BitwardenLogin m_bitwardenLogin;
    BwSync m_bwSync;
    QTimer m_bwReconnectTimer;
    int m_bwReconnectDelayMs = 5000;
    void startBitwardenRealtime();
    void stopBitwardenRealtime();
    void handleBitwardenSyncEvent(const BwSyncEvent &event);
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
    QStringList m_entryHaystacks;     // what the search reads, parallel to m_allEntries
    QVariantList m_allRows;           // parallel to m_allEntries
    QList<int> m_shownRows;           // m_allEntries positions the filter kept
    QHash<QString, int> m_rowOf;      // entry path → position in m_allEntries
    EntryRowsModel m_rowsModel;
    SiteIcons m_siteIcons;
    // Whether the open vault's rows ask the sites for icons (IconChoice):
    // its own choice, not the config.toml default the settings edit while
    // no vault is open.
    bool m_iconsDownload = false;
    bool m_iconsDuckDuckGo = false;
    EntryIcons m_entryIcons;

    // Login and URL read one entry at a time for a backend that cannot list
    // them: filled in the background and kept while the vault stays open.
    struct LazyMeta {
        QString path;
        bool ok = false;
        EntryMeta meta;
    };
    QHash<QString, EntryMeta> m_lazyMeta;     // what has arrived so far
    std::optional<TotpParams> m_shownOtp;     // the info sheet's entry, see otpNow()
    QString m_shownOtpEntry;
    QHash<QString, EntryMeta> m_listedMeta;   // what the backend listed at once
    QFutureWatcher<LazyMeta> *m_metaWatcher = nullptr;
    QThreadPool m_metaPool;
    QTimer m_metaFlush;                       // batches arrivals into one repaint
    QStringList m_metaArrived;                // paths that came in since the last repaint
    QStringList m_groups;
    QString m_activeSection = QStringLiteral("all");
    QSet<QString> m_expandedSidebarNodes;
    QVariantList m_sidebarItems;
    void rebuildSidebar();
    QString m_query;

    QString m_messageText;
    bool m_messageIsError = false;
    int m_clipboardCountdown = -1;
    QTimer m_messageTimer;

    // Last, so it goes first: it waits for its reads of the vault and closes
    // the socket before anything it uses is torn down.
    BrowserIntegration m_browser;
};
