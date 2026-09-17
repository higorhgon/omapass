#pragma once

#include <QElapsedTimer>
#include <QObject>
#include <QScopedPointer>
#include <QStringList>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>

#include "bitwardenlogin.h"
#include "config.h"
#include "history.h"
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

    Q_PROPERTY(QVariantList databases READ databases NOTIFY databasesChanged)
    Q_PROPERTY(bool anyDatabaseFound READ anyDatabaseFound NOTIFY databasesChanged)
    Q_PROPERTY(QString databaseQuery READ databaseQuery WRITE setDatabaseQuery NOTIFY databasesChanged)
    Q_PROPERTY(QVariantMap pendingDatabase READ pendingDatabase NOTIFY pendingDatabaseChanged)
    Q_PROPERTY(QString unlockError READ unlockError NOTIFY unlockErrorChanged)

    Q_PROPERTY(bool bitwardenAvailable READ bitwardenAvailable CONSTANT)
    // Where the Bitwarden login sheet is: "" (closed), "credentials",
    // "method", "code" or "deviceCode".
    Q_PROPERTY(QString loginStep READ loginStep NOTIFY loginChanged)
    Q_PROPERTY(QString loginEmail READ loginEmail NOTIFY loginChanged)

    Q_PROPERTY(QString vaultLabel READ vaultLabel NOTIFY stageChanged)
    Q_PROPERTY(bool passBackend READ passBackend NOTIFY stageChanged)

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

    QVariantList databases() const;
    bool anyDatabaseFound() const { return !m_databases.isEmpty(); }
    QString databaseQuery() const { return m_databaseQuery; }
    void setDatabaseQuery(const QString &query);
    QVariantMap pendingDatabase() const;
    QString unlockError() const { return m_unlockError; }

    bool bitwardenAvailable() const;
    QString loginStep() const { return m_loginStep; }
    QString loginEmail() const { return m_loginEmail; }

    QString vaultLabel() const;
    bool passBackend() const;

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
    Q_INVOKABLE void cancelUnlock();

    // Database creation
    Q_INVOKABLE void createKeepassDatabase(const QString &name, const QString &password);
    Q_INVOKABLE QVariantList gpgKeys() const;
    Q_INVOKABLE QStringList directorySuggestions(const QString &path) const;
    Q_INVOKABLE QString defaultPassStoreDirectory() const;
    Q_INVOKABLE void createPassStore(const QString &directory, const QString &keyId);

    // Bitwarden account
    Q_INVOKABLE void addBitwardenAccount();
    Q_INVOKABLE void bitwardenLogin(const QString &email, const QString &password);
    Q_INVOKABLE void chooseBitwardenMethod(int method);
    Q_INVOKABLE void sendBitwardenCode(const QString &code);
    Q_INVOKABLE void cancelBitwardenLogin();
    Q_INVOKABLE bool isBitwardenDatabase(int index) const;
    Q_INVOKABLE void logoutBitwarden();

    // Entries
    Q_INVOKABLE bool isEmptyGroup(const QString &entry) const;
    Q_INVOKABLE QString groupNameOf(const QString &entry) const;
    Q_INVOKABLE void copyPassword(const QString &entry);
    Q_INVOKABLE void copyText(const QString &text);
    Q_INVOKABLE QVariantMap entryDetails(const QString &entry);
    Q_INVOKABLE QVariantMap entryFields(const QString &entry);
    Q_INVOKABLE void saveEntry(const QVariantMap &fields);
    Q_INVOKABLE void deleteEntry(const QString &entry);
    Q_INVOKABLE void renameGroup(const QString &entry, const QString &newName);
    Q_INVOKABLE QStringList matchingGroups(const QString &prefix) const;

    // Status line
    Q_INVOKABLE void showMessage(const QString &text, bool isError);
    Q_INVOKABLE void clearMessage();

    // Window geometry, remembered across runs like the rest of the family.
    Q_INVOKABLE QVariantMap windowGeometry() const;
    Q_INVOKABLE void saveWindowGeometry(int x, int y, int width, int height, bool maximized);

signals:
    void stageChanged();
    void busyChanged();
    void databasesChanged();
    void pendingDatabaseChanged();
    void unlockErrorChanged();
    void entriesChanged();
    void messageChanged();
    void databaseCreated();
    void loginChanged();

private:
    void setBusy(bool busy);
    void setUnlockError(const QString &error);
    void refreshDatabases();
    void refreshEntries();
    void applyEntryFilter();
    void openVault(const DbRef &ref, const Secret &secret);
    void adoptVault(const DbRef &ref, Vault *vault);
    void setLoginStep(const QString &step);
    void closeVault();
    void showClipboardMessage(const QString &text);
    void lock();

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

    QVector<DbRef> m_databases;
    QVector<DbRef> m_filteredDatabases;
    QString m_databaseQuery;
    DbRef m_pendingDatabase;
    bool m_hasPendingDatabase = false;
    QString m_unlockError;

    QScopedPointer<Vault> m_vault;

    BitwardenLogin m_bitwardenLogin;
    QString m_loginStep;
    QString m_loginEmail;
    // Kept only while a login is in progress: choosing a two-step method
    // restarts `bw login`, which needs the password again.
    Secret m_loginPassword;

    QStringList m_allEntries;
    QStringList m_filteredEntries;
    QStringList m_groups;
    QString m_query;

    QString m_messageText;
    bool m_messageIsError = false;
    int m_clipboardCountdown = -1;
    QTimer m_messageTimer;
};
