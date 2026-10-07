#pragma once

#include <QObject>
#include <QVariantList>
#include <QVariantMap>

// Stand-in for AppController, so DatabasePage can be drawn in a test the way
// it is drawn in the application. Only the properties the page reads are
// here; the actions it calls are no-ops, since what is under test is what
// the page decides to show, not what the controller does about it.
//
// The point of driving it by hand is the order signals arrive in: the page
// must reach the same conclusion whether the list or the scan flag lands
// first, which is precisely what it once got wrong.
class FakeController : public QObject {
    Q_OBJECT

    Q_PROPERTY(bool scanning MEMBER m_scanning NOTIFY scanningChanged)
    Q_PROPERTY(bool anyDatabaseFound READ anyDatabaseFound NOTIFY databasesChanged)
    Q_PROPERTY(QVariantList databases MEMBER m_databases NOTIFY databasesChanged)
    Q_PROPERTY(QString databaseQuery MEMBER m_databaseQuery NOTIFY databasesChanged)
    Q_PROPERTY(bool busy MEMBER m_busy CONSTANT)
    Q_PROPERTY(bool checkingAccount MEMBER m_checkingAccount NOTIFY checkingAccountChanged)
    Q_PROPERTY(QString checkingAccountName MEMBER m_checkingAccountName NOTIFY checkingAccountChanged)
    Q_PROPERTY(QVariantMap pendingDatabase MEMBER m_pendingDatabase NOTIFY pendingDatabaseChanged)
    Q_PROPERTY(QString unlockError MEMBER m_unlockError CONSTANT)
    Q_PROPERTY(bool pinAvailable MEMBER m_pinAvailable CONSTANT)
    Q_PROPERTY(QString loginStep MEMBER m_loginStep NOTIFY loginChanged)
    Q_PROPERTY(QString loginEmail MEMBER m_loginEmail NOTIFY loginChanged)
    Q_PROPERTY(QString loginServer MEMBER m_loginServer NOTIFY loginChanged)
    Q_PROPERTY(QVariantList loginMethods MEMBER m_loginMethods NOTIFY loginChanged)
    Q_PROPERTY(bool onePasswordAvailable MEMBER m_onePasswordAvailable CONSTANT)
    Q_PROPERTY(QString message MEMBER m_message NOTIFY messageChanged)
    Q_PROPERTY(bool messageIsError MEMBER m_messageIsError NOTIFY messageChanged)
    Q_PROPERTY(bool hasMessage MEMBER m_hasMessage NOTIFY messageChanged)
    // What the last copy put on the clipboard, for the tests to read.
    Q_PROPERTY(QString lastCopied MEMBER m_lastCopied NOTIFY copied)

public:
    using QObject::QObject;

    bool anyDatabaseFound() const { return !m_databases.isEmpty(); }

    // The two halves of a finished scan, so a test can deliver them in
    // either order.
    Q_INVOKABLE void emitScanning(bool scanning) {
        m_scanning = scanning;
        emit scanningChanged();
    }
    Q_INVOKABLE void emitDatabases(const QVariantList &databases) {
        m_databases = databases;
        emit databasesChanged();
    }

    Q_INVOKABLE void selectDatabase(int) {}
    Q_INVOKABLE void copyText(const QString &text) {
        m_lastCopied = text;
        emit copied();
    }
    Q_INVOKABLE bool isBitwardenDatabase(int) { return false; }
    Q_INVOKABLE bool isOnePasswordDatabase(int) { return false; }
    Q_INVOKABLE void cancelAccountCheck() { emit cancelAccountCheckCalled(); }
    Q_INVOKABLE void cancelUnlock() {}
    Q_INVOKABLE void unlock(const QString &) {}
    Q_INVOKABLE void unlockWithPin(const QString &) {}
    Q_INVOKABLE void createKeepassDatabase(const QString &, const QString &) {}
    Q_INVOKABLE void createPassStore(const QString &, const QString &) {}
    Q_INVOKABLE void addBitwardenAccount() {}
    Q_INVOKABLE void addOnePasswordAccount() {}
    Q_INVOKABLE void bitwardenLogin(const QString &, const QString &, const QString &) {}
    Q_INVOKABLE void sendBitwardenCode(const QString &) {}
    Q_INVOKABLE void cancelBitwardenLogin() {}
    Q_INVOKABLE void chooseBitwardenMethod(int) {}
    Q_INVOKABLE void logoutBitwarden(int) {}
    Q_INVOKABLE void onePasswordLogin(const QString &, const QString &, const QString &,
                                      const QString &, const QString &) {}
    Q_INVOKABLE void sendOnePasswordCode(const QString &) {}
    Q_INVOKABLE void cancelOnePasswordLogin() {}
    Q_INVOKABLE void logoutOnePassword(int) {}

signals:
    void copied();
    void scanningChanged();
    void databasesChanged();
    void checkingAccountChanged();
    void pendingDatabaseChanged();
    void loginChanged();
    void messageChanged();
    void cancelAccountCheckCalled();
    void databaseCreated();

private:
    bool m_scanning = true;
    QVariantList m_databases;
    QString m_databaseQuery;
    bool m_busy = false;
    bool m_checkingAccount = false;
    QString m_checkingAccountName;
    QVariantMap m_pendingDatabase;
    QString m_unlockError;
    bool m_pinAvailable = false;
    QString m_loginStep;
    QString m_loginEmail;
    QString m_loginServer;
    QString m_lastCopied;
    QVariantList m_loginMethods;
    bool m_onePasswordAvailable = true;
    QString m_message;
    bool m_messageIsError = false;
    bool m_hasMessage = false;
};
