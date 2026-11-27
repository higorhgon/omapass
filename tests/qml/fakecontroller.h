#pragma once

#include <QObject>
#include <QVariantList>
#include <QVariantMap>

// Stand-in for BrowserIntegration: the prompt is set by the test, and the
// answers BrowserPromptModal gives are kept for it to read.
class FakeBrowser : public QObject {
    Q_OBJECT

    Q_PROPERTY(QVariantMap prompt MEMBER m_prompt NOTIFY promptChanged)
    Q_PROPERTY(QVariantList answers MEMBER m_answers NOTIFY promptChanged)
    Q_PROPERTY(QString existing MEMBER m_existing NOTIFY promptChanged)

public:
    using QObject::QObject;

    Q_INVOKABLE void setPrompt(const QVariantMap &prompt) {
        m_prompt = prompt;
        m_answers.clear();
        emit promptChanged();
    }
    Q_INVOKABLE void answerAssociate(const QString &name) { record(QStringLiteral("associate"), name); }
    Q_INVOKABLE bool associationExists(const QString &name) const { return !name.isEmpty() && name == m_existing; }
    Q_INVOKABLE void answerAccess(const QStringList &allowed, bool remember) {
        record(QStringLiteral("access"), QVariantMap{{QStringLiteral("allowed"), allowed},
                                                     {QStringLiteral("remember"), remember}});
    }
    Q_INVOKABLE void answerUpdate(bool accepted) { record(QStringLiteral("update"), accepted); }
    Q_INVOKABLE void answerConflict(bool replace) { record(QStringLiteral("conflict"), replace); }

signals:
    void promptChanged();
    void raiseRequested();

private:
    // As the real one does: answered, the prompt goes.
    void record(const QString &kind, const QVariant &value) {
        m_answers.append(QVariantMap{{QStringLiteral("kind"), kind}, {QStringLiteral("value"), value}});
        m_prompt.clear();
        emit promptChanged();
    }

    QVariantMap m_prompt;
    QVariantList m_answers;
    QString m_existing = QStringLiteral("notebook");
};

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
    // How many times GeneratorModal copied what it generated.
    Q_PROPERTY(int copiedSecrets MEMBER m_copiedSecrets NOTIFY copied)
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
    // What the last "open in the browser" was asked to open.
    Q_PROPERTY(QString lastOpened MEMBER m_lastOpened NOTIFY copied)
    Q_PROPERTY(QObject *browser READ browser CONSTANT)
    Q_PROPERTY(QVariantList entryRows READ entryRows CONSTANT)
    Q_PROPERTY(QString query MEMBER m_query NOTIFY queryChanged)
    Q_PROPERTY(QString activeSection MEMBER m_activeSection NOTIFY queryChanged)
    Q_PROPERTY(QVariantList sidebarItems MEMBER m_sidebarItems NOTIFY sidebarChanged)
    Q_PROPERTY(QVariantList openDatabases READ openDatabases CONSTANT)
    Q_PROPERTY(QString vaultLabel READ vaultLabel CONSTANT)
    Q_PROPERTY(bool passBackend MEMBER m_passBackend CONSTANT)
    Q_PROPERTY(bool bitwardenBackend MEMBER m_bitwardenBackend NOTIFY backendChanged)
    Q_PROPERTY(bool onePasswordBackend MEMBER m_onePasswordBackend CONSTANT)
    Q_PROPERTY(QStringList groups MEMBER m_groups)
    Q_PROPERTY(QVariantList bitwardenCollections MEMBER m_bitwardenCollections CONSTANT)
    Q_PROPERTY(QVariantList bitwardenOrganizations MEMBER m_bitwardenOrganizations NOTIFY backendChanged)
    Q_PROPERTY(bool pinConfigured MEMBER m_pinConfigured CONSTANT)
    Q_PROPERTY(bool syncing MEMBER m_syncing CONSTANT)

public:
    using QObject::QObject;

    QObject *browser() { return &m_browser; }
    bool anyDatabaseFound() const { return !m_databases.isEmpty(); }
    QVariantList openDatabases() const {
        return {QVariantMap{{"name", "Pessoal"}, {"kind", "KeePassXC"}, {"path", "/pessoal.kdbx"}},
                QVariantMap{{"name", "Trabalho"}, {"kind", "pass"}, {"path", "/trabalho"}}};
    }
    Q_INVOKABLE void switchDatabase(const QString &path) { emit databaseSwitched(path); }
    Q_INVOKABLE void switchDatabaseAt(int index) {
        const QVariantList dbs = openDatabases();
        if (index >= 0 && index < dbs.size())
            emit databaseSwitched(dbs.at(index).toMap().value(QStringLiteral("path")).toString());
    }
    Q_INVOKABLE void chooseAnotherDatabase() { emit databasePickerRequested(); }
    QString vaultLabel() const { return QStringLiteral("Cofre"); }

    QVariantList entryRows() const {
        return {QVariantMap{{QStringLiteral("path"), QStringLiteral("Trabalho/Gmail")},
                            {QStringLiteral("name"), QStringLiteral("Gmail")}},
                QVariantMap{{QStringLiteral("path"), QStringLiteral("Outlook")},
                            {QStringLiteral("name"), QStringLiteral("Outlook")}}};
    }

    Q_INVOKABLE QString entryPathAt(int index) const {
        return entryRows().value(index).toMap().value(QStringLiteral("path")).toString();
    }
    Q_INVOKABLE bool isEmptyGroup(const QString &) const { return false; }
    Q_INVOKABLE bool isNoteEntry(const QString &) const { return false; }
    Q_INVOKABLE QString entryKind(const QString &) const { return QStringLiteral("login"); }
    Q_INVOKABLE QString entryLabelFor(const QString &entry) const { return entry; }
    Q_INVOKABLE bool createBitwardenSend(const QVariantMap &) { return true; }
    Q_INVOKABLE bool createGroup(const QString &) { return true; }
    Q_INVOKABLE bool createBitwardenCollection(const QString &, const QString &) { return true; }
    Q_INVOKABLE void syncBitwarden() {}
    Q_INVOKABLE void selectSection(const QString &section) { m_activeSection = section; emit queryChanged(); }
    Q_INVOKABLE void toggleSidebarNode(const QString &) { emit sidebarChanged(); }
    Q_INVOKABLE void setSidebarNodeExpanded(const QString &, bool) { emit sidebarChanged(); }
    Q_INVOKABLE void restoreTrashEntry(const QString &) {}
    Q_INVOKABLE void purgeTrashEntry(const QString &) {}
    Q_INVOKABLE void deleteBitwardenSend(const QString &) {}
    Q_INVOKABLE QString sendUrlFor(const QString &) const { return QString(); }
    Q_INVOKABLE QVariantMap entryMenuFields(const QString &entry) const {
        return {{QStringLiteral("hasPassword"), entry == entryPathAt(0)},
                {QStringLiteral("hasUsername"), entry == entryPathAt(1)},
                {QStringLiteral("hasUrl"), entry == entryPathAt(0)},
                {QStringLiteral("hasOtp"), entry == entryPathAt(1)}};
    }
    Q_INVOKABLE QVariantMap sshKeyOptions(const QString &) const { return {}; }
    Q_INVOKABLE QVariantMap entryDetails(const QString &entry) const {
        return {{QStringLiteral("title"), entry.section(QLatin1Char('/'), -1)},
                {QStringLiteral("notes"), QStringLiteral("segunda conta")}};
    }
    Q_INVOKABLE QVariantMap entryFields(const QString &entry) const {
        auto fields = entryDetails(entry);
        fields.insert(QStringLiteral("originalPath"), entry);
        return fields;
    }

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

    Q_INVOKABLE void selectDatabase(int index) { emit databaseSelected(index); }
    Q_INVOKABLE void copyPassword(const QString &entry) { emit passwordRequested(entry); }
    Q_INVOKABLE void copyText(const QString &text) {
        m_lastCopied = text;
        emit copied();
    }
    Q_INVOKABLE void openAddress(const QString &address) {
        m_lastOpened = address;
        emit copied();
    }
    Q_INVOKABLE bool isKeepassDatabase(int) { return false; }
    Q_INVOKABLE void unlistKeepassDatabase(int) {}
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

    // The info sheet's one-time password: a fixed code, and copying it goes
    // through its own call (the clipboard clearing of a password), which is
    // what a test checks.
    Q_INVOKABLE QVariantMap otpNow() const {
        return {{QStringLiteral("code"), QStringLiteral("287082")},
                {QStringLiteral("secondsLeft"), 4},
                {QStringLiteral("period"), 30}};
    }
    Q_INVOKABLE void copyShownOtp() {
        m_lastCopied = QStringLiteral("otp:287082");
        emit copied();
    }
    Q_INVOKABLE void forgetShownOtp() {}
    // Groups the form suggests: every one for an empty field, else those
    // that contain what was typed. Empty unless a test fills it.
    Q_INVOKABLE QStringList matchingGroups(const QString &prefix) const {
        QStringList matches;
        for (const QString &group : m_groups) {
            if (group.contains(prefix, Qt::CaseInsensitive))
                matches.append(group);
        }
        return matches;
    }
    // PinSetupModal's warning under the PIN, and what it says is wrong.
    Q_INVOKABLE QString pinWeakWarning(const QString &) const { return QString(); }
    Q_INVOKABLE QString validatePin(const QString &, const QString &, bool) const { return QString(); }

    // What GeneratorModal reads on opening and calls on every change. The
    // password is not the point there, only that the sheet can be walked.
    Q_INVOKABLE QVariantMap generatorOptions() const {
        return {
            {QStringLiteral("passphrase"), false},
            {QStringLiteral("passphraseAvailable"), true},
            {QStringLiteral("length"), 20},
            {QStringLiteral("lower"), true},
            {QStringLiteral("upper"), true},
            {QStringLiteral("numbers"), true},
            {QStringLiteral("logograms"), false},
            {QStringLiteral("punctuation"), false},
            {QStringLiteral("quotes"), false},
            {QStringLiteral("dashes"), false},
            {QStringLiteral("math"), false},
            {QStringLiteral("braces"), false},
            {QStringLiteral("extendedAscii"), false},
            {QStringLiteral("excludeSimilar"), false},
            {QStringLiteral("everyGroup"), true},
            {QStringLiteral("exclude"), QString()},
            {QStringLiteral("extra"), QString()},
            {QStringLiteral("custom"), QString()},
            {QStringLiteral("words"), 6},
            {QStringLiteral("separator"), QStringLiteral("-")},
        };
    }
    Q_INVOKABLE void copySecret(const QString &) {
        ++m_copiedSecrets;
        emit copied();
    }
    Q_INVOKABLE QVariantMap generate(const QVariantMap &) const {
        return {{QStringLiteral("password"), QStringLiteral("senha-de-teste")},
                {QStringLiteral("entropy"), 82.0},
                {QStringLiteral("quality"), QStringLiteral("good")}};
    }

signals:
    void databaseSelected(int index);
    void passwordRequested(const QString &entry);
    void databaseSwitched(const QString &path);
    void databasePickerRequested();
    void queryChanged();
    void sidebarChanged();
    void backendChanged();
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
    QString m_query;
    QString m_activeSection = QStringLiteral("all");
    QVariantList m_sidebarItems;
    bool m_passBackend = false;
    bool m_bitwardenBackend = false;
    bool m_onePasswordBackend = false;
    QStringList m_groups;
    QVariantList m_bitwardenCollections;
    QVariantList m_bitwardenOrganizations;
    bool m_pinConfigured = false;
    bool m_syncing = false;
    bool m_scanning = true;
    int m_copiedSecrets = 0;
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
    QString m_lastOpened;
    FakeBrowser m_browser;
    QVariantList m_loginMethods;
    bool m_onePasswordAvailable = true;
    QString m_message;
    bool m_messageIsError = false;
    bool m_hasMessage = false;
};
