#include "bitwardenvault.h"

#include "bwcache.h"
#include "i18n.h"
#include "process.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QSettings>
#include <QStandardPaths>
#include <QThread>

#include <atomic>

namespace {

const auto accountSetting = QStringLiteral("bitwarden/account");
const auto refPrefix = QStringLiteral("bitwarden:");

// The `bw lock` started by the last close(), which runs detached.
std::atomic<qint64> pendingLockPid{0};

// A lock that finishes after a new unlock would invalidate the session that
// unlock just created, so unlocking first lets any pending lock end.
void waitForPendingLock() {
    const qint64 pid = pendingLockPid.exchange(0);
    if (pid <= 0)
        return;
    const QString procEntry = QStringLiteral("/proc/%1").arg(pid);
    for (int waited = 0; waited < 10000 && QFile::exists(procEntry); waited += 100)
        QThread::msleep(100);
}

// bw's messages come after whatever it drew on stderr; the last line is the
// one that explains the failure.
QString lastMessage(const ProcResult &result) {
    static const QRegularExpression ansi(QStringLiteral("\\x1b\\[[0-9;?]*[A-Za-z]"));
    for (const QString &text : {result.err, result.out}) {
        QString clean = text;
        clean.remove(ansi);
        const QStringList lines = clean.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        for (auto it = lines.crbegin(); it != lines.crend(); ++it) {
            if (!it->trimmed().isEmpty())
                return it->trimmed();
        }
    }
    return QString();
}

QProcessEnvironment bwEnvironment(const Secret &session) {
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("BW_NOINTERACTION"), QStringLiteral("true"));
    if (!session.isEmpty())
        env.insert(QStringLiteral("BW_SESSION"), session.toString());
    return env;
}

ProcResult runBw(const QStringList &args, const Secret &session,
                 const QByteArray &stdinData = QByteArray(),
                 const QProcessEnvironment &extraEnv = QProcessEnvironment()) {
    QProcessEnvironment env = bwEnvironment(session);
    env.insert(extraEnv);

    ProcResult result = runProcess(QStringLiteral("bw"), args, stdinData, env);
    if (!result.started)
        result.err = I18n::t(QStringLiteral("bitwarden.spawn_error"), QStringLiteral("err"), result.err);
    else if (!result.success)
        result.err = lastMessage(result);
    return result;
}

// bw takes objects as base64-encoded JSON; stdin keeps them out of argv.
ProcResult runBwWithJson(const QStringList &args, const Secret &session, QByteArray json) {
    QByteArray encoded = json.toBase64();
    json.fill('\0');
    ProcResult result = runBw(args, session, encoded);
    encoded.fill('\0');
    return result;
}

// Runs several read-only bw commands at once: each pays Node's start-up on
// its own, so side by side they take about as long as one.
QVector<ProcResult> runBwParallel(const QVector<QStringList> &commands, const Secret &session) {
    const QProcessEnvironment env = bwEnvironment(session);

    QVector<QProcess *> processes;
    for (const QStringList &args : commands) {
        auto *process = new QProcess;
        process->setProcessEnvironment(env);
        process->start(QStringLiteral("bw"), args);
        process->closeWriteChannel();
        processes.append(process);
    }

    QVector<ProcResult> results;
    for (QProcess *process : std::as_const(processes)) {
        ProcResult result;
        result.started = process->waitForStarted(-1);
        if (result.started) {
            process->waitForFinished(-1);
            result.success = process->exitStatus() == QProcess::NormalExit && process->exitCode() == 0;
            result.out = QString::fromUtf8(process->readAllStandardOutput());
            result.err = QString::fromUtf8(process->readAllStandardError());
            if (!result.success)
                result.err = lastMessage(result);
        } else {
            result.err = I18n::t(QStringLiteral("bitwarden.spawn_error"), QStringLiteral("err"),
                                 process->errorString());
        }
        results.append(result);
        delete process;
    }
    return results;
}

void wipe(QString *text) {
    text->fill(QChar(0));
    text->clear();
}

QString lastSegment(const QString &path) {
    return path.section(QLatin1Char('/'), -1);
}

}

bool BitwardenVault::isAvailable() {
    return !QStandardPaths::findExecutable(QStringLiteral("bw")).isEmpty();
}

QString BitwardenVault::rememberedAccount() {
    return QSettings().value(accountSetting).toString();
}

void BitwardenVault::rememberAccount(const QString &email) {
    QSettings().setValue(accountSetting, email);
}

void BitwardenVault::forgetAccount() {
    QSettings().remove(accountSetting);
}

QString BitwardenVault::refPath(const QString &email) {
    return refPrefix + email;
}

QString BitwardenVault::emailOf(const QString &path) {
    return path.startsWith(refPrefix) ? path.mid(refPrefix.size()) : path;
}

bool BitwardenVault::unlockSession(const Secret &password, Secret *session, QString *error) {
    waitForPendingLock();

    QProcessEnvironment passwordEnv;
    passwordEnv.insert(QStringLiteral("OMAPASS_BW_PASSWORD"), password.toString());
    ProcResult result = runBw({QStringLiteral("unlock"), QStringLiteral("--passwordenv"),
                               QStringLiteral("OMAPASS_BW_PASSWORD"), QStringLiteral("--raw")},
                              Secret(), QByteArray(), passwordEnv);
    if (!result.success) {
        *error = classifyBwError(result.err) == BwLoginError::WrongPassword
            ? I18n::t(QStringLiteral("backend.wrong_password"))
            : result.err;
        return false;
    }

    *session = Secret(result.out.trimmed());
    wipe(&result.out);
    return true;
}

BwStatus BitwardenVault::status() {
    QFile file(BwCache::defaultPath());
    if (!file.exists()) {
        BwStatus status;
        status.status = QStringLiteral("unauthenticated");
        return status;
    }
    if (file.open(QIODevice::ReadOnly)) {
        // The file also holds bw's tokens; nothing but the account record is
        // read, and the buffer is wiped straight after.
        QByteArray content = file.readAll();
        const BwStatus status = parseBwDataFile(content);
        content.fill('\0');
        if (!status.status.isEmpty())
            return status;
    }

    const ProcResult result = runBw({QStringLiteral("status")}, Secret());
    return result.success ? parseBwStatus(result.out) : BwStatus();
}

bool BitwardenVault::logout(QString *error) {
    const ProcResult result = runBw({QStringLiteral("logout")}, Secret());

    // bw's own view settles it, not the exit code.
    if (!status().loggedIn())
        return true;

    *error = result.err.trimmed().isEmpty() ? I18n::t(QStringLiteral("bitwarden.logout_failed"))
                                            : result.err.trimmed();
    return false;
}

BitwardenVault *BitwardenVault::unlock(const QString &email, const Secret &password, QString *error) {
    const BwStatus current = status();
    if (!current.loggedIn()) {
        *error = I18n::t(QStringLiteral("bitwarden.not_logged_in"));
        return nullptr;
    }

    const QString account = current.userEmail.isEmpty() ? email : current.userEmail;

    if (const std::optional<BwCache> cache = BwCache::load()) {
        QHash<QString, QJsonObject> items;
        QHash<QString, QString> folders;
        switch (cache->decrypt(password, &items, &folders)) {
        case BwCache::Result::Ok: {
            auto *vault = new BitwardenVault(account, Secret());
            vault->m_password = password;
            vault->m_index = buildBwIndex(items, folders);
            vault->m_items = std::move(items);
            vault->m_folders = std::move(folders);
            return vault;
        }
        case BwCache::Result::WrongPassword:
            *error = I18n::t(QStringLiteral("backend.wrong_password"));
            return nullptr;
        case BwCache::Result::Unsupported:
            break; // bw knows its own format: let it do the work
        }
    }

    Secret session;
    if (!unlockSession(password, &session, error))
        return nullptr;
    return openWithSession(account, session, error);
}

BitwardenVault *BitwardenVault::openWithSession(const QString &email, const Secret &session,
                                                QString *error) {
    auto *vault = new BitwardenVault(email, session);
    if (!vault->reload(error)) {
        delete vault;
        return nullptr;
    }
    return vault;
}

bool BitwardenVault::ensureSession(QString *error) {
    if (!m_session.isEmpty())
        return true;

    Secret session;
    const bool ok = unlockSession(m_password, &session, error);
    m_password.clear();
    if (ok)
        m_session = session;
    return ok;
}

bool BitwardenVault::requireSession(QString *error) const {
    if (!m_session.isEmpty())
        return true;
    *error = I18n::t(QStringLiteral("bitwarden.no_session"));
    return false;
}

bool BitwardenVault::sync(QString *error) {
    if (!ensureSession(error))
        return false;

    const ProcResult result = runBw({QStringLiteral("sync")}, m_session);
    if (!result.success) {
        *error = result.err;
        return false;
    }
    return reload(error);
}

bool BitwardenVault::reload(QString *error) const {
    QVector<ProcResult> results = runBwParallel(
        {{QStringLiteral("list"), QStringLiteral("items")}, {QStringLiteral("list"), QStringLiteral("folders")}},
        m_session);
    ProcResult &items = results[0];
    const ProcResult &folders = results[1];

    if (!items.success || !folders.success) {
        *error = !items.success ? items.err : folders.err;
        wipe(&items.out);
        return false;
    }

    QByteArray itemsJson = items.out.toUtf8();
    wipe(&items.out);
    QHash<QString, QJsonObject> parsedItems = parseBwItems(itemsJson);
    itemsJson.fill('\0');
    QHash<QString, QString> parsedFolders = parseBwFolders(folders.out.toUtf8());
    BwIndex index = buildBwIndex(parsedItems, parsedFolders);

    const QMutexLocker locker(&m_mutex);
    m_items = std::move(parsedItems);
    m_folders = std::move(parsedFolders);
    m_index = std::move(index);
    return true;
}

void BitwardenVault::storeItem(const QByteArray &itemJson) const {
    const QJsonObject item = QJsonDocument::fromJson(itemJson).object();
    const QString id = item.value(QStringLiteral("id")).toString();
    if (id.isEmpty())
        return;

    const QMutexLocker locker(&m_mutex);
    m_items.insert(id, item);
    m_index = buildBwIndex(m_items, m_folders);
}

void BitwardenVault::storeFolder(const QByteArray &folderJson) const {
    const QJsonObject folder = QJsonDocument::fromJson(folderJson).object();
    const QString id = folder.value(QStringLiteral("id")).toString();
    const QString name = folder.value(QStringLiteral("name")).toString();
    if (id.isEmpty() || name.isEmpty())
        return;

    const QMutexLocker locker(&m_mutex);
    m_folders.insert(id, name);
    m_index = buildBwIndex(m_items, m_folders);
}

bool BitwardenVault::lookup(const QString &entryPath, BwItemRef *ref, QJsonObject *item,
                            QString *error) const {
    const QMutexLocker locker(&m_mutex);
    if (!m_index.items.contains(entryPath)) {
        *error = I18n::t(QStringLiteral("bitwarden.entry_not_found"), QStringLiteral("entry"), entryPath);
        return false;
    }
    *ref = m_index.items.value(entryPath);
    if (item)
        *item = m_items.value(ref->id);
    return true;
}

bool BitwardenVault::ensureFolder(const QString &group, QString *folderId, QString *error) const {
    if (!requireSession(error))
        return false;
    if (group.isEmpty()) {
        folderId->clear();
        return true;
    }
    {
        const QMutexLocker locker(&m_mutex);
        if (m_index.folders.contains(group)) {
            *folderId = m_index.folders.value(group);
            return true;
        }
    }

    const ProcResult result = runBwWithJson({QStringLiteral("create"), QStringLiteral("folder")},
                                            m_session, bwFolderJson(group));
    if (!result.success) {
        *error = result.err;
        return false;
    }

    const QByteArray folderJson = result.out.toUtf8();
    *folderId = QJsonDocument::fromJson(folderJson).object().value(QStringLiteral("id")).toString();
    storeFolder(folderJson);
    return true;
}

void BitwardenVault::list(QStringList *entries, QStringList *groups) const {
    {
        const QMutexLocker locker(&m_mutex);
        *entries = m_index.entries;
        *groups = m_index.groups;
    }
    appendEmptyGroups(*groups, entries);
}

QString BitwardenVault::titleFor(const QString &entryPath, const QString &fallback) const {
    const QMutexLocker locker(&m_mutex);
    const QString name = m_index.items.value(entryPath).name;
    return name.isEmpty() ? fallback : name;
}

bool BitwardenVault::fetchPassword(const QString &entryPath, Secret *password, QString *error) const {
    EntryData data;
    if (!fetchEntry(entryPath, &data, error))
        return false;
    *password = data.password;
    return true;
}

bool BitwardenVault::fetchEntry(const QString &entryPath, EntryData *data, QString *error) const {
    BwItemRef ref;
    QJsonObject item;
    if (!lookup(entryPath, &ref, &item, error))
        return false;
    *data = bwEntryData(item);
    return true;
}

bool BitwardenVault::addEntry(const QString &entryPath, const QString &group, const EntryData &data,
                              QString *error) const {
    QString folderId;
    if (!ensureFolder(group, &folderId, error))
        return false;

    ProcResult result =
        runBwWithJson({QStringLiteral("create"), QStringLiteral("item")}, m_session,
                      applyBwEntryData(QByteArray(), lastSegment(entryPath), folderId, data));
    if (!result.success) {
        *error = result.err;
        return false;
    }

    QByteArray created = result.out.toUtf8();
    wipe(&result.out);
    storeItem(created);
    created.fill('\0');
    return true;
}

bool BitwardenVault::editEntry(const QString &oldPath, const QString &newPath, const QString &group,
                               const EntryData &data, QString *error) const {
    BwItemRef ref;
    if (!lookup(oldPath, &ref, nullptr, error) || !requireSession(error))
        return false;

    // The item as bw has it, not the in-memory copy: that one only carries
    // the fields omapass shows, and editing from it would drop password
    // history, attachments, passkeys and the like.
    ProcResult current = runBw({QStringLiteral("get"), QStringLiteral("item"), ref.id}, m_session);
    if (!current.success) {
        *error = current.err;
        return false;
    }
    QByteArray itemJson = current.out.toUtf8();
    wipe(&current.out);

    QString folderId;
    if (!ensureFolder(group, &folderId, error)) {
        itemJson.fill('\0');
        return false;
    }

    // An untouched title keeps the real name: the path segment may carry a
    // look-alike slash or the id suffix that told duplicates apart.
    const QString title = lastSegment(newPath);
    const QString name = title == lastSegment(oldPath) ? ref.name : title;

    QByteArray updated = applyBwEntryData(itemJson, name, folderId, data);
    itemJson.fill('\0');

    ProcResult result = runBwWithJson({QStringLiteral("edit"), QStringLiteral("item"), ref.id},
                                      m_session, std::move(updated));
    if (!result.success) {
        *error = result.err;
        return false;
    }

    QByteArray edited = result.out.toUtf8();
    wipe(&result.out);
    storeItem(edited);
    edited.fill('\0');
    return true;
}

bool BitwardenVault::removeEntry(const QString &entryPath, QString *error) const {
    BwItemRef ref;
    if (!lookup(entryPath, &ref, nullptr, error) || !requireSession(error))
        return false;

    // Without --permanent the item goes to Bitwarden's trash, recoverable
    // from the web vault for 30 days.
    const ProcResult result = runBw({QStringLiteral("delete"), QStringLiteral("item"), ref.id}, m_session);
    if (!result.success) {
        *error = result.err;
        return false;
    }

    const QMutexLocker locker(&m_mutex);
    m_items.remove(ref.id);
    m_index = buildBwIndex(m_items, m_folders);
    return true;
}

bool BitwardenVault::renameGroup(const QString &oldGroup, const QString &newName, QString *error) const {
    const QString parent = parentGroup(oldGroup);
    const QString newGroup = parent.isEmpty() ? newName : parent + QLatin1Char('/') + newName;
    const QString oldPrefix = oldGroup + QLatin1Char('/');
    if (!requireSession(error))
        return false;

    QHash<QString, QString> folders;
    {
        const QMutexLocker locker(&m_mutex);
        folders = m_folders;
    }

    // Bitwarden nests by name alone, so renaming a group is renaming every
    // folder at or below it. A parent that exists only implicitly has no
    // folder of its own and is covered through its children. Each folder
    // renamed is stored as it goes, so a failure midway still leaves the
    // list showing what actually changed.
    for (auto it = folders.cbegin(); it != folders.cend(); ++it) {
        const QString &name = it.value();
        if (name != oldGroup && !name.startsWith(oldPrefix))
            continue;

        const ProcResult result =
            runBwWithJson({QStringLiteral("edit"), QStringLiteral("folder"), it.key()}, m_session,
                          bwFolderJson(newGroup + name.mid(oldGroup.size())));
        if (!result.success) {
            *error = result.err;
            return false;
        }
        storeFolder(result.out.toUtf8());
    }
    return true;
}

bool BitwardenVault::removeGroup(const QString &group, QString *error) const {
    QString folderId;
    {
        const QMutexLocker locker(&m_mutex);
        folderId = m_index.folders.value(group);
    }
    if (folderId.isEmpty())
        return true;
    if (!requireSession(error))
        return false;

    const ProcResult result = runBw({QStringLiteral("delete"), QStringLiteral("folder"), folderId},
                                    m_session);
    if (!result.success) {
        *error = result.err;
        return false;
    }

    const QMutexLocker locker(&m_mutex);
    m_folders.remove(folderId);
    m_index = buildBwIndex(m_items, m_folders);
    return true;
}

void BitwardenVault::close() {
    m_password.clear();

    // Opened from the local copy and locked before a session was ever made:
    // bw was never unlocked, so there is nothing to lock.
    if (m_session.isEmpty()) {
        const QMutexLocker locker(&m_mutex);
        m_items.clear();
        m_folders.clear();
        m_index = BwIndex();
        return;
    }

    // Detached: `bw lock` takes seconds, and nothing waits on it — neither
    // locking back to the database list nor quitting the app.
    QProcess process;
    process.setProcessEnvironment(bwEnvironment(m_session));
    process.setProgram(QStringLiteral("bw"));
    process.setArguments({QStringLiteral("lock")});
    process.setStandardOutputFile(QProcess::nullDevice());
    process.setStandardErrorFile(QProcess::nullDevice());
    // Detached processes otherwise inherit the terminal omapass was started
    // from, and a CLI that decides to ask something would ask it there.
    process.setStandardInputFile(QProcess::nullDevice());
    qint64 pid = 0;
    if (process.startDetached(&pid))
        pendingLockPid = pid;

    m_session.clear();
    const QMutexLocker locker(&m_mutex);
    m_items.clear();
    m_folders.clear();
    m_index = BwIndex();
}
