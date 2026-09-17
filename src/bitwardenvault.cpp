#include "bitwardenvault.h"

#include "i18n.h"
#include "process.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QSettings>
#include <QStandardPaths>

namespace {

const auto accountSetting = QStringLiteral("bitwarden/account");
const auto refPrefix = QStringLiteral("bitwarden:");

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

ProcResult runBw(const QStringList &args, const Secret &session,
                 const QByteArray &stdinData = QByteArray(),
                 const QProcessEnvironment &extraEnv = QProcessEnvironment()) {
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("BW_NOINTERACTION"), QStringLiteral("true"));
    if (!session.isEmpty())
        env.insert(QStringLiteral("BW_SESSION"), session.toString());
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

BwStatus BitwardenVault::status() {
    const ProcResult result = runBw({QStringLiteral("status")}, Secret());
    return result.success ? parseBwStatus(result.out) : BwStatus();
}

void BitwardenVault::logout() {
    runBw({QStringLiteral("logout")}, Secret());
}

BitwardenVault *BitwardenVault::unlock(const QString &email, const Secret &password, QString *error) {
    const BwStatus current = status();
    if (!current.loggedIn()) {
        *error = I18n::t(QStringLiteral("bitwarden.not_logged_in"));
        return nullptr;
    }

    QProcessEnvironment passwordEnv;
    passwordEnv.insert(QStringLiteral("OMAPASS_BW_PASSWORD"), password.toString());
    ProcResult result = runBw({QStringLiteral("unlock"), QStringLiteral("--passwordenv"),
                               QStringLiteral("OMAPASS_BW_PASSWORD"), QStringLiteral("--raw")},
                              Secret(), QByteArray(), passwordEnv);
    if (!result.success) {
        *error = classifyBwError(result.err) == BwLoginError::WrongPassword
            ? I18n::t(QStringLiteral("backend.wrong_password"))
            : result.err;
        return nullptr;
    }

    const Secret session(result.out.trimmed());
    wipe(&result.out);
    return openWithSession(current.userEmail.isEmpty() ? email : current.userEmail, session, error);
}

BitwardenVault *BitwardenVault::openWithSession(const QString &email, const Secret &session,
                                                QString *error) {
    auto *vault = new BitwardenVault(email, session);
    if (!vault->reload(true, error)) {
        delete vault;
        return nullptr;
    }
    return vault;
}

bool BitwardenVault::reload(bool sync, QString *error) const {
    if (sync) {
        // Offline is not fatal: bw still has the last copy it synced.
        runBw({QStringLiteral("sync")}, m_session);
    }

    ProcResult items = runBw({QStringLiteral("list"), QStringLiteral("items")}, m_session);
    if (!items.success) {
        *error = items.err;
        return false;
    }
    const ProcResult folders = runBw({QStringLiteral("list"), QStringLiteral("folders")}, m_session);
    if (!folders.success) {
        wipe(&items.out);
        *error = folders.err;
        return false;
    }

    // The item list carries every password in the vault: it is dropped as
    // soon as the index (which keeps none) is built.
    QByteArray itemsJson = items.out.toUtf8();
    wipe(&items.out);
    m_index = buildBwIndex(itemsJson, folders.out.toUtf8());
    itemsJson.fill('\0');
    return true;
}

bool BitwardenVault::lookup(const QString &entryPath, BwItemRef *ref, QString *error) const {
    if (!m_index.items.contains(entryPath)) {
        *error = I18n::t(QStringLiteral("bitwarden.entry_not_found"), QStringLiteral("entry"), entryPath);
        return false;
    }
    *ref = m_index.items.value(entryPath);
    return true;
}

bool BitwardenVault::ensureFolder(const QString &group, QString *folderId, QString *error) const {
    if (group.isEmpty()) {
        folderId->clear();
        return true;
    }
    if (m_index.folders.contains(group)) {
        *folderId = m_index.folders.value(group);
        return true;
    }

    const ProcResult result = runBwWithJson({QStringLiteral("create"), QStringLiteral("folder")},
                                            m_session, bwFolderJson(group));
    if (!result.success) {
        *error = result.err;
        return false;
    }

    *folderId = QJsonDocument::fromJson(result.out.toUtf8()).object().value(QStringLiteral("id")).toString();
    m_index.folders.insert(group, *folderId);
    return true;
}

void BitwardenVault::list(QStringList *entries, QStringList *groups) const {
    *entries = m_index.entries;
    *groups = m_index.groups;
    appendEmptyGroups(*groups, entries);
}

QString BitwardenVault::titleFor(const QString &entryPath, const QString &fallback) const {
    const QString name = m_index.items.value(entryPath).name;
    return name.isEmpty() ? fallback : name;
}

bool BitwardenVault::fetchPassword(const QString &entryPath, Secret *password, QString *error) const {
    BwItemRef ref;
    if (!lookup(entryPath, &ref, error))
        return false;

    ProcResult result = runBw({QStringLiteral("get"), QStringLiteral("password"), ref.id}, m_session);
    if (!result.success) {
        *error = result.err;
        return false;
    }

    QString text = result.out;
    wipe(&result.out);
    while (text.endsWith(QLatin1Char('\n')) || text.endsWith(QLatin1Char('\r')))
        text.chop(1);
    *password = Secret(text);
    wipe(&text);
    return true;
}

bool BitwardenVault::fetchEntry(const QString &entryPath, EntryData *data, QString *error) const {
    BwItemRef ref;
    if (!lookup(entryPath, &ref, error))
        return false;

    ProcResult result = runBw({QStringLiteral("get"), QStringLiteral("item"), ref.id}, m_session);
    if (!result.success) {
        *error = result.err;
        return false;
    }

    QByteArray json = result.out.toUtf8();
    wipe(&result.out);
    const QJsonObject item = QJsonDocument::fromJson(json).object();
    json.fill('\0');

    const QJsonObject login = item.value(QStringLiteral("login")).toObject();
    const QJsonArray uris = login.value(QStringLiteral("uris")).toArray();
    data->username = login.value(QStringLiteral("username")).toString();
    data->password = Secret(login.value(QStringLiteral("password")).toString());
    data->url = uris.isEmpty() ? QString()
                               : uris.first().toObject().value(QStringLiteral("uri")).toString();
    data->notes = item.value(QStringLiteral("notes")).toString();
    data->extra.clear();
    return true;
}

bool BitwardenVault::addEntry(const QString &entryPath, const QString &group, const EntryData &data,
                              QString *error) const {
    QString folderId;
    if (!ensureFolder(group, &folderId, error))
        return false;

    const ProcResult result =
        runBwWithJson({QStringLiteral("create"), QStringLiteral("item")}, m_session,
                      applyBwEntryData(QByteArray(), lastSegment(entryPath), folderId, data));
    if (!result.success) {
        *error = result.err;
        return false;
    }
    return reload(false, error);
}

bool BitwardenVault::editEntry(const QString &oldPath, const QString &newPath, const QString &group,
                               const EntryData &data, QString *error) const {
    BwItemRef ref;
    if (!lookup(oldPath, &ref, error))
        return false;

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

    const ProcResult result = runBwWithJson({QStringLiteral("edit"), QStringLiteral("item"), ref.id},
                                            m_session, std::move(updated));
    if (!result.success) {
        *error = result.err;
        return false;
    }
    return reload(false, error);
}

bool BitwardenVault::removeEntry(const QString &entryPath, QString *error) const {
    BwItemRef ref;
    if (!lookup(entryPath, &ref, error))
        return false;

    // Without --permanent the item goes to Bitwarden's trash, recoverable
    // from the web vault for 30 days.
    const ProcResult result = runBw({QStringLiteral("delete"), QStringLiteral("item"), ref.id}, m_session);
    if (!result.success) {
        *error = result.err;
        return false;
    }
    return reload(false, error);
}

bool BitwardenVault::renameGroup(const QString &oldGroup, const QString &newName, QString *error) const {
    const QString parent = parentGroup(oldGroup);
    const QString newGroup = parent.isEmpty() ? newName : parent + QLatin1Char('/') + newName;
    const QString oldPrefix = oldGroup + QLatin1Char('/');

    // Bitwarden nests by name alone, so renaming a group is renaming every
    // folder at or below it. A parent that exists only implicitly has no
    // folder of its own and is covered through its children.
    for (auto it = m_index.folders.cbegin(); it != m_index.folders.cend(); ++it) {
        const QString &name = it.key();
        if (name != oldGroup && !name.startsWith(oldPrefix))
            continue;

        const ProcResult result =
            runBwWithJson({QStringLiteral("edit"), QStringLiteral("folder"), it.value()}, m_session,
                          bwFolderJson(newGroup + name.mid(oldGroup.size())));
        if (!result.success) {
            *error = result.err;
            // Folders renamed before the failure stay renamed; the list has
            // to show that rather than the tree as it was.
            QString ignored;
            reload(false, &ignored);
            return false;
        }
    }
    return reload(false, error);
}

bool BitwardenVault::removeGroup(const QString &group, QString *error) const {
    const QString folderId = m_index.folders.value(group);
    if (folderId.isEmpty())
        return reload(false, error);

    const ProcResult result = runBw({QStringLiteral("delete"), QStringLiteral("folder"), folderId},
                                    m_session);
    if (!result.success) {
        *error = result.err;
        return false;
    }
    return reload(false, error);
}

void BitwardenVault::close() {
    runBw({QStringLiteral("lock")}, m_session);
    m_session.clear();
}
