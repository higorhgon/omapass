#include "keepassvault.h"

#include <QFileInfo>
#include <QMutexLocker>

#include <algorithm>

#include "i18n.h"

namespace {

QString lastSegment(const QString &path) {
    const int slash = path.lastIndexOf(QLatin1Char('/'));
    return slash < 0 ? path : path.mid(slash + 1);
}

}  // namespace

QString KeepassVault::openError(KdbxStatus status, const QString &detail) {
    switch (status) {
    case KdbxStatus::WrongPassword:
        return I18n::t(QStringLiteral("backend.wrong_password"));
    case KdbxStatus::Unreadable:
        return I18n::t(QStringLiteral("keepass.unreadable"), QStringLiteral("err"), detail);
    case KdbxStatus::Unsupported:
        return I18n::t(QStringLiteral("keepass.unsupported"), QStringLiteral("detail"), detail);
    case KdbxStatus::Corrupt:
    case KdbxStatus::Ok:
        break;
    }
    return I18n::t(QStringLiteral("keepass.corrupt"));
}

KeepassVault::KeepassVault(const QString &path, const Secret &password, std::unique_ptr<KdbxDatabase> db)
    : Vault(VaultKind::Keepass, path), m_password(password), m_db(std::move(db)) {
    stamp();
}

KeepassVault *KeepassVault::unlock(const QString &path, const Secret &password, QString *error) {
    KdbxStatus status = KdbxStatus::Corrupt;
    QString detail;
    std::unique_ptr<KdbxDatabase> db = KdbxDatabase::open(path, password, &status, &detail);
    if (!db) {
        *error = openError(status, detail);
        return nullptr;
    }
    return new KeepassVault(path, password, std::move(db));
}

void KeepassVault::stamp() const {
    const QFileInfo info(path());
    m_modified = info.lastModified();
    m_size = info.size();
}

bool KeepassVault::refresh(QString *error) const {
    const QFileInfo info(path());
    if (info.lastModified() == m_modified && info.size() == m_size)
        return true;

    KdbxStatus status = KdbxStatus::Corrupt;
    QString detail;
    std::unique_ptr<KdbxDatabase> db = KdbxDatabase::open(path(), m_password, &status, &detail);
    if (!db) {
        *error = openError(status, detail);
        return false;
    }
    m_db = std::move(db);
    stamp();
    return true;
}

// Reads memory back from the file, throwing away whatever an operation did
// before it failed, so that the next successful one does not save it.
void KeepassVault::rollback() const {
    KdbxStatus status = KdbxStatus::Corrupt;
    if (std::unique_ptr<KdbxDatabase> db = KdbxDatabase::open(path(), m_password, &status)) {
        m_db = std::move(db);
        stamp();
    }
}

// Writes the in-memory database. When that fails the file is left as it was,
// and memory is read back from it so the two do not drift.
bool KeepassVault::commit(QString *error) const {
    const QString failure = m_db->save(path());
    if (failure.isEmpty()) {
        stamp();
        return true;
    }
    *error = failure;
    rollback();
    return false;
}

// The outcome of an operation on the in-memory database: saved when it
// worked, rolled back when it did not.
bool KeepassVault::finish(const QString &failure, QString *error) const {
    if (failure.isEmpty())
        return commit(error);
    *error = failure;
    rollback();
    return false;
}

void KeepassVault::list(QStringList *entries, QStringList *groups) const {
    entries->clear();
    groups->clear();

    const QMutexLocker locker(&m_mutex);
    QString error;
    if (!refresh(&error))
        return;
    m_db->list(entries, groups);
    appendEmptyGroups(*groups, entries);
}

QHash<QString, EntryMeta> KeepassVault::entryMeta() const {
    QHash<QString, EntryMeta> meta;
    const QMutexLocker locker(&m_mutex);
    QString error;
    if (!refresh(&error))
        return meta;
    const auto all = m_db->allEntries();
    for (const auto &item : all) {
        EntryMeta entry;
        entry.username = item.second.username;
        entry.url = item.second.url;
        meta.insert(item.first, entry);
    }
    return meta;
}

QString KeepassVault::titleFor(const QString &entryPath, const QString &fallback) const {
    const QMutexLocker locker(&m_mutex);
    QString error;
    KdbxEntry entry;
    if (!refresh(&error) || !m_db->entry(entryPath, &entry) || entry.title.isEmpty())
        return fallback;
    return entry.title;
}

bool KeepassVault::fetchPassword(const QString &entryPath, Secret *password, QString *error) const {
    EntryData data;
    if (!fetchEntry(entryPath, &data, error))
        return false;
    *password = data.password;
    return true;
}

bool KeepassVault::fetchEntry(const QString &entryPath, EntryData *data, QString *error) const {
    const QMutexLocker locker(&m_mutex);
    if (!refresh(error))
        return false;

    KdbxEntry entry;
    if (!m_db->entry(entryPath, &entry)) {
        *error = I18n::t(QStringLiteral("keepass.entry_not_found"), QStringLiteral("entry"), entryPath);
        return false;
    }
    data->username = entry.username;
    data->password = entry.password;
    data->url = entry.url;
    data->notes = entry.notes;
    data->extra.clear();
    return true;
}

bool KeepassVault::addEntry(const QString &entryPath, const QString &group, const EntryData &data,
                            QString *error) const {
    const QMutexLocker locker(&m_mutex);
    if (!refresh(error))
        return false;

    KdbxEntry entry;
    entry.title = lastSegment(entryPath);
    entry.username = data.username;
    entry.password = data.password;
    entry.url = data.url;
    entry.notes = data.notes;

    return finish(m_db->addEntry(group, entry), error);
}

bool KeepassVault::editEntry(const QString &oldPath, const QString &newPath, const QString &group,
                             const EntryData &data, QString *error) const {
    const QMutexLocker locker(&m_mutex);
    if (!refresh(error))
        return false;

    KdbxEntry entry;
    entry.title = lastSegment(newPath);
    entry.username = data.username;
    entry.password = data.password;
    entry.url = data.url;
    entry.notes = data.notes;

    return finish(m_db->editEntry(oldPath, group, entry), error);
}

bool KeepassVault::removeEntry(const QString &entryPath, QString *error) const {
    const QMutexLocker locker(&m_mutex);
    if (!refresh(error))
        return false;
    return finish(m_db->removeEntry(entryPath), error);
}

bool KeepassVault::renameGroup(const QString &oldGroup, const QString &newName, QString *error) const {
    const QMutexLocker locker(&m_mutex);
    if (!refresh(error))
        return false;
    return finish(m_db->renameGroup(oldGroup, newName), error);
}

bool KeepassVault::removeGroup(const QString &group, QString *error) const {
    const QMutexLocker locker(&m_mutex);
    if (!refresh(error))
        return false;
    return finish(m_db->removeGroup(group), error);
}
