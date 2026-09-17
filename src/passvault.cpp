#include "passvault.h"

#include "passstore.h"

namespace {

PassEntryData toPassData(const EntryData &data) {
    PassEntryData pd;
    pd.password = data.password;
    pd.username = data.username;
    pd.url = data.url;
    pd.extra = data.extra;
    return pd;
}

}

void PassVault::list(QStringList *entries, QStringList *groups) const {
    entries->clear();
    groups->clear();

    PassStore(path()).list(entries, groups);
    appendEmptyGroups(*groups, entries);
}

QString PassVault::titleFor(const QString &, const QString &fallback) const {
    return fallback;
}

bool PassVault::fetchPassword(const QString &entryPath, Secret *password, QString *error) const {
    PassEntryData data;
    if (!PassStore(path()).show(entryPath, m_passphrase, &data, error))
        return false;

    *password = data.password;
    return true;
}

bool PassVault::fetchEntry(const QString &entryPath, EntryData *data, QString *error) const {
    PassEntryData pd;
    if (!PassStore(path()).show(entryPath, m_passphrase, &pd, error))
        return false;

    data->username = pd.username;
    data->password = pd.password;
    data->url = pd.url;
    data->notes = pd.extra.join(QLatin1Char('\n'));
    data->extra = pd.extra;
    return true;
}

bool PassVault::addEntry(const QString &entryPath, const QString & /*group*/, const EntryData &data,
                         QString *error) const {
    return PassStore(path()).insert(entryPath, toPassData(data), error);
}

bool PassVault::editEntry(const QString &oldPath, const QString &newPath, const QString & /*group*/,
                          const EntryData &data, QString *error) const {
    const PassStore store(path());
    if (!store.insert(oldPath, toPassData(data), error))
        return false;
    if (newPath != oldPath)
        return store.move(oldPath, newPath, error);
    return true;
}

bool PassVault::removeEntry(const QString &entryPath, QString *error) const {
    return PassStore(path()).remove(entryPath, error);
}

bool PassVault::renameGroup(const QString &oldGroup, const QString &newName, QString *error) const {
    const QString parent = parentGroup(oldGroup);
    const QString newGroup = parent.isEmpty() ? newName : parent + QLatin1Char('/') + newName;

    return PassStore(path()).move(oldGroup, newGroup, error);
}

bool PassVault::removeGroup(const QString &group, QString *error) const {
    return PassStore(path()).removeGroup(group, error);
}
