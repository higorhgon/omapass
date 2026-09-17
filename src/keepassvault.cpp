#include "keepassvault.h"

void KeepassVault::list(QStringList *entries, QStringList *groups) const {
    entries->clear();
    groups->clear();

    const KpResult result = runKpcli({QStringLiteral("ls"), QStringLiteral("-Rfq"), path()},
                                     {m_password});
    if (!result.success)
        return;

    QStringList lines;
    const auto rawLines = result.out.split(QLatin1Char('\n'));
    for (const QString &raw : rawLines) {
        const QString line = raw.trimmed();
        if (line.isEmpty())
            continue;
        lines.append(line);
        if (line.endsWith(QLatin1Char('/')))
            groups->append(line.chopped(1));
        else
            entries->append(line);
    }

    // `ls -Rfq` lists a group both as "Work/" and through its children,
    // so emptiness is decided against the raw listing rather than the
    // split lists.
    for (const QString &group : std::as_const(*groups)) {
        const QString prefix = group + QLatin1Char('/');
        const bool isEmpty = !std::any_of(lines.cbegin(), lines.cend(),
                                          [&prefix](const QString &line) {
            return line.startsWith(prefix) && line != prefix;
        });
        if (isEmpty)
            entries->append(group + emptyGroupSuffix());
    }
}

QString KeepassVault::titleFor(const QString &entryPath, const QString &fallback) const {
    const KpResult result = runKpcli({QStringLiteral("show"), QStringLiteral("-q"), path(), entryPath,
                                      QStringLiteral("-a"), QStringLiteral("Title")},
                                     {m_password});
    const QString title = result.success ? result.out.trimmed() : QString();
    return title.isEmpty() ? fallback : title;
}

bool KeepassVault::fetchPassword(const QString &entryPath, Secret *password, QString *error) const {
    const KpResult result = runKpcli({QStringLiteral("show"), QStringLiteral("-q"), path(),
                                      entryPath, QStringLiteral("-a"), QStringLiteral("Password")},
                                     {m_password});
    if (!result.success) {
        *error = result.err;
        return false;
    }
    *password = Secret(result.out.trimmed());
    return true;
}

bool KeepassVault::fetchEntry(const QString &entryPath, EntryData *data, QString * /*error*/) const {
    const auto attribute = [this, &entryPath](const QString &name) {
        const KpResult result = runKpcli({QStringLiteral("show"), QStringLiteral("-q"), path(),
                                          entryPath, QStringLiteral("-a"), name},
                                         {m_password});
        return result.success ? result.out.trimmed() : QString();
    };

    data->username = attribute(QStringLiteral("UserName"));
    data->password = Secret(attribute(QStringLiteral("Password")));
    data->url = attribute(QStringLiteral("URL"));
    data->notes = attribute(QStringLiteral("Notes"));
    data->extra.clear();
    return true;
}

bool KeepassVault::addEntry(const QString &entryPath, const QString &group, const EntryData &data,
                            QString *error) const {
    if (!group.isEmpty())
        runKpcli({QStringLiteral("mkdir"), QStringLiteral("-q"), path(), group}, {m_password});

    const KpResult result = runKpcli({QStringLiteral("add"), QStringLiteral("-q"),
                                      QStringLiteral("-p"), QStringLiteral("-u"), data.username,
                                      QStringLiteral("--url"), data.url,
                                      QStringLiteral("--notes"), data.notes, path(), entryPath},
                                     {m_password, data.password, data.password});
    if (!result.success) {
        *error = result.err;
        return false;
    }
    return true;
}

bool KeepassVault::editEntry(const QString &oldPath, const QString &newPath, const QString &group,
                             const EntryData &data, QString *error) const {
    if (!group.isEmpty())
        runKpcli({QStringLiteral("mkdir"), QStringLiteral("-q"), path(), group}, {m_password});

    if (newPath != oldPath) {
        // keepassxc-cli's `mv` takes [database] [source] [target group];
        // the root is spelled "/".
        const QString destination = group.isEmpty() ? QStringLiteral("/") : group;
        runKpcli({QStringLiteral("mv"), QStringLiteral("-q"), path(), oldPath, destination},
                 {m_password});
    }

    const KpResult result = runKpcli({QStringLiteral("edit"), QStringLiteral("-q"),
                                      QStringLiteral("-p"), QStringLiteral("-u"), data.username,
                                      QStringLiteral("--url"), data.url,
                                      QStringLiteral("--notes"), data.notes, path(), newPath},
                                     {m_password, data.password, data.password});
    if (!result.success) {
        *error = result.err;
        return false;
    }
    return true;
}

bool KeepassVault::removeEntry(const QString &entryPath, QString *error) const {
    const KpResult result = runKpcli({QStringLiteral("rm"), QStringLiteral("-q"), path(), entryPath},
                                     {m_password});
    if (!result.success) {
        *error = result.err;
        return false;
    }
    return true;
}

bool KeepassVault::renameGroup(const QString &oldGroup, const QString &newName, QString *error) const {
    const QString parent = parentGroup(oldGroup);
    const QString newGroup = parent.isEmpty() ? newName : parent + QLatin1Char('/') + newName;

    // keepassxc-cli has no native group rename: rebuild the subtree under the
    // new name, move each entry across keeping its relative path, then delete
    // the old (now empty) tree from the leaves up.
    QStringList entries;
    QStringList groups;
    list(&entries, &groups);
    const QString oldPrefix = oldGroup + QLatin1Char('/');

    // Every step is checked and aborts on the first failure: this is
    // multi-step (a sequence of mkdir/mv), so swallowing an error midway
    // would leave the group tree half-rebuilt.
    const auto mkdir = [this, error](const QString &group) {
        const KpResult result = runKpcli({QStringLiteral("mkdir"), QStringLiteral("-q"), path(), group},
                                         {m_password});
        if (!result.success) {
            *error = result.err;
            return false;
        }
        return true;
    };
    const auto move = [this, error](const QString &source, const QString &destinationGroup) {
        const KpResult result = runKpcli({QStringLiteral("mv"), QStringLiteral("-q"), path(), source,
                                          destinationGroup},
                                         {m_password});
        if (!result.success) {
            *error = result.err;
            return false;
        }
        return true;
    };

    // The new group is always created, even when `oldGroup` has no children —
    // otherwise an empty group would simply vanish, since the mkdir/mv calls
    // below only build destinations for content that actually exists.
    if (!mkdir(newGroup))
        return false;

    for (const QString &group : std::as_const(groups)) {
        if (!group.startsWith(oldPrefix))
            continue;
        if (!mkdir(newGroup + QLatin1Char('/') + group.mid(oldPrefix.size())))
            return false;
    }

    const QString suffix = emptyGroupSuffix();
    for (const QString &entry : std::as_const(entries)) {
        if (entry.endsWith(suffix) || !entry.startsWith(oldPrefix))
            continue;

        const QString relative = entry.mid(oldPrefix.size());
        const int slash = relative.lastIndexOf(QLatin1Char('/'));
        const QString destination = slash < 0
            ? newGroup
            : newGroup + QLatin1Char('/') + relative.left(slash);

        if (!mkdir(destination) || !move(entry, destination))
            return false;
    }

    QStringList oldTree;
    for (const QString &group : std::as_const(groups)) {
        if (group == oldGroup || group.startsWith(oldPrefix))
            oldTree.append(group);
    }
    std::sort(oldTree.begin(), oldTree.end(), [](const QString &a, const QString &b) {
        return a.size() > b.size();
    });
    for (const QString &group : std::as_const(oldTree)) {
        const KpResult result = runKpcli({QStringLiteral("rmdir"), QStringLiteral("-q"), path(), group},
                                         {m_password});
        if (!result.success) {
            *error = result.err;
            return false;
        }
    }

    return true;
}

bool KeepassVault::removeGroup(const QString &group, QString *error) const {
    const KpResult result = runKpcli({QStringLiteral("rmdir"), QStringLiteral("-q"), path(), group},
                                     {m_password});
    if (!result.success) {
        *error = result.err;
        return false;
    }
    return true;
}
