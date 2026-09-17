#include "vault.h"

#include "config.h"
#include "i18n.h"
#include "keepassvault.h"
#include "passstore.h"
#include "passvault.h"
#include "process.h"

#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>

namespace {

QString keepassDatabaseDir() {
    return Config::configDir() + QStringLiteral("/databases");
}

// Finds files matching `pattern` under `path`. Prefers `fd`, which is what
// omapass has always used and is markedly faster over a whole home directory;
// falls back to walking the tree when it is not installed.
QStringList findFiles(const QString &pattern, const QString &path, bool includeHidden) {
    QStringList results;

    QStringList args;
    if (includeHidden)
        args << QStringLiteral("--hidden") << QStringLiteral("--no-ignore");
    args << pattern << path;

    const ProcResult fd = runProcess(QStringLiteral("fd"), args);
    if (fd.started) {
        const auto lines = fd.out.split(QLatin1Char('\n'));
        for (const QString &line : lines) {
            const QString trimmed = line.trimmed();
            if (!trimmed.isEmpty())
                results.append(trimmed);
        }
        return results;
    }

    QDir::Filters filters = QDir::Files | QDir::NoDotAndDotDot;
    if (includeHidden)
        filters |= QDir::Hidden;

    QDirIterator it(path, filters, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        if (QRegularExpression(pattern).match(it.fileName()).hasMatch())
            results.append(it.filePath());
    }
    return results;
}

// Roots of pass stores: the parent directory of every .gpg-id found. A
// narrower-scope .gpg-id inside a store already found is not a database of
// its own — only the outermost root is kept.
QStringList findPassStores(const QString &searchPath) {
    QStringList roots;
    const QStringList markers = findFiles(QStringLiteral("^\\.gpg-id$"), searchPath, true);
    for (const QString &marker : markers) {
        const QString parent = QFileInfo(marker).absolutePath();
        if (!roots.contains(parent))
            roots.append(parent);
    }
    roots.sort();

    const QStringList all = roots;
    QStringList outermost;
    for (const QString &root : all) {
        const bool nested = std::any_of(all.cbegin(), all.cend(), [&root](const QString &other) {
            return other != root && root.startsWith(other + QLatin1Char('/'));
        });
        if (!nested)
            outermost.append(root);
    }
    return outermost;
}

}

KpResult runKpcli(const QStringList &args, const QVector<Secret> &stdinLines) {
    QByteArray stdinData;
    for (const Secret &line : stdinLines)
        stdinData.append(line.bytes()).append('\n');

    const ProcResult result = runProcess(QStringLiteral("keepassxc-cli"), args, stdinData);
    stdinData.fill('\0');

    KpResult kp;
    kp.started = result.started;
    kp.success = result.success;
    kp.out = result.out;
    kp.err = result.started
        ? result.err
        : I18n::t(QStringLiteral("keepass.spawn_error"), QStringLiteral("err"), result.err);
    return kp;
}

void appendEmptyGroups(const QStringList &groups, QStringList *entries) {
    for (const QString &group : groups) {
        const QString prefix = group + QLatin1Char('/');
        const bool hasChildren =
            std::any_of(entries->cbegin(), entries->cend(),
                        [&prefix](const QString &e) { return e.startsWith(prefix); })
            || std::any_of(groups.cbegin(), groups.cend(),
                           [&prefix](const QString &g) { return g.startsWith(prefix); });
        if (!hasChildren)
            entries->append(group + Vault::emptyGroupSuffix());
    }
}

QString parentGroup(const QString &group) {
    const int slash = group.lastIndexOf(QLatin1Char('/'));
    return slash < 0 ? QString() : group.left(slash);
}

QString Vault::emptyGroupSuffix() {
    return QLatin1Char('/') + I18n::t(QStringLiteral("common.empty_group_marker"));
}

QString Vault::kindLabel(VaultKind kind) {
    return kind == VaultKind::Keepass ? QStringLiteral("KeePassXC") : QStringLiteral("pass");
}

QVector<DbRef> Vault::findDatabases(const QString &searchPath) {
    QVector<DbRef> databases;

    QStringList kdbx = findFiles(QStringLiteral(".kdbx$"), searchPath, false);
    kdbx += findFiles(QStringLiteral(".kdbx$"), keepassDatabaseDir(), false);
    kdbx.sort();
    kdbx.removeDuplicates();
    for (const QString &path : kdbx)
        databases.append({path, VaultKind::Keepass});

    QStringList stores = findPassStores(searchPath);

    // The conventional location is always considered, even when `path` was
    // customised to somewhere that does not contain it.
    const QString defaultStore = QDir::homePath() + QStringLiteral("/.password-store");
    if (PassStore::isStore(defaultStore) && !stores.contains(defaultStore))
        stores.append(defaultStore);

    for (const QString &root : stores)
        databases.append({root, VaultKind::Pass});

    return databases;
}

bool Vault::createKeepassDatabase(const QString &name, const Secret &password,
                                  QString *createdPath, QString *error) {
    const QString dir = keepassDatabaseDir();
    if (!QDir().mkpath(dir)) {
        *error = I18n::t(QStringLiteral("keepass.mkdir_error"), QStringLiteral("err"), dir);
        return false;
    }

    const QString path = dir + QLatin1Char('/') + name + QStringLiteral(".kdbx");
    if (QFile::exists(path)) {
        *error = I18n::t(QStringLiteral("keepass.file_exists"));
        return false;
    }

    const KpResult result = runKpcli({QStringLiteral("db-create"), QStringLiteral("-p"), path},
                                     {password, password});
    if (!result.success) {
        *error = result.err;
        return false;
    }

    *createdPath = path;
    return true;
}

Vault *Vault::open(const DbRef &ref, const Secret &secret, QString *error) {
    if (ref.kind == VaultKind::Keepass) {
        const KpResult result = runKpcli({QStringLiteral("ls"), QStringLiteral("-q"), ref.path},
                                         {secret});
        if (!result.started) {
            *error = result.err;
            return nullptr;
        }
        if (!result.success) {
            *error = I18n::t(QStringLiteral("backend.wrong_password"));
            return nullptr;
        }
        return new KeepassVault(ref.path, secret);
    }

    if (!PassStore::isStore(ref.path)) {
        *error = I18n::t(QStringLiteral("pass.store_not_initialized"), QStringLiteral("path"), ref.path);
        return nullptr;
    }

    const PassStore store(ref.path);
    if (!store.verifyPassphrase(secret, error))
        return nullptr;

    return new PassVault(ref.path, secret);
}
