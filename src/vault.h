#pragma once

#include <QString>
#include <QStringList>
#include <QVector>

#include "secret.h"

// Abstraction over the supported password backends: KeePassXC (through
// `keepassxc-cli`, see keepassvault.h), pass (through gpg, see passvault.h)
// and Bitwarden (through `bw`, see bitwardenvault.h). The rest of the app only ever talks to Vault/DbRef, so no
// backend's command shapes leak into the interface.

enum class VaultKind { Keepass, Pass, Bitwarden };

// A database found by the search, before it is opened.
struct DbRef {
    QString path;
    VaultKind kind = VaultKind::Keepass;
};

// An entry's fields, as the union of what the two formats carry. `extra` is
// only used by the pass backend, to preserve lines it does not model (an OTP
// seed, say) when an entry that already had them is edited.
struct EntryData {
    QString username;
    Secret password;
    QString url;
    QString notes;
    QStringList extra;
};

// Result of one `keepassxc-cli` run.
struct KpResult {
    bool started = false;
    bool success = false;
    QString out;
    QString err;
};

// Runs `keepassxc-cli` with the given arguments, writing each item of
// `stdinLines` (database password, new password, confirmation…) as one line
// on stdin.
KpResult runKpcli(const QStringList &args, const QVector<Secret> &stdinLines);

// Tags every group with no entries or subgroups below it, so it still shows
// up in the list. Shared by backends whose listing does not mark empty
// groups on its own.
void appendEmptyGroups(const QStringList &groups, QStringList *entries);

// The group a group lives in (`Work/Mail` → `Work`), empty at the root.
QString parentGroup(const QString &group);

// Interface every backend implements. The static half finds, creates and
// opens databases; an opened Vault is always one concrete backend.
class Vault {
public:
    virtual ~Vault() = default;

    // Suffix marking an empty group in the entry list (`Work/[empty]`), so it
    // stays navigable — and deletable — even with nothing inside. Translated,
    // but always produced and matched through this one function (the locale
    // cannot change mid-run), so display and detection never drift apart.
    static QString emptyGroupSuffix();
    static QString kindLabel(VaultKind kind);
    // How a database is named in the list: the file or directory name, or
    // the account e-mail for Bitwarden.
    static QString displayName(const DbRef &ref);

    // Finds KeePassXC databases (.kdbx) and pass stores (any directory with a
    // .gpg-id) under `searchPath` — the same configurable directory for both,
    // so a store anywhere below it is found, not just ~/.password-store —
    // plus the Bitwarden account added through omapass, if any.
    static QVector<DbRef> findDatabases(const QString &searchPath);

    static bool createKeepassDatabase(const QString &name, const Secret &password,
                                      QString *createdPath, QString *error);

    // Opens and authenticates against `ref`, validating the password or
    // passphrase before handing back a usable Vault.
    static Vault *open(const DbRef &ref, const Secret &secret, QString *error);

    VaultKind kind() const { return m_kind; }
    QString path() const { return m_path; }

    // Lists entries and groups, tagging empty groups with the suffix above.
    virtual void list(QStringList *entries, QStringList *groups) const = 0;

    // An entry's display title. Under KeePassXC this can differ from the last
    // path segment (Title is its own attribute); under pass the title is
    // always the filename.
    virtual QString titleFor(const QString &entryPath, const QString &fallback) const = 0;

    // Fetches only the password, so copying does not pay for the other
    // attributes.
    virtual bool fetchPassword(const QString &entryPath, Secret *password,
                               QString *error) const = 0;
    virtual bool fetchEntry(const QString &entryPath, EntryData *data, QString *error) const = 0;

    virtual bool addEntry(const QString &entryPath, const QString &group, const EntryData &data,
                          QString *error) const = 0;
    // Edits the entry at `oldPath`, moving it to `newPath` when the path
    // changed (group and/or title).
    virtual bool editEntry(const QString &oldPath, const QString &newPath, const QString &group,
                           const EntryData &data, QString *error) const = 0;
    virtual bool removeEntry(const QString &entryPath, QString *error) const = 0;

    // Renames the last segment of `oldGroup` to `newName`, keeping the parent
    // group and everything below it intact.
    virtual bool renameGroup(const QString &oldGroup, const QString &newName,
                             QString *error) const = 0;
    virtual bool removeGroup(const QString &group, QString *error) const = 0;

    // Releases whatever the backend holds outside this process when the vault
    // is locked. Nothing to do for the file-based backends.
    virtual void close() {}

protected:
    Vault(VaultKind kind, const QString &path) : m_kind(kind), m_path(path) {}

private:
    VaultKind m_kind;
    QString m_path;
};
