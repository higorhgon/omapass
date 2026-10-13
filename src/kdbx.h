#pragma once

#include <QByteArray>
#include <QList>
#include <QString>
#include <QStringList>

#include <memory>

#include "secret.h"

// A KeePass database (.kdbx, formats 3.1 and 4) read and written in-process,
// with Botan for the cryptography. The XML is kept as a tree and edited in
// place, so everything omapass does not model (history, custom fields,
// attachments, icons, custom data…) is written back as it was.
//
// Opened with a password only: key files and hardware keys are not
// supported. Paths are the group names joined with "/", the root group left
// out, and the entry title last — the spelling `keepassxc-cli` used.

// What the entry form shows.
struct KdbxEntry {
    QString title;
    QString username;
    Secret password;
    QString url;
    QString notes;
};

enum class KdbxStatus {
    Ok,
    WrongPassword,   // the key did not open the database
    Unreadable,      // the file is missing or cannot be read
    Corrupt,         // not a KeePass database, or damaged
    Unsupported,     // a cipher, KDF or format version omapass does not do
};

class KdbxDatabase {
public:
    ~KdbxDatabase();
    KdbxDatabase(const KdbxDatabase &) = delete;
    KdbxDatabase &operator=(const KdbxDatabase &) = delete;

    // Opens `path`. On failure the result is null and `status` says why;
    // `detail` carries a short technical reason for the unsupported cases.
    static std::unique_ptr<KdbxDatabase> open(const QString &path, const Secret &password,
                                              KdbxStatus *status, QString *detail = nullptr);
    // A new, empty database: KDBX 4, AES-256, Argon2d, recycle bin on.
    // `legacy` makes a KDBX 3.1 one (AES-KDF), which exists to exercise that
    // format; nothing in the app asks for it.
    static std::unique_ptr<KdbxDatabase> create(const Secret &password, const QString &name,
                                                bool legacy = false);

    // Writes the database to `path`, in the format it was read in, replacing
    // the file only once the new one is complete. Empty on success, or the
    // error.
    QString save(const QString &path);

    // The tree flattened: every entry's path and every group's path.
    void list(QStringList *entries, QStringList *groups) const;

    bool entry(const QString &path, KdbxEntry *entry) const;
    // Every entry with its path, for exporting. Entries in the recycle bin
    // are left out unless asked for.
    QList<QPair<QString, KdbxEntry>> allEntries(bool includeRecycled = true) const;

    // The mutating calls return an empty string on success, or the error.
    // `group` is the destination group path ("" is the root) and is created
    // when it does not exist. The title is the entry's own.
    QString addEntry(const QString &group, const KdbxEntry &entry);
    QString editEntry(const QString &oldPath, const QString &group, const KdbxEntry &entry);
    // To the recycle bin when the database has one on, deleted otherwise.
    QString removeEntry(const QString &path);
    QString renameGroup(const QString &oldPath, const QString &newName);
    QString removeGroup(const QString &path);

private:
    class Impl;
    explicit KdbxDatabase(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> d;
};
