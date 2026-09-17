#pragma once

#include <QMutex>

#include "bitwardenjson.h"
#include "vault.h"

// Backend for a Bitwarden account, through the official `bw` CLI.
//
// Every `bw` run starts a Node program and takes a couple of seconds, so:
// - opening decrypts bw's own encrypted copy (data.json, see BwCache)
//   in-process, without running bw at all; only when that copy is in a shape
//   BwCache does not know does it go through `bw unlock` and `bw list`;
// - the whole vault is kept in memory while open, which makes copying,
//   viewing and editing instant;
// - writes update that copy from what `bw` returns instead of listing again;
// - the slow calls (unlock, sync, writes) are meant to be run off the GUI
//   thread — the cache is guarded for that.
//
// Security notes:
// - The session key lives in a `Secret` and only reaches `bw` through the
//   BW_SESSION variable of each child process, never argv.
// - The master password goes through --passwordenv, and item/folder JSON
//   (which carries the password) through stdin, so neither shows up in `ps`.
// - While the vault is open its items, passwords included, are held in
//   memory; they are dropped when it is locked.
// - Locking the vault runs `bw lock`, which also ends any session opened
//   with `bw unlock` in a terminal.
class BitwardenVault : public Vault {
public:
    static bool isAvailable();

    // The account added through omapass, remembered so it can be listed
    // without spawning `bw` at start-up. Empty when none.
    static QString rememberedAccount();
    static void rememberAccount(const QString &email);
    static void forgetAccount();

    static QString refPath(const QString &email);
    static QString emailOf(const QString &refPath);

    // Read from bw's data.json when possible (instant), falling back to
    // `bw status` (seconds) when the file is in a shape it does not know.
    static BwStatus status();
    static void logout();

    // Unlocks the logged-in account with the master password and loads it.
    static BitwardenVault *unlock(const QString &email, const Secret &password, QString *error);
    // Loads the account behind a session key `bw login` already handed back.
    static BitwardenVault *openWithSession(const QString &email, const Secret &session,
                                           QString *error);

    // Gets a bw session if opening did not need one, pulls from the server
    // and reloads. Opening skips all of it so the list shows up at once; the
    // caller runs this afterwards, in the background. Changes need the
    // session, so they wait for it.
    bool sync(QString *error);

    void list(QStringList *entries, QStringList *groups) const override;
    QString titleFor(const QString &entryPath, const QString &fallback) const override;
    bool fetchPassword(const QString &entryPath, Secret *password, QString *error) const override;
    bool fetchEntry(const QString &entryPath, EntryData *data, QString *error) const override;
    bool addEntry(const QString &entryPath, const QString &group, const EntryData &data,
                  QString *error) const override;
    bool editEntry(const QString &oldPath, const QString &newPath, const QString &group,
                   const EntryData &data, QString *error) const override;
    bool removeEntry(const QString &entryPath, QString *error) const override;
    bool renameGroup(const QString &oldGroup, const QString &newName, QString *error) const override;
    bool removeGroup(const QString &group, QString *error) const override;
    void close() override;

private:
    BitwardenVault(const QString &email, const Secret &session)
        : Vault(VaultKind::Bitwarden, refPath(email)), m_session(session) {}

    static bool unlockSession(const Secret &password, Secret *session, QString *error);
    bool reload(QString *error) const;
    bool ensureSession(QString *error);
    bool requireSession(QString *error) const;
    bool ensureFolder(const QString &group, QString *folderId, QString *error) const;
    bool lookup(const QString &entryPath, BwItemRef *ref, QJsonObject *item, QString *error) const;
    // Stores what a create/edit returned and rebuilds the index.
    void storeItem(const QByteArray &itemJson) const;
    void storeFolder(const QByteArray &folderJson) const;

    Secret m_session;
    // Held only between a local unlock and the `bw unlock` that sync() runs
    // right after, which needs it once more.
    Secret m_password;

    // Mutable because the Vault interface is const: the cache is refreshed
    // by the very operations that change what it mirrors. The mutex lets a
    // background sync swap it while the interface reads.
    mutable QMutex m_mutex;
    mutable QHash<QString, QJsonObject> m_items;  // id → item, as bw returns it
    mutable QHash<QString, QString> m_folders;    // id → name
    mutable BwIndex m_index;
};
