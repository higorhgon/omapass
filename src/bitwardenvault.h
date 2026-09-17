#pragma once

#include "bitwardenjson.h"
#include "vault.h"

// Backend for a Bitwarden account, through the official `bw` CLI.
//
// Security notes:
// - The session key lives in a `Secret` and only reaches `bw` through the
//   BW_SESSION variable of each child process, never argv.
// - The master password goes through --passwordenv, and item/folder JSON
//   (which carries the password) through stdin, so neither shows up in `ps`.
// - The entry list keeps names and ids only; a password is fetched by id when
//   it is copied or edited.
// - Locking the vault runs `bw lock`, which also ends any session opened
//   with `bw unlock` in a terminal.
class BitwardenVault : public Vault {
public:
    static bool isAvailable();

    // The account added through omapass, remembered so it can be listed
    // without spawning `bw` (a Node program that takes about a second) at
    // start-up. Empty when none.
    static QString rememberedAccount();
    static void rememberAccount(const QString &email);
    static void forgetAccount();

    static QString refPath(const QString &email);
    static QString emailOf(const QString &refPath);

    static BwStatus status();
    static void logout();

    // Unlocks the logged-in account with the master password and loads it.
    static BitwardenVault *unlock(const QString &email, const Secret &password, QString *error);
    // Loads the account behind a session key `bw login` already handed back.
    static BitwardenVault *openWithSession(const QString &email, const Secret &session,
                                           QString *error);

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

    // Re-reads items and folders from bw's local copy. `sync` pulls from the
    // server first, which is only worth it when the vault is opened: every
    // write below already goes through the server.
    bool reload(bool sync, QString *error) const;
    bool ensureFolder(const QString &group, QString *folderId, QString *error) const;
    bool lookup(const QString &entryPath, BwItemRef *ref, QString *error) const;

    Secret m_session;
    // Mutable because the Vault interface is const: the cache is refreshed
    // by the very operations that change what it mirrors.
    mutable BwIndex m_index;
};
