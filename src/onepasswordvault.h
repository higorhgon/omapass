#pragma once

#include <QMutex>

#include "opjson.h"
#include "vault.h"

// Backend for a 1Password account, through the official `op` CLI.
//
// `op` is a Go binary: it starts in milliseconds, keeps a daemon that caches
// items and keys in memory, and pays only for the network. So, unlike the
// Bitwarden backend, there is no local copy to decrypt here — opening signs
// in and lists, and a password is fetched from the server the first time it
// is shown, then kept in memory while the vault is open.
//
// 1Password has no folders: an item lives in a vault and carries tags, which
// nest with slashes. omapass shows the vault as the first group and the tag
// below it (`Pessoal/Trabalho/Email`), which is what opjson builds.
//
// Security notes:
// - The session token lives in a `Secret` and only reaches `op` through the
//   OP_SESSION_<account> variable of each child process, never argv.
// - The master password is written to `op signin` on stdin, and item JSON
//   (which carries the password) to `op item create`/`op item edit` the same
//   way, so neither shows up in `ps`.
// - The master password is not kept after opening. When the session expires
//   — 30 minutes of inactivity — the vault reports it and omapass locks back
//   to the unlock screen instead of holding the password to sign in again.
class OnePasswordVault : public Vault {
public:
    static bool isAvailable();

    static QString refPath(const QString &account);
    static QString accountOf(const QString &refPath);

    // The accounts `op` is configured with on this device, which is what the
    // database list is built from — omapass keeps no account of its own.
    static QVector<OpAccount> accounts();
    static bool hasAccount(const QString &account);
    // The account as the list shows it: the shorthand when it was chosen,
    // the e-mail when `op` derived one from the address (`my` and the like,
    // which says nothing about whose account it is).
    static QString displayName(const QString &account);
    // Signs out and drops the account's details from this device.
    static void logout(const QString &account);

    // Signs in with the master password and loads the account.
    static OnePasswordVault *unlock(const QString &account, const Secret &password, QString *error);
    // Loads the account behind a session token `op signin` already handed
    // back, which is how the login flow gets in.
    static OnePasswordVault *openWithSession(const QString &account, const Secret &session,
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
    OnePasswordVault(const QString &account, const Secret &session)
        : Vault(VaultKind::OnePassword, refPath(account)), m_account(account), m_session(session) {}

    static bool signIn(const QString &account, const Secret &password, Secret *session,
                       QString *error);

    bool reload(QString *error) const;
    // The item as `op` has it, fetched once and then kept: a listing only
    // carries the title, the vault and the tags, and editing from that would
    // drop every field the form does not show.
    bool fullItem(const OpItemRef &ref, QJsonObject *item, QString *error) const;
    bool lookup(const QString &entryPath, OpItemRef *ref, QString *error) const;
    // The vault a group lives in: its first segment, which has to be a vault
    // that already exists.
    bool vaultOfGroup(const QString &group, QString *vaultId, QString *error) const;
    // Sets an item's tags, which is how groups are renamed and removed.
    bool setTags(const QString &itemId, const QString &vaultId, const QStringList &tags,
                 QString *error) const;
    // Stores what a create/edit/get returned and rebuilds the index.
    void storeItem(const QByteArray &itemJson) const;
    void forgetItem(const QString &itemId) const;

    QString m_account;
    Secret m_session;

    // Mutable because the Vault interface is const: the cache is refreshed
    // by the very operations that change what it mirrors, and the mutex lets
    // a background task swap it while the interface reads.
    mutable QMutex m_mutex;
    mutable QHash<QString, QJsonObject> m_items;   // id → item, as op returns it
    mutable QHash<QString, QString> m_vaults;      // vault id → name
    mutable OpIndex m_index;
};
