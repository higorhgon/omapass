#pragma once

#include <QDateTime>
#include <QMutex>

#include "bitwardenjson.h"
#include "bwaccount.h"
#include "bwapi.h"
#include "vault.h"

// Backend for a Bitwarden account — bitwarden.com, the EU cloud or a server
// of your own (Vaultwarden, self-hosted Bitwarden) — spoken to directly over
// its API, with no CLI in between.
//
// - Opening decrypts omapass' own copy of the vault (BwAccountState) with
//   the master password, without touching the network, so the list shows
//   up at once and works offline.
// - sync() then refreshes the access token and pulls from the server; the
//   caller runs it in the background right after opening.
// - Writes go straight to the server, encrypted here, and what it answers
//   updates the copy on disk and in memory.
// - Calls are synchronous and meant to run off the GUI thread; the vault in
//   memory is guarded so a background sync can swap it while the interface
//   reads.
//
// Security notes:
// - The master password is only used to derive the keys, and is not kept.
// - The access token lives in a `Secret` in memory; the refresh token is
//   kept on disk encrypted with the user key, so the file alone reaches
//   nothing.
// - While the vault is open its items, passwords included, are held in
//   memory; they are dropped when it is locked.
class BitwardenVault : public Vault {
public:
    // Every account omapass has a copy of, as database list entries; plus
    // the one remembered by versions that drove `bw`, until it logs in again.
    static QVector<DbRef> accounts();
    // Whether the account can still reach the server without logging in
    // again: a copy with a refresh token in it.
    static bool hasSession(const QString &refPath);
    // "e-mail" for bitwarden.com, "e-mail (host)" for any other server.
    static QString displayName(const QString &refPath);
    // The server, as the login sheet shows it.
    static QString serverLabel(const QString &refPath);

    // Forgets the account: its copy on disk goes, and with it the refresh
    // token. Nothing is left that reaches the server.
    static bool logout(const QString &refPath, QString *error);
    // Whether `password` opens the account's copy, without opening it.
    static bool verifyPassword(const QString &refPath, const Secret &password, QString *error);

    // Opens the account's copy with the master password.
    static BitwardenVault *unlock(const QString &refPath, const Secret &password, QString *error);
    // An account just logged into: `state` freshly synced and saved, `keys`
    // opened, `accessToken` the one the login got.
    static BitwardenVault *fromLogin(const BwAccountState &state, const BwKeys &keys,
                                     const Secret &accessToken, int expiresIn);

    // Refreshes the access token and pulls the vault from the server. Skipped
    // when it was pulled a moment ago (right after logging in).
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
    BitwardenVault(const BwAccountState &state, const BwKeys &keys);

    // A valid access token, refreshing it when it is missing or about to
    // expire. A refresh token the server no longer takes ends the session:
    // it is dropped from the copy, and the next open asks to log in.
    bool authorize(QString *error) const;
    // An API call with the access token, retried once with a fresh one when
    // the server says the token is no longer good.
    BwResponse request(const QByteArray &method, const QString &path, QString *error,
                       const QJsonObject &body = QJsonObject(), bool hasBody = false) const;
    // Rebuilds the decrypted vault from m_state. Caller holds the mutex.
    void rebuild() const;
    void persist() const;
    // Takes a cipher or folder the server answered with into the copy.
    void storeCipher(const QJsonObject &cipher) const;
    void storeFolder(const QJsonObject &folder) const;

    bool ensureFolder(const QString &group, QString *folderId, QString *error) const;
    bool lookup(const QString &entryPath, BwItemRef *ref, QJsonObject *item, QString *error) const;

    // Mutable because the Vault interface is const: the copy is refreshed by
    // the very operations that change what it mirrors. The mutex lets a
    // background sync swap it while the interface reads.
    mutable QMutex m_mutex;
    mutable BwAccountState m_state;
    mutable BwKeys m_keys;
    mutable Secret m_accessToken;
    mutable QDateTime m_tokenExpiry;
    QDateTime m_syncedAt;

    mutable QHash<QString, QJsonObject> m_items;  // id → decrypted item
    mutable QHash<QString, QString> m_folders;    // id → name
    mutable BwIndex m_index;
};
