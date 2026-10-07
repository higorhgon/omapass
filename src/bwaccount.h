#pragma once

#include <QHash>
#include <QJsonArray>
#include <QJsonObject>
#include <QString>
#include <QStringList>

#include <optional>

#include "bwcrypto.h"
#include "secret.h"
#include "vault.h"

// A Bitwarden account as omapass keeps it between runs: the server's own
// encrypted copy of the vault (what /sync returns), plus what it takes to
// open it with the master password alone and to talk to the server again.
//
// Nothing in the file is readable without the master password: items,
// folders and keys stay encrypted the way the server sent them, and the
// refresh token — the one thing that would let someone reach the server —
// is encrypted with the account's user key before it is written. The file
// lives in $XDG_DATA_HOME/omapass/bitwarden, readable by the user only.
struct BwAccountState {
    QString server;          // normalised, empty for bitwarden.com
    QString email;
    QString userId;          // the account's id, which writes say they are encrypted for
    QString salt;            // the KDF salt: the e-mail, as the server says
    BwKdf kdf;
    QString userKey;         // EncString, wrapped with the stretched master key
    QString privateKey;      // EncString, wrapped with the user key
    QString refreshToken;    // EncString, wrapped with the user key; empty when logged out
    QJsonObject organizationKeys;  // organization id → RSA EncString of its key
    QJsonArray folders;      // as /sync returns them
    QJsonArray ciphers;
};

// The keys an unlocked account works with. Held only while the vault is open.
struct BwKeys {
    BwKey user;
    QHash<QString, BwKey> organizations;
};

namespace BwAccount {

// Where the files live.
QString directory();

// An account's entry in the database list: "bitwarden:<e-mail>" for
// bitwarden.com — the same as before omapass spoke to the server itself, so
// a PIN set back then still applies — and "bitwarden:<e-mail>|<server>" for
// any other server.
QString refPath(const QString &email, const QString &server);
QString emailOf(const QString &refPath);
QString serverOf(const QString &refPath);

// Every account with a file, by ref path.
QStringList refPaths();

std::optional<BwAccountState> load(const QString &refPath);
bool save(const BwAccountState &state, QString *error);
void remove(const QString &refPath);

enum class Unlock { Ok, WrongPassword, Unsupported };

// Derives the master key from the password and opens the user key and the
// organisation keys.
Unlock unlock(const BwAccountState &state, const Secret &password, BwKeys *keys);
// The organisation keys, opened with the private key under `user`. Keys that
// cannot be opened (an organisation managed by a provider, say) are left
// out, and so, later, are that organisation's items.
QHash<QString, BwKey> organizationKeys(const BwAccountState &state, const BwKey &user);

// Takes what a /sync response says about the account into `state`: profile
// keys, KDF settings when given, organisations, folders and ciphers.
void applySync(BwAccountState *state, const QJsonObject &sync);

// The key a cipher's fields are encrypted with: its own key when it has one,
// wrapped with the user's or its organisation's key. Empty when it cannot be
// opened.
std::optional<BwKey> cipherKey(const QJsonObject &cipher, const BwKeys &keys);

// One cipher decrypted into the shape the rest of omapass reads (that of
// `bw list items`). Only live logins: empty for other types, items in the
// trash or ones that do not decrypt.
std::optional<QJsonObject> decryptCipher(const QJsonObject &cipher, const BwKeys &keys);
// A folder's name; empty when it does not decrypt.
QString decryptFolder(const QJsonObject &folder, const BwKey &user);

// The body of a create (`encrypted` empty) or edit (`encrypted` the cipher
// as the server has it) of a login: name, folder, username, password, first
// URI and notes set from `data`, encrypted with `key`; everything else —
// TOTP, custom fields, further URIs, passkeys, attachments — carried over
// encrypted as it was, so nothing omapass does not show is lost. A changed
// password goes into the item's password history, as the official clients
// do. `previousPassword` is the decrypted password before the edit.
QJsonObject cipherRequest(const QJsonObject &encrypted, const QString &previousPassword,
                          const QString &name, const QString &folderId, const EntryData &data,
                          const BwKey &key, const QString &userId);

// The body of a folder create or rename.
QJsonObject folderRequest(const QString &name, const BwKey &user);

// Everything at once: id → item, id → folder name.
void decryptVault(const BwAccountState &state, const BwKeys &keys, QHash<QString, QJsonObject> *items,
                  QHash<QString, QString> *folders);

}
