#pragma once

#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QVector>

#include "vault.h"

// The pure half of the 1Password backend: reading what `op` prints and
// building what it expects, with no process spawned. Kept apart so it can be
// tested without an account or a network.

// One entry of `op account list --format=json`.
struct OpAccount {
    QString shorthand;
    QString email;
    QString url;
    QString userUuid;

    // What `--account` takes: the shorthand when the account has one, the
    // user id otherwise (an account added without --shorthand has none).
    QString key() const;
};

QVector<OpAccount> parseOpAccounts(const QByteArray &json);

// One item as the entry list knows it. `title` and the vault name are kept
// as 1Password has them, not as the path shows them.
struct OpItemRef {
    QString id;
    QString title;
    QString vaultId;
    QString vaultName;
    QString tagPath;   // empty at the vault's root
};

// The account flattened into omapass' path model: the vault is the first
// segment and the item's tag nests below it, so the path
// `Pessoal/Trabalho/Email/Netflix` is the item "Netflix", tagged
// "Trabalho/Email", in the vault "Pessoal". 1Password lets an item carry
// several tags; the first in alphabetical order is the one that places it.
struct OpIndex {
    QStringList entries;
    QStringList groups;
    QHash<QString, OpItemRef> items;   // entry path → item
    QHash<QString, QString> vaults;    // vault name as shown → vault id
};

// `op item list` (or `op item get`) keyed by id, and `op vault list` as
// id → name.
QHash<QString, QJsonObject> parseOpItems(const QByteArray &itemsJson);
QHash<QString, QString> parseOpVaults(const QByteArray &vaultsJson);

// Builds the index from items and vaults. Items other than logins and
// passwords are left out: omapass only models a title, a username, a
// password, a URL and notes, and rewriting a credit card or an identity
// through that shape would drop most of it. Two items that would land on the
// same path both get the start of their id appended (`Netflix [1a2b3c4d]`),
// so every path is unique and stays the same across runs.
OpIndex buildOpIndex(const QHash<QString, QJsonObject> &items,
                     const QHash<QString, QString> &vaults);
OpIndex buildOpIndex(const QByteArray &itemsJson, const QByteArray &vaultsJson);

// The path segment for a vault name or an item title: a slash inside either
// would read as a group, so it is shown as a look-alike division slash
// instead. Tags are not passed through this — their slashes are the nesting.
QString opDisplayName(const QString &name);

// The first segment of a path (the vault) and everything after it (the tag
// path, empty at the vault's root).
QString opVaultOf(const QString &path);
QString opTagPathOf(const QString &path);

// A tag as 1Password stores it: no empty segments, no leading or trailing
// slash, no surrounding spaces.
QString opNormalizeTag(const QString &tag);

// The fields omapass shows, read from an item object.
EntryData opEntryData(const QJsonObject &item);

// Returns `itemJson` (from `op item get`) with only the fields omapass edits
// replaced — title, placing tag, username, password, first URL and notes.
// Everything else (sections, custom fields, one-time passwords, other tags,
// further URLs) is carried over as it was, because `op item edit` with a
// template replaces the whole item.
QByteArray applyOpEntryData(const QByteArray &itemJson, const QString &title,
                            const QString &tagPath, const EntryData &data);

// A whole new login item for `op item create`, in the given vault.
QByteArray opNewItemJson(const QString &title, const QString &vaultId,
                         const QString &tagPath, const EntryData &data);

// True when the item carries a passkey, which a template edit would destroy:
// `op item edit` warns that JSON templates do not support passkeys.
bool opHasPasskey(const QJsonObject &item);

// What an unsuccessful `op` run meant, read from its output. The strings
// matched are the ones in the `op` binary itself (2.39).
enum class OpError {
    None,
    WrongPassword,
    WrongSecretKey,
    WrongCode,
    NotSignedIn,      // no session at all
    SessionExpired,   // had one, 30 minutes of inactivity went by
    NoAccount,        // nothing configured on this device
    RateLimited,
    Other,
};

OpError classifyOpError(const QString &output);

// The prompts `op account add` and `op signin` show while they wait for
// input.
enum class OpPrompt {
    None,
    SignInAddress,
    Email,
    SecretKey,
    Password,
    TwoFactorCode,
};

OpPrompt detectOpPrompt(const QString &stderrText);
