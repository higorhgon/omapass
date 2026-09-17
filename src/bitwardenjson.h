#pragma once

#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QString>
#include <QStringList>

#include "vault.h"

// The pure half of the Bitwarden backend: reading what `bw` prints and
// building what it expects, with no process spawned. Kept apart so it can be
// tested without an account or a network.

// `bw status`.
struct BwStatus {
    // "unauthenticated", "locked" or "unlocked"; empty when the output could
    // not be read at all.
    QString status;
    QString userEmail;

    bool loggedIn() const { return status == QLatin1String("locked") || status == QLatin1String("unlocked"); }
};

BwStatus parseBwStatus(const QString &json);

// The same answer read from bw's own state file (data.json) instead of
// spawning `bw status`, which takes seconds. The file cannot tell locked from
// unlocked, so a logged-in account comes back as "locked". An empty status
// means the file was there but not in a shape this understands.
BwStatus parseBwDataFile(const QByteArray &json);

// One login item as the entry list knows it.
struct BwItemRef {
    QString id;
    QString name;
    QString folderId;
};

// The vault flattened into omapass' path model. A folder named "Work/Mail"
// is the group `Work/Mail`; its parents exist as groups even when Bitwarden
// has no folder object for them.
struct BwIndex {
    QStringList entries;
    QStringList groups;
    QHash<QString, BwItemRef> items;   // entry path → item
    QHash<QString, QString> folders;   // folder name → folder id (real folders only)
};

// `bw list items` keyed by id, and `bw list folders` as id → name (without
// the "No Folder" pseudo-folder).
QHash<QString, QJsonObject> parseBwItems(const QByteArray &itemsJson);
QHash<QString, QString> parseBwFolders(const QByteArray &foldersJson);

// Builds the index from items and folders. Items other than logins, or in
// the trash, are left out. Two logins that would land on the same path both
// get the start of their id appended (`Mail [1a2b3c4d]`), so every path is
// unique and stays the same across runs.
BwIndex buildBwIndex(const QHash<QString, QJsonObject> &items, const QHash<QString, QString> &folders);
BwIndex buildBwIndex(const QByteArray &itemsJson, const QByteArray &foldersJson);

// The fields omapass shows, read from an item object.
EntryData bwEntryData(const QJsonObject &item);

// The path segment for an item name: a slash inside a name would read as a
// group, so it is shown as a look-alike division slash instead.
QString bwDisplayName(const QString &name);

// Returns `itemJson` (from `bw get item`) with only the fields omapass edits
// replaced — name, folder, username, password, first URI and notes. TOTP,
// custom fields, further URIs and organisation data are carried over as they
// were. An empty `itemJson` starts from a blank login item.
QByteArray applyBwEntryData(const QByteArray &itemJson, const QString &name,
                            const QString &folderId, const EntryData &data);

// A folder object for `bw create folder` / `bw edit folder`.
QByteArray bwFolderJson(const QString &name);

// What an unsuccessful `bw login` or `bw unlock` meant, read from its output.
enum class BwLoginError {
    None,
    WrongPassword,
    InvalidEmail,
    InvalidCode,
    AlreadyLoggedIn,
    Other,
};

BwLoginError classifyBwError(const QString &output);

// The prompts `bw login` shows while it waits for input on stdin.
enum class BwPrompt {
    None,
    TwoFactorMethod,     // several 2FA providers and none chosen
    TwoFactorCode,       // code from the authenticator app, e-mail, key…
    NewDeviceCode,       // one-time code e-mailed for an unrecognised device
};

BwPrompt detectBwPrompt(const QString &stderrText);
