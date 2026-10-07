#pragma once

#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

#include <optional>

#include "vault.h"

// The pure half of the Bitwarden backend: the decrypted vault flattened into
// omapass' path model, the server address, and what the login answers mean.
// Kept apart so it can be tested without an account or a network.

// The server address typed on the login sheet, in the one form the account
// is kept under: "https://host[:port][/path]", with no trailing slash. The
// scheme may be left out and https is assumed. bitwarden.com (in any of its
// spellings, or nothing at all) comes back empty; the EU cloud as
// "https://vault.bitwarden.eu". Plain http — which would send the password
// hash in the clear — or anything that is not an address is nullopt.
std::optional<QString> normalizeBwServer(const QString &input);
// How the login sheet shows a normalised server: "bitwarden.com" for the
// default, the address itself otherwise.
QString bwServerLabel(const QString &serverUrl);

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

// Builds the index from items and folders. Items other than logins, or in
// the trash, are left out. Two logins that would land on the same path both
// get the start of their id appended (`Mail [1a2b3c4d]`), so every path is
// unique and stays the same across runs.
BwIndex buildBwIndex(const QHash<QString, QJsonObject> &items, const QHash<QString, QString> &folders);

// The fields omapass shows, read from an item object.
EntryData bwEntryData(const QJsonObject &item);

// The path segment for an item name: a slash inside a name would read as a
// group, so it is shown as a look-alike division slash instead.
QString bwDisplayName(const QString &name);

// What an unsuccessful login meant.
enum class BwLoginError {
    None,
    WrongPassword,
    InvalidEmail,
    InvalidCode,
    ServerUnreachable,   // nothing answered at the address
    ServerCertificate,   // something answered, with a certificate the system does not trust
    UnsupportedTwoStep,  // only two-step methods omapass cannot ask for (Duo, passkeys…)
    Other,
};

// The error a login attempt got back from the server, read from its message.
// `sentCode` says a two-step or new-device code went with the attempt, which
// is then what any refusal is about.
BwLoginError classifyBwLoginMessage(const QString &message, bool sentCode);

// What the login waits for after the credentials.
enum class BwPrompt {
    None,
    TwoFactorMethod,     // several two-step methods and none chosen
    TwoFactorCode,       // code from the authenticator app, e-mail, key…
    NewDeviceCode,       // one-time code e-mailed for an unrecognised device
};

// The two-step methods omapass can ask for, among `providers` (the keys of
// the server's TwoFactorProviders2): authenticator (0), e-mail (1) and
// YubiKey OTP (3), in that order.
QList<int> bwSupportedTwoFactor(const QList<int> &providers);
