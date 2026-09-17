#pragma once

#include <QHash>
#include <QJsonObject>
#include <QString>

#include <optional>

#include "secret.h"

// bw's own encrypted copy of the vault (data.json), read and decrypted
// without starting the CLI. Only the parts needed to list and read logins
// are taken from the file — never its access tokens — and nothing is ever
// written back: bw stays the owner of the file.
//
// The file format is internal to bw and changes between releases, so every
// step validates what it finds; anything unexpected is `Unsupported`, which
// tells the caller to go through `bw` instead. A vault is never returned half
// decrypted.
class BwCache {
public:
    enum class Result { Ok, WrongPassword, Unsupported };

    // bw's data.json, following its own rules: BITWARDENCLI_APPDATA_DIR when
    // set, otherwise "Bitwarden CLI" under the XDG config directory.
    static QString defaultPath();

    // Reads the active account's encrypted state. Empty when the file is
    // missing, no account is logged in or the layout is not recognised.
    static std::optional<BwCache> load(const QString &path = defaultPath());

    QString email() const { return m_email; }

    // Derives the master key and decrypts every login and folder, in the
    // shape `bw list items` / `bw list folders` give them (the fields omapass
    // uses). Items other than logins, and logins in the trash, are skipped.
    Result decrypt(const Secret &password, QHash<QString, QJsonObject> *items,
                   QHash<QString, QString> *folders) const;

private:
    QString m_email;
    QJsonObject m_unlockKey;
    QJsonObject m_cryptoState;
    QJsonObject m_organizationKeys;
    QJsonObject m_folders;
    QJsonObject m_ciphers;
};
