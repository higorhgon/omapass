#pragma once

#include "vault.h"

// Backend for KeePassXC databases, through `keepassxc-cli`. The database
// password is written on stdin for every command; it never reaches argv.
class KeepassVault : public Vault {
public:
    KeepassVault(const QString &path, const Secret &password)
        : Vault(VaultKind::Keepass, path), m_password(password) {}

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

private:
    Secret m_password;
};
