#pragma once

#include "vault.h"

// Backend for pass stores, a thin adapter from Vault onto PassStore that
// keeps the GPG passphrase for the session.
class PassVault : public Vault {
public:
    PassVault(const QString &root, const Secret &passphrase)
        : Vault(VaultKind::Pass, root), m_passphrase(passphrase) {}

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
    Secret m_passphrase;
};
