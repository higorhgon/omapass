#pragma once

#include <QHash>
#include <QString>

#include <optional>

struct AppConfig {
    QString searchPath;
    bool recencyEnabled = true;
    QString themeName = QStringLiteral("default");
    QString language = QStringLiteral("en");
    // Role name ("Title", "Base", …) to hex colour, read from the active
    // theme in ~/.config/fpass/themes. These win over the Omarchy palette,
    // so a user who pinned specific colours keeps them.
    QHash<QString, QString> themeOverrides;
    // Minutes of inactivity before the open vault is locked (back to the
    // database list, secret dropped from memory). std::nullopt disables
    // auto-lock (`lock_minutes = false` in config.toml).
    std::optional<int> lockMinutes = 10;
};

namespace Config {

QString configDir();
QString themesDir();

void ensureConfigExists();
AppConfig load();

// Exposed for testing: resolves the effective UI language from the config
// value and the environment, in that order of priority.
QString resolveLanguage(const QString &configured, const QString &langEnv, const QString &lcAllEnv);

// Exposed for testing: interprets `general.lock_minutes` as read raw from
// the config file. An empty string (key absent) is the 10-minute default;
// "false" disables auto-lock; a positive integer is minutes; anything else
// (zero, negative, "true", garbage) is treated as invalid and also falls
// back to the default, rather than silently becoming "never locks".
std::optional<int> parseLockMinutes(const QString &raw);

// Minimal TOML reader for the flat `[section] key = "value"` files omapass and
// Omarchy both use. Keys come back as "section.key" (or bare "key" outside a
// section). Not a general TOML parser — it does not need to be.
QHash<QString, QString> readFlatToml(const QString &path);

}
