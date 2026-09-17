#include "config.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>

namespace {

QString home() {
    return QDir::homePath();
}

QString unquote(QString value) {
    value = value.trimmed();

    // A quoted value ends at its closing quote; anything after it (a comment,
    // say) is not part of it, and a '#' inside the quotes is.
    if (value.startsWith(QLatin1Char('"')) || value.startsWith(QLatin1Char('\''))) {
        const QChar quote = value.at(0);
        const int closing = value.indexOf(quote, 1);
        if (closing > 0)
            return value.mid(1, closing - 1);
        return value.mid(1);
    }

    const int hash = value.indexOf(QLatin1Char('#'));
    if (hash >= 0)
        value = value.left(hash).trimmed();

    return value;
}

}

namespace Config {

// ~/.config/omapass, except on a machine that still has the ~/.config/fpass
// this app used to be called: that one keeps being used, so an existing
// history, theme and set of created databases survive the rename untouched.
// Move the directory yourself to adopt the new name.
QString configDir() {
    static const QString directory = []() {
        const QString current = home() + QStringLiteral("/.config/omapass");
        const QString legacy = home() + QStringLiteral("/.config/fpass");
        if (!QDir(current).exists() && QDir(legacy).exists())
            return legacy;
        return current;
    }();
    return directory;
}

QString themesDir() {
    return configDir() + QStringLiteral("/themes");
}

QHash<QString, QString> readFlatToml(const QString &path) {
    QHash<QString, QString> values;

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return values;

    QTextStream in(&file);
    QString section;
    while (!in.atEnd()) {
        const QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#')))
            continue;

        if (line.startsWith(QLatin1Char('[')) && line.endsWith(QLatin1Char(']'))) {
            section = line.mid(1, line.size() - 2).trimmed();
            continue;
        }

        const int equals = line.indexOf(QLatin1Char('='));
        if (equals < 0)
            continue;

        const QString key = line.left(equals).trimmed();
        const QString value = unquote(line.mid(equals + 1));
        values.insert(section.isEmpty() ? key : section + QLatin1Char('.') + key, value);
    }

    return values;
}

QString tomlString(const QString &value) {
    QString escaped = value;
    escaped.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
    escaped.replace(QLatin1Char('"'), QStringLiteral("\\\""));
    return QLatin1Char('"') + escaped + QLatin1Char('"');
}

QString applyTomlEdits(const QString &content, const QMap<QString, QString> &values) {
    QStringList lines = content.split(QLatin1Char('\n'));
    QMap<QString, QString> pending = values;

    // Where each section's own lines end, so a key that is missing is added
    // to its section instead of the end of the file.
    QHash<QString, int> sectionEnd;
    QString section;
    for (int i = 0; i < lines.size(); ++i) {
        const QString line = lines.at(i);
        const QString trimmed = line.trimmed();

        if (trimmed.startsWith(QLatin1Char('[')) && trimmed.endsWith(QLatin1Char(']'))) {
            section = trimmed.mid(1, trimmed.size() - 2).trimmed();
            sectionEnd.insert(section, i + 1);
            continue;
        }
        if (!trimmed.isEmpty())
            sectionEnd.insert(section, i + 1);
        if (trimmed.isEmpty() || trimmed.startsWith(QLatin1Char('#')))
            continue;

        const int equals = trimmed.indexOf(QLatin1Char('='));
        if (equals < 0)
            continue;

        const QString key = trimmed.left(equals).trimmed();
        const QString fullKey = section.isEmpty() ? key : section + QLatin1Char('.') + key;
        if (!pending.contains(fullKey))
            continue;

        // A comment sitting after the value stays where it is.
        QString comment;
        const QString rest = trimmed.mid(equals + 1);
        bool quoted = false;
        for (int c = 0; c < rest.size(); ++c) {
            const QChar character = rest.at(c);
            if (character == QLatin1Char('"') || character == QLatin1Char('\''))
                quoted = !quoted;
            else if (character == QLatin1Char('#') && !quoted) {
                comment = QStringLiteral("  ") + rest.mid(c).trimmed();
                break;
            }
        }

        int indentSize = 0;
        while (indentSize < line.size() && line.at(indentSize).isSpace())
            ++indentSize;

        lines[i] = line.left(indentSize) + key + QStringLiteral(" = ") + pending.value(fullKey) + comment;
        pending.remove(fullKey);
    }

    // What is left did not exist yet: into its section, or into a new one.
    while (!pending.isEmpty()) {
        const QString fullKey = pending.firstKey();
        const int dot = fullKey.lastIndexOf(QLatin1Char('.'));
        const QString keySection = dot < 0 ? QString() : fullKey.left(dot);
        const QString key = dot < 0 ? fullKey : fullKey.mid(dot + 1);
        const QString line = key + QStringLiteral(" = ") + pending.take(fullKey);

        if (sectionEnd.contains(keySection)) {
            const int at = sectionEnd.value(keySection);
            lines.insert(at, line);
            // Everything after this point moved down by one.
            for (auto it = sectionEnd.begin(); it != sectionEnd.end(); ++it) {
                if (it.value() >= at)
                    *it += 1;
            }
            continue;
        }

        if (!lines.isEmpty() && !lines.last().trimmed().isEmpty())
            lines << QString();
        lines << QLatin1Char('[') + keySection + QLatin1Char(']') << line;
        sectionEnd.insert(keySection, lines.size());
    }

    QString result = lines.join(QLatin1Char('\n'));
    if (!result.endsWith(QLatin1Char('\n')))
        result += QLatin1Char('\n');
    return result;
}

bool writeValues(const QMap<QString, QString> &values) {
    const QString path = configDir() + QStringLiteral("/config.toml");

    QString content;
    QFile file(path);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text))
        content = QString::fromUtf8(file.readAll());
    file.close();

    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
        return false;

    QTextStream out(&file);
    out << applyTomlEdits(content, values);
    return true;
}

std::optional<int> parseLockMinutes(const QString &raw) {
    constexpr int defaultMinutes = 10;
    if (raw.isEmpty())
        return defaultMinutes;
    if (raw == QStringLiteral("false"))
        return std::nullopt;

    bool ok = false;
    const int minutes = raw.toInt(&ok);
    if (ok && minutes > 0)
        return minutes;

    return defaultMinutes;
}

QString resolveLanguage(const QString &configured, const QString &langEnv, const QString &lcAllEnv) {
    if (configured == QStringLiteral("en") || configured == QStringLiteral("pt-BR"))
        return configured;

    QString envLang = langEnv;
    if (envLang.isEmpty())
        envLang = lcAllEnv;

    envLang = envLang.toLower();
    if (envLang.startsWith(QStringLiteral("pt")))
        return QStringLiteral("pt-BR");
    if (envLang.startsWith(QStringLiteral("en")))
        return QStringLiteral("en");

    return QStringLiteral("en");
}

void ensureConfigExists() {
    QDir().mkpath(themesDir());

    const QString path = configDir() + QStringLiteral("/config.toml");
    if (QFile::exists(path))
        return;

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
        return;

    QTextStream out(&file);
    out << "[general]\n"
        << "path = \"~/\"\n"
        << "recency = true\n"
        << "theme = \"default\"\n"
        << "language = \"auto\"\n"
        << "# Minutes of inactivity before the open vault is locked (back to the\n"
        << "# database list, asking to unlock again). \"false\" disables auto-lock.\n"
        << "lock_minutes = 10\n"
        << "\n"
        << "[generator]\n"
        << "# Wordlist for the passphrase generator: \"auto\" follows the\n"
        << "# interface language, or name one that ships with omapass\n"
        << "# (\"pt-BR\", \"en\"), or give a path to a file of your own.\n"
        << "wordlist = \"auto\"\n";
}

AppConfig load() {
    AppConfig config;
    config.searchPath = home();

    const QHash<QString, QString> raw = readFlatToml(configDir() + QStringLiteral("/config.toml"));

    QString path = raw.value(QStringLiteral("general.path"));
    if (!path.isEmpty()) {
        if (path.startsWith(QStringLiteral("~/")))
            path = home() + path.mid(1);
        config.searchPath = path;
    }

    const QString recency = raw.value(QStringLiteral("general.recency"));
    if (!recency.isEmpty())
        config.recencyEnabled = recency != QStringLiteral("false");

    const QString theme = raw.value(QStringLiteral("general.theme"));
    if (!theme.isEmpty())
        config.themeName = theme;

    config.language = resolveLanguage(raw.value(QStringLiteral("general.language")),
                                      qEnvironmentVariable("LANG"),
                                      qEnvironmentVariable("LC_ALL"));

    config.lockMinutes = parseLockMinutes(raw.value(QStringLiteral("general.lock_minutes")));

    QString wordlist = raw.value(QStringLiteral("generator.wordlist"));
    if (!wordlist.isEmpty()) {
        if (wordlist.startsWith(QStringLiteral("~/")))
            wordlist = home() + wordlist.mid(1);
        config.wordlist = wordlist;
    }

    if (config.themeName == QStringLiteral("default"))
        return config;

    // Themes are matched on the `name` inside the file, not the filename, so
    // a theme can be dropped in under any filename.
    const QDir dir(themesDir());
    const auto files = dir.entryInfoList({QStringLiteral("*.toml")}, QDir::Files, QDir::Name);
    for (const QFileInfo &info : files) {
        const QHash<QString, QString> values = readFlatToml(info.absoluteFilePath());
        if (values.value(QStringLiteral("theme.name")) != config.themeName)
            continue;

        for (auto it = values.constBegin(); it != values.constEnd(); ++it) {
            if (!it.key().startsWith(QStringLiteral("colors.")))
                continue;
            config.themeOverrides.insert(it.key().mid(7), it.value());
        }
        break;
    }

    return config;
}

}
