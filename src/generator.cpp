#include "generator.h"

#include "config.h"
#include "i18n.h"
#include "process.h"

#include <QCoreApplication>
#include <QFile>
#include <QStandardPaths>

namespace {

// Set by configure(); the defaults are what the tests and a bare run see.
QString configuredWordlist = QStringLiteral("auto");
QString interfaceLanguage = QStringLiteral("en");

constexpr int minLength = 4;
constexpr int maxLength = 128;
constexpr int minWords = 3;
constexpr int maxWords = 16;

}

namespace Generator {

GeneratorOptions normalize(GeneratorOptions options) {
    options.length = qBound(minLength, options.length, maxLength);
    options.words = qBound(minWords, options.words, maxWords);

    // A custom set replaces the classes, so it is the one thing that has to
    // be there when it is used.
    if (!options.custom.isEmpty())
        return options;

    // Every class off would leave keepassxc-cli with nothing to draw from.
    if (!options.lower && !options.upper && !options.numbers && !options.special)
        options.lower = true;
    return options;
}

QStringList arguments(const GeneratorOptions &options, const QString &wordlist) {
    const GeneratorOptions bounded = normalize(options);

    if (bounded.passphrase) {
        return {QStringLiteral("diceware"), QStringLiteral("-W"), QString::number(bounded.words),
                QStringLiteral("-w"), wordlist};
    }

    QStringList args{QStringLiteral("generate"), QStringLiteral("-L"),
                     QString::number(bounded.length)};

    if (!bounded.custom.isEmpty()) {
        args << QStringLiteral("-c") << bounded.custom;
    } else {
        if (bounded.lower)
            args << QStringLiteral("-l");
        if (bounded.upper)
            args << QStringLiteral("-U");
        if (bounded.numbers)
            args << QStringLiteral("-n");
        if (bounded.special)
            args << QStringLiteral("-s");
    }

    if (bounded.excludeSimilar)
        args << QStringLiteral("--exclude-similar");
    if (!bounded.exclude.isEmpty())
        args << QStringLiteral("-x") << bounded.exclude;

    return args;
}

void configure(const QString &configured, const QString &language) {
    configuredWordlist = configured.isEmpty() ? QStringLiteral("auto") : configured;
    interfaceLanguage = language;
}

QStringList wordlistNames(const QString &configured, const QString &language) {
    // A path is used as given, with no fallback: naming a file that is not
    // there is a mistake worth noticing, not something to paper over.
    if (configured.contains(QLatin1Char('/')))
        return {configured};

    const QString english = QStringLiteral("eff_large.wordlist");
    if (configured == QLatin1String("en"))
        return {english};
    if (!configured.isEmpty() && configured != QLatin1String("auto"))
        return {configured + QStringLiteral(".wordlist"), english};

    // "auto": the interface language first, English as the fallback — the
    // language is a tag like "pt-BR", which is the list's own name.
    QStringList names;
    if (!language.isEmpty() && !language.startsWith(QLatin1String("en")))
        names << language + QStringLiteral(".wordlist");
    names << english;
    return names;
}

QStringList wordlistDirectories() {
    const QString appDir = QCoreApplication::applicationDirPath();
    QStringList directories{
        // Lists the user brought in through the settings sheet.
        Config::configDir() + QStringLiteral("/wordlists"),
        // Installed beside omapass (PREFIX/share/omapass/…), wherever that is.
        appDir + QStringLiteral("/../share/omapass/wordlists"),
        // Running from build/: the lists in the repository and in the submodule.
        appDir + QStringLiteral("/../wordlists"),
        appDir + QStringLiteral("/../vendor/keepassxc/share/wordlists"),
    };

    const QStringList data = QStandardPaths::standardLocations(QStandardPaths::AppDataLocation);
    for (const QString &directory : data)
        directories << directory + QStringLiteral("/wordlists");
    return directories;
}

QString wordlistPath() {
    const QStringList names = wordlistNames(configuredWordlist, interfaceLanguage);
    for (const QString &name : names) {
        if (name.contains(QLatin1Char('/')))
            return QFile::exists(name) ? name : QString();

        for (const QString &directory : wordlistDirectories()) {
            const QString candidate = directory + QLatin1Char('/') + name;
            if (QFile::exists(candidate))
                return candidate;
        }
    }
    return QString();
}

bool generate(const GeneratorOptions &options, Secret *password, QString *error) {
    const QString wordlist = options.passphrase ? wordlistPath() : QString();
    if (options.passphrase && wordlist.isEmpty()) {
        *error = I18n::t(QStringLiteral("generator.no_wordlist"));
        return false;
    }

    // Straight to the process rather than through runKpcli(): generating
    // needs no database and no password on stdin, so it does not depend on
    // the vault backends at all.
    const ProcResult result = runProcess(QStringLiteral("keepassxc-cli"), arguments(options, wordlist));
    if (!result.started) {
        *error = I18n::t(QStringLiteral("keepass.spawn_error"), QStringLiteral("err"), result.err);
        return false;
    }
    if (!result.success) {
        *error = result.err.trimmed();
        if (error->isEmpty())
            *error = I18n::t(QStringLiteral("generator.error"));
        return false;
    }

    QString generated = result.out.trimmed();
    if (generated.isEmpty()) {
        *error = I18n::t(QStringLiteral("generator.error"));
        return false;
    }

    // keepassxc-cli always separates diceware words with a space; anything
    // else the sheet asks for is put in here.
    if (options.passphrase && options.separator != QStringLiteral(" "))
        generated.replace(QLatin1Char(' '), options.separator);

    *password = Secret(generated);
    generated.fill(QChar(0));
    return true;
}

}
