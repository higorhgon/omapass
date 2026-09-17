#include "generator.h"

#include "i18n.h"
#include "process.h"

#include <QCoreApplication>
#include <QFile>
#include <QStandardPaths>

namespace {

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

QString wordlistPath() {
    const QString relative = QStringLiteral("wordlists/eff_large.wordlist");

    QStringList candidates;
    // Installed beside omapass (PREFIX/share/omapass/…), wherever that is.
    const QString installed = QCoreApplication::applicationDirPath()
        + QStringLiteral("/../share/omapass/") + relative;
    candidates << installed;
    // Running from the build directory, straight out of the submodule.
    candidates << QCoreApplication::applicationDirPath()
            + QStringLiteral("/../vendor/keepassxc/share/") + relative;
    candidates << QStandardPaths::locate(QStandardPaths::AppDataLocation, relative);

    for (const QString &candidate : std::as_const(candidates)) {
        if (!candidate.isEmpty() && QFile::exists(candidate))
            return candidate;
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
