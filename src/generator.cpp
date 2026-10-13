#include "generator.h"

#include "config.h"
#include "i18n.h"

#include <QCoreApplication>
#include <QFile>
#include <QStandardPaths>

#include <botan/system_rng.h>

#include <limits>
#include <vector>

namespace {

// Set by configure(); the defaults are what the tests and a bare run see.
QString configuredWordlist = QStringLiteral("auto");
QString interfaceLanguage = QStringLiteral("en");

constexpr int minLength = 4;
constexpr int maxLength = 128;
constexpr int minWords = 3;
constexpr int maxWords = 16;

// What each class draws from. Special is the printable ASCII punctuation;
// "similar" are the characters that are easy to take for one another.
const QString lowerSet = QStringLiteral("abcdefghijklmnopqrstuvwxyz");
const QString upperSet = QStringLiteral("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
const QString numberSet = QStringLiteral("0123456789");
const QString specialSet = QStringLiteral("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");
const QString similarSet = QStringLiteral("iIl1|Lo0O");

// A uniform number in [0, bound), without modulo bias.
quint32 randomBelow(quint32 bound) {
    if (bound <= 1)
        return 0;
    const quint32 limit = std::numeric_limits<quint32>::max() - (std::numeric_limits<quint32>::max() % bound);
    for (;;) {
        quint32 value = 0;
        Botan::system_rng().randomize(reinterpret_cast<uint8_t *>(&value), sizeof(value));
        if (value < limit)
            return value % bound;
    }
}

QString withoutChars(const QString &set, const QString &removed) {
    QString out;
    for (const QChar c : set) {
        if (!removed.contains(c))
            out.append(c);
    }
    return out;
}

QStringList readWords(const QString &path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return {};
    QStringList words;
    while (!file.atEnd()) {
        QString line = QString::fromUtf8(file.readLine()).trimmed();
        // A list with dice numbers ("11111<TAB>abacus") keeps the word.
        const int tab = line.lastIndexOf(QLatin1Char('\t'));
        if (tab >= 0)
            line = line.mid(tab + 1).trimmed();
        if (!line.isEmpty())
            words.append(line);
    }
    return words;
}

}

namespace Generator {

GeneratorOptions normalize(GeneratorOptions options) {
    options.length = qBound(minLength, options.length, maxLength);
    options.words = qBound(minWords, options.words, maxWords);

    // A custom set replaces the classes, so it is the one thing that has to
    // be there when it is used.
    if (!options.custom.isEmpty())
        return options;

    // Every class off would leave nothing to draw from.
    if (!options.lower && !options.upper && !options.numbers && !options.special)
        options.lower = true;
    return options;
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
        // Beside the executable (the Windows package, which has no
        // PREFIX/share to speak of).
        appDir + QStringLiteral("/wordlists"),
        // Running from build/: the lists in the repository.
        appDir + QStringLiteral("/../wordlists"),
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
    const GeneratorOptions bounded = normalize(options);

    try {
        if (bounded.passphrase) {
            const QString wordlist = wordlistPath();
            if (wordlist.isEmpty()) {
                *error = I18n::t(QStringLiteral("generator.no_wordlist"));
                return false;
            }
            const QStringList words = readWords(wordlist);
            if (words.size() < minimumWordlistSize) {
                *error = I18n::t(QStringLiteral("generator.error"));
                return false;
            }

            QStringList chosen;
            for (int i = 0; i < bounded.words; ++i)
                chosen.append(words.at(int(randomBelow(quint32(words.size())))));
            QString phrase = chosen.join(bounded.separator);
            *password = Secret(phrase);
            phrase.fill(QChar(0));
            return true;
        }

        // The classes in use, each with the characters left after the
        // exclusions; a custom set stands alone.
        QString removed = bounded.exclude;
        if (bounded.excludeSimilar)
            removed += similarSet;

        QStringList groups;
        if (!bounded.custom.isEmpty()) {
            groups << withoutChars(bounded.custom, removed);
        } else {
            if (bounded.lower)
                groups << withoutChars(lowerSet, removed);
            if (bounded.upper)
                groups << withoutChars(upperSet, removed);
            if (bounded.numbers)
                groups << withoutChars(numberSet, removed);
            if (bounded.special)
                groups << withoutChars(specialSet, removed);
        }
        groups.removeAll(QString());
        if (groups.isEmpty()) {
            *error = I18n::t(QStringLiteral("generator.error"));
            return false;
        }

        QString pool;
        for (const QString &group : std::as_const(groups))
            pool += group;

        // One from every class first, so the result meets what was asked
        // for; the rest from the whole pool; then shuffled so the guaranteed
        // ones do not sit at the front.
        std::vector<QChar> picked;
        for (const QString &group : std::as_const(groups)) {
            if (int(picked.size()) < bounded.length)
                picked.push_back(group.at(int(randomBelow(quint32(group.size())))));
        }
        while (int(picked.size()) < bounded.length)
            picked.push_back(pool.at(int(randomBelow(quint32(pool.size())))));
        for (size_t i = picked.size(); i > 1; --i)
            std::swap(picked[i - 1], picked[randomBelow(quint32(i))]);

        QString generated;
        generated.reserve(int(picked.size()));
        for (const QChar c : picked)
            generated.append(c);
        *password = Secret(generated);
        generated.fill(QChar(0));
        return true;
    } catch (const std::exception &) {
        *error = I18n::t(QStringLiteral("generator.error"));
        return false;
    }
}

}
