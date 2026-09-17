#pragma once

#include <QString>
#include <QStringList>

#include "secret.h"

// Password and passphrase generation, through `keepassxc-cli`, which omapass
// already ships and which answers in about ten milliseconds — fast enough to
// regenerate on every change in the sheet. The other backends' generators
// are not used: `bw generate` takes a couple of seconds per password, and
// `pass generate` writes an entry instead of just generating one.

struct GeneratorOptions {
    // Words from a wordlist instead of characters.
    bool passphrase = false;

    // Password
    int length = 20;
    bool lower = true;
    bool upper = true;
    bool numbers = true;
    bool special = true;
    bool excludeSimilar = false;
    // Characters to leave out, and a set to draw from instead of the classes
    // above. Both are optional.
    QString exclude;
    QString custom;

    // Passphrase
    int words = 6;
    QString separator = QStringLiteral(" ");
};

namespace Generator {

// Bounds the numbers and makes sure at least one character class is on, so
// the sheet cannot ask for something keepassxc-cli would refuse.
GeneratorOptions normalize(GeneratorOptions options);

// The `keepassxc-cli` command line for these options. Exposed for testing.
QStringList arguments(const GeneratorOptions &options, const QString &wordlist);

// The EFF wordlist that comes with the vendored keepassxc, installed beside
// omapass. Empty when it cannot be found, which is what turns the passphrase
// mode off.
QString wordlistPath();

bool generate(const GeneratorOptions &options, Secret *password, QString *error);

}
