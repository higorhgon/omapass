#pragma once

#include <QString>

#include <optional>

#include "secret.h"

// PIN unlock for a Bitwarden account.
//
// `bw` knows nothing but the master password, so a PIN cannot replace it:
// what omapass keeps is the master password itself, encrypted with a key
// derived from the PIN (PBKDF2-SHA256, 600000 rounds, random salt), in the
// system keyring through `secret-tool`. The right PIN decrypts it and the
// usual unlock goes ahead unchanged.
//
// Be honest about what this buys: a four-digit PIN is 10000 candidates, and
// whoever can read the keyring can try them all offline — the KDF cost is
// the only thing in the way. The attempt limit below is an interface
// deterrent, not a defence against that.
namespace BwPin {

// Wrong PINs before the stored password is deleted.
constexpr int maxAttempts = 5;
// Shorter than this is refused; shorter than `recommendedLength` is warned about.
constexpr int minLength = 4;
constexpr int recommendedLength = 6;

enum class Result { Ok, WrongPin, Missing, Unavailable };

// What the keyring holds, as one line:
// "omapass-pin.v1|<salt base64>|<iterations>|<EncString type 2>".
struct Blob {
    QString salt;
    int iterations = 0;
    QString encrypted;
};

QString buildBlob(const Blob &blob);
// Empty for anything this version does not recognise, which makes the PIN be
// ignored rather than half understood.
std::optional<Blob> parseBlob(const QString &text);

// Empty when the PIN is acceptable, otherwise the reason, translated.
// `confirm` is only checked when given.
QString validate(const QString &pin, const QString &confirm = QString());
// Empty for a PIN of the recommended length or longer (and while one is
// still being typed); otherwise says how few combinations it has.
QString weakWarning(const QString &pin);

// `secret-tool` (libsecret) present; without it there is no PIN unlock.
bool isAvailable();
bool hasPin(const QString &email);

bool store(const QString &email, const QString &pin, const Secret &masterPassword, QString *error);
Result recover(const QString &email, const QString &pin, Secret *masterPassword);
void clear(const QString &email);

// Wrong attempts since the last success, kept across runs so closing the
// window is not a way around the limit.
int failedAttempts();
// Counts one wrong PIN and returns how many are left; deletes the stored
// password (and returns 0) on the last one.
int registerFailure(const QString &email);
void resetAttempts();

}
