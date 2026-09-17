#include "bwpin.h"

#include "bwcrypto.h"
#include "i18n.h"
#include "process.h"

#include <QLocale>
#include <QRegularExpression>
#include <QSettings>
#include <QStandardPaths>
#include <QStringList>

namespace {

const auto blobVersion = QStringLiteral("omapass-pin.v1");
const auto keyringService = QStringLiteral("omapass");
const auto attemptsSetting = QStringLiteral("bitwarden/pinAttempts");

// Bitwarden's own default, and about 90 ms here.
constexpr int pinIterations = 600000;

QString account(const QString &email) {
    return QStringLiteral("bitwarden-pin:") + email;
}

QStringList attributes(const QString &email) {
    return {QStringLiteral("service"), keyringService, QStringLiteral("account"), account(email)};
}

std::optional<BwKey> pinKey(const QString &pin, const QString &salt, int iterations) {
    BwKdf kdf;
    kdf.type = 0; // PBKDF2-SHA256
    kdf.iterations = iterations;
    return BwCrypto::deriveMasterKey(Secret(pin), salt, kdf);
}

}

namespace BwPin {

QString buildBlob(const Blob &blob) {
    return blobVersion + QLatin1Char('|') + blob.salt + QLatin1Char('|')
        + QString::number(blob.iterations) + QLatin1Char('|') + blob.encrypted;
}

std::optional<Blob> parseBlob(const QString &text) {
    const QStringList parts = text.trimmed().split(QLatin1Char('|'));
    // The EncString carries two '|' of its own, so the split is bounded at
    // the front and everything after the third field is the ciphertext.
    if (parts.size() != 6 || parts.at(0) != blobVersion)
        return std::nullopt;

    bool ok = false;
    Blob blob;
    blob.salt = parts.at(1);
    blob.iterations = parts.at(2).toInt(&ok);
    blob.encrypted = QStringList(parts.mid(3)).join(QLatin1Char('|'));
    if (!ok || blob.iterations <= 0 || blob.salt.isEmpty() || !blob.encrypted.startsWith(QLatin1String("2.")))
        return std::nullopt;
    return blob;
}

QString validate(const QString &pin, const QString &confirm) {
    static const QRegularExpression digits(QStringLiteral("^[0-9]+$"));
    if (pin.length() < minLength) {
        return I18n::t(QStringLiteral("bitwarden.pin_too_short"), QStringLiteral("min"),
                       QString::number(minLength));
    }
    if (!digits.match(pin).hasMatch())
        return I18n::t(QStringLiteral("bitwarden.pin_only_digits"));
    if (!confirm.isNull() && confirm != pin)
        return I18n::t(QStringLiteral("bitwarden.pin_mismatch"));
    return QString();
}

QString weakWarning(const QString &pin) {
    if (pin.length() < minLength || pin.length() >= recommendedLength)
        return QString();

    qint64 combinations = 1;
    for (int i = 0; i < pin.length(); ++i)
        combinations *= 10;

    return I18n::t(QStringLiteral("bitwarden.pin_weak"),
                   {{QStringLiteral("digits"), pin.length()},
                    {QStringLiteral("combinations"), QLocale::system().toString(combinations)},
                    {QStringLiteral("recommended"), recommendedLength}});
}

bool isAvailable() {
    return !QStandardPaths::findExecutable(QStringLiteral("secret-tool")).isEmpty();
}

bool hasPin(const QString &email) {
    if (email.isEmpty() || !isAvailable())
        return false;
    const ProcResult result = runProcess(QStringLiteral("secret-tool"),
                                         QStringList{QStringLiteral("lookup")} + attributes(email));
    return result.success && !result.out.trimmed().isEmpty();
}

bool store(const QString &email, const QString &pin, const Secret &masterPassword, QString *error) {
    if (!isAvailable()) {
        *error = I18n::t(QStringLiteral("bitwarden.pin_no_keyring"));
        return false;
    }

    const BwBytes saltBytes = BwCrypto::randomBytes(32);
    const QString salt = QString::fromLatin1(
        QByteArray(reinterpret_cast<const char *>(saltBytes.data()), qsizetype(saltBytes.size())).toBase64());

    const std::optional<BwKey> key = pinKey(pin, salt, pinIterations);
    const std::optional<QString> encrypted =
        key ? BwCrypto::encrypt(masterPassword.bytes(), *key) : std::nullopt;
    if (!encrypted) {
        *error = I18n::t(QStringLiteral("bitwarden.pin_store_error"));
        return false;
    }

    // The blob goes in on stdin: secret-tool would otherwise take it as an
    // argument, where `ps` can read it.
    QByteArray blob = buildBlob({salt, pinIterations, *encrypted}).toUtf8();
    const QStringList args = QStringList{QStringLiteral("store"), QStringLiteral("--label"),
                                         QStringLiteral("omapass (Bitwarden PIN)")}
        + attributes(email);
    const ProcResult result = runProcess(QStringLiteral("secret-tool"), args, blob);
    blob.fill('\0');

    if (!result.success) {
        *error = result.started ? result.err.trimmed()
                                : I18n::t(QStringLiteral("bitwarden.pin_no_keyring"));
        if (error->isEmpty())
            *error = I18n::t(QStringLiteral("bitwarden.pin_store_error"));
        return false;
    }

    resetAttempts();
    return true;
}

Result recover(const QString &email, const QString &pin, Secret *masterPassword) {
    if (!isAvailable())
        return Result::Unavailable;

    ProcResult stored = runProcess(QStringLiteral("secret-tool"),
                                   QStringList{QStringLiteral("lookup")} + attributes(email));
    if (!stored.success || stored.out.trimmed().isEmpty())
        return Result::Missing;

    const std::optional<Blob> blob = parseBlob(stored.out);
    stored.out.fill(QChar(0));
    if (!blob)
        return Result::Missing;

    const std::optional<BwKey> key = pinKey(pin, blob->salt, blob->iterations);
    // A wrong PIN fails the HMAC, so there is no separate check — and no
    // stored hash of the PIN to attack.
    const std::optional<BwBytes> password = key ? BwCrypto::decrypt(blob->encrypted, *key) : std::nullopt;
    if (!password)
        return Result::WrongPin;

    *masterPassword = Secret(QByteArray(reinterpret_cast<const char *>(password->data()),
                                        qsizetype(password->size())));
    return Result::Ok;
}

void clear(const QString &email) {
    if (isAvailable()) {
        runProcess(QStringLiteral("secret-tool"),
                   QStringList{QStringLiteral("clear")} + attributes(email));
    }
    resetAttempts();
}

int failedAttempts() {
    return QSettings().value(attemptsSetting, 0).toInt();
}

int registerFailure(const QString &email) {
    const int attempts = failedAttempts() + 1;
    if (attempts >= maxAttempts) {
        clear(email); // also resets the counter
        return 0;
    }

    QSettings().setValue(attemptsSetting, attempts);
    return maxAttempts - attempts;
}

void resetAttempts() {
    QSettings().remove(attemptsSetting);
}

}
