#include "pin.h"

#include "bwcrypto.h"
#include "i18n.h"
#include "process.h"

#include <QCryptographicHash>
#include <QLocale>
#include <QRegularExpression>
#include <QSettings>
#include <QStandardPaths>
#include <QStringList>

namespace {

const auto blobVersion = QStringLiteral("omapass-pin.v1");
const auto keyringService = QStringLiteral("omapass");
// Where the PIN of the single Bitwarden account lived before every database
// got one of its own.
const auto legacyPrefix = QStringLiteral("bitwarden-pin:");
const auto legacyBitwardenRef = QStringLiteral("bitwarden:");
const auto legacyAttemptsSetting = QStringLiteral("bitwarden/pinAttempts");

// Bitwarden's own default, and about 90 ms here.
constexpr int pinIterations = 600000;

QStringList attributesFor(const QString &account) {
    return {QStringLiteral("service"), keyringService, QStringLiteral("account"), account};
}

QStringList attributes(const QString &vaultPath) {
    return attributesFor(Pin::accountAttribute(vaultPath));
}

QString lookupBlob(const QStringList &attrs) {
    ProcResult stored = runProcess(QStringLiteral("secret-tool"),
                                   QStringList{QStringLiteral("lookup")} + attrs);
    if (!stored.success)
        return QString();
    const QString blob = stored.out.trimmed();
    stored.out.fill(QChar(0));
    return blob;
}

bool writeBlob(const QStringList &attrs, QByteArray blob, QString *error) {
    // The blob goes in on stdin: secret-tool would otherwise take it as an
    // argument, where `ps` can read it.
    const QStringList args = QStringList{QStringLiteral("store"), QStringLiteral("--label"),
                                         QStringLiteral("omapass (PIN)")}
        + attrs;
    const ProcResult result = runProcess(QStringLiteral("secret-tool"), args, blob);
    blob.fill('\0');

    if (!result.success && error) {
        *error = result.started ? result.err.trimmed() : I18n::t(QStringLiteral("pin.no_keyring"));
        if (error->isEmpty())
            *error = I18n::t(QStringLiteral("pin.store_error"));
    }
    return result.success;
}

// A PIN set before PINs were per database sits under the old attribute; it
// is moved on first use, so nobody has to set it up again. The blob itself
// is unchanged, so moving it is a copy.
QString migrateLegacy(const QString &vaultPath) {
    if (!vaultPath.startsWith(legacyBitwardenRef))
        return QString();

    const QStringList legacy = attributesFor(legacyPrefix + vaultPath.mid(legacyBitwardenRef.size()));
    const QString blob = lookupBlob(legacy);
    if (blob.isEmpty())
        return QString();

    QByteArray moved = blob.toUtf8();
    const bool stored = writeBlob(attributes(vaultPath), moved, nullptr);
    moved.fill('\0');
    if (!stored)
        return QString();

    runProcess(QStringLiteral("secret-tool"), QStringList{QStringLiteral("clear")} + legacy);
    QSettings settings;
    if (settings.contains(legacyAttemptsSetting)) {
        settings.setValue(Pin::attemptsKey(vaultPath), settings.value(legacyAttemptsSetting));
        settings.remove(legacyAttemptsSetting);
    }
    return blob;
}

// The stored blob for a database, moving a pre-per-database one over if that
// is where it still is.
QString storedBlob(const QString &vaultPath) {
    const QString blob = lookupBlob(attributes(vaultPath));
    return blob.isEmpty() ? migrateLegacy(vaultPath) : blob;
}

std::optional<BwKey> pinKey(const QString &pin, const QString &salt, int iterations) {
    BwKdf kdf;
    kdf.type = 0; // PBKDF2-SHA256
    kdf.iterations = iterations;
    return BwCrypto::deriveMasterKey(Secret(pin), salt, kdf);
}

}

namespace Pin {

QString accountAttribute(const QString &vaultPath) {
    return QStringLiteral("pin:") + vaultPath;
}

QString attemptsKey(const QString &vaultPath) {
    // A path cannot be a settings key (slashes are groups there), so the
    // counter hangs off a digest of it — which also keeps the file from
    // listing where every database is.
    const QByteArray digest =
        QCryptographicHash::hash(vaultPath.toUtf8(), QCryptographicHash::Sha256).toHex().left(16);
    return QStringLiteral("pin/attempts/") + QString::fromLatin1(digest);
}

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
        return I18n::t(QStringLiteral("pin.too_short"), QStringLiteral("min"),
                       QString::number(minLength));
    }
    if (!digits.match(pin).hasMatch())
        return I18n::t(QStringLiteral("pin.only_digits"));
    if (!confirm.isNull() && confirm != pin)
        return I18n::t(QStringLiteral("pin.mismatch"));
    return QString();
}

QString weakWarning(const QString &pin) {
    if (pin.length() < minLength || pin.length() >= recommendedLength)
        return QString();

    qint64 combinations = 1;
    for (int i = 0; i < pin.length(); ++i)
        combinations *= 10;

    return I18n::t(QStringLiteral("pin.weak"),
                   {{QStringLiteral("digits"), pin.length()},
                    {QStringLiteral("combinations"), QLocale::system().toString(combinations)},
                    {QStringLiteral("recommended"), recommendedLength}});
}

bool isAvailable() {
    return !QStandardPaths::findExecutable(QStringLiteral("secret-tool")).isEmpty();
}

bool hasPin(const QString &vaultPath) {
    if (vaultPath.isEmpty() || !isAvailable())
        return false;
    return !storedBlob(vaultPath).isEmpty();
}

bool store(const QString &vaultPath, const QString &pin, const Secret &password, QString *error) {
    if (!isAvailable()) {
        *error = I18n::t(QStringLiteral("pin.no_keyring"));
        return false;
    }

    const BwBytes saltBytes = BwCrypto::randomBytes(32);
    const QString salt = QString::fromLatin1(
        QByteArray(reinterpret_cast<const char *>(saltBytes.data()), qsizetype(saltBytes.size())).toBase64());

    const std::optional<BwKey> key = pinKey(pin, salt, pinIterations);
    const std::optional<QString> encrypted =
        key ? BwCrypto::encrypt(password.bytes(), *key) : std::nullopt;
    if (!encrypted) {
        *error = I18n::t(QStringLiteral("pin.store_error"));
        return false;
    }

    QByteArray blob = buildBlob({salt, pinIterations, *encrypted}).toUtf8();
    const bool ok = writeBlob(attributes(vaultPath), blob, error);
    blob.fill('\0');
    if (!ok)
        return false;

    resetAttempts(vaultPath);
    return true;
}

Result recover(const QString &vaultPath, const QString &pin, Secret *password) {
    if (!isAvailable())
        return Result::Unavailable;

    QString stored = storedBlob(vaultPath);
    if (stored.isEmpty())
        return Result::Missing;

    const std::optional<Blob> blob = parseBlob(stored);
    stored.fill(QChar(0));
    if (!blob)
        return Result::Missing;

    const std::optional<BwKey> key = pinKey(pin, blob->salt, blob->iterations);
    // A wrong PIN fails the HMAC, so there is no separate check — and no
    // stored hash of the PIN to attack.
    const std::optional<BwBytes> plaintext = key ? BwCrypto::decrypt(blob->encrypted, *key) : std::nullopt;
    if (!plaintext)
        return Result::WrongPin;

    *password = Secret(QByteArray(reinterpret_cast<const char *>(plaintext->data()),
                                  qsizetype(plaintext->size())));
    return Result::Ok;
}

void clear(const QString &vaultPath) {
    if (isAvailable()) {
        runProcess(QStringLiteral("secret-tool"),
                   QStringList{QStringLiteral("clear")} + attributes(vaultPath));
        if (vaultPath.startsWith(legacyBitwardenRef)) {
            const QString account = legacyPrefix + vaultPath.mid(legacyBitwardenRef.size());
            runProcess(QStringLiteral("secret-tool"),
                       QStringList{QStringLiteral("clear")} + attributesFor(account));
        }
    }
    resetAttempts(vaultPath);
}

int failedAttempts(const QString &vaultPath) {
    return QSettings().value(attemptsKey(vaultPath), 0).toInt();
}

int registerFailure(const QString &vaultPath) {
    const int attempts = failedAttempts(vaultPath) + 1;
    if (attempts >= maxAttempts) {
        clear(vaultPath); // also resets the counter
        return 0;
    }

    QSettings().setValue(attemptsKey(vaultPath), attempts);
    return maxAttempts - attempts;
}

void resetAttempts(const QString &vaultPath) {
    QSettings settings;
    settings.remove(attemptsKey(vaultPath));
    settings.remove(legacyAttemptsSetting);
}

}
