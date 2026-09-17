#include "bwcrypto.h"

#include <QByteArray>
#include <QStringList>

#include <botan/cipher_mode.h>
#include <botan/data_src.h>
#include <botan/hash.h>
#include <botan/kdf.h>
#include <botan/mac.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/pwdhash.h>
#include <botan/system_rng.h>

namespace {

BwBytes fromBase64(const QString &text) {
    const QByteArray decoded = QByteArray::fromBase64(text.toLatin1(), QByteArray::AbortOnBase64DecodingErrors);
    return BwBytes(decoded.cbegin(), decoded.cend());
}

// Splits "<type>.<body>" and returns the type, or -1 when malformed.
int encStringType(const QString &encString, QString *body) {
    const int dot = encString.indexOf(QLatin1Char('.'));
    if (dot <= 0)
        return -1;
    bool ok = false;
    const int type = encString.left(dot).toInt(&ok);
    if (!ok)
        return -1;
    *body = encString.mid(dot + 1);
    return type;
}

}

namespace BwCrypto {

std::optional<BwBytes> deriveKdfMaterial(const Secret &password, const QString &salt, const BwKdf &kdf) {
    if (kdf.iterations <= 0)
        return std::nullopt;

    const QByteArray saltBytes = salt.toUtf8();
    BwBytes out(32);

    try {
        if (kdf.type == 0) {
            const auto family = Botan::PasswordHashFamily::create_or_throw("PBKDF2(SHA-256)");
            const auto hash = family->from_params(size_t(kdf.iterations));
            hash->hash(out, std::string_view(password.bytes().constData(), size_t(password.bytes().size())),
                       std::span(reinterpret_cast<const uint8_t *>(saltBytes.constData()), size_t(saltBytes.size())));
            return out;
        }

        if (kdf.type == 1) {
            if (kdf.memory <= 0 || kdf.parallelism <= 0)
                return std::nullopt;
            // Argon2 wants at least 16 bytes of salt, so Bitwarden salts it
            // with the SHA-256 of the e-mail instead of the e-mail itself.
            const auto sha256 = Botan::HashFunction::create_or_throw("SHA-256");
            const auto hashedSalt = sha256->process(reinterpret_cast<const uint8_t *>(saltBytes.constData()),
                                                    size_t(saltBytes.size()));

            const auto family = Botan::PasswordHashFamily::create_or_throw("Argon2id");
            const auto hash = family->from_params(size_t(kdf.memory) * 1024, size_t(kdf.iterations),
                                                  size_t(kdf.parallelism));
            hash->hash(out, std::string_view(password.bytes().constData(), size_t(password.bytes().size())),
                       std::span(hashedSalt.data(), hashedSalt.size()));
            return out;
        }
    } catch (const std::exception &) {
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<BwKey> deriveMasterKey(const Secret &password, const QString &salt, const BwKdf &kdf) {
    const std::optional<BwBytes> material = deriveKdfMaterial(password, salt, kdf);
    if (!material)
        return std::nullopt;

    try {
        // HKDF-Expand only (no extract step), as the SDK's stretch does.
        const auto hkdf = Botan::KDF::create_or_throw("HKDF-Expand(SHA-256)");
        const std::string_view enc = "enc";
        const std::string_view mac = "mac";
        BwKey key;
        key.enc = hkdf->derive_key(32, *material, std::span<const uint8_t>(),
                                   std::span(reinterpret_cast<const uint8_t *>(enc.data()), enc.size()));
        key.mac = hkdf->derive_key(32, *material, std::span<const uint8_t>(),
                                   std::span(reinterpret_cast<const uint8_t *>(mac.data()), mac.size()));
        return key;
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

std::optional<BwKey> keyFromBytes(const BwBytes &bytes) {
    if (bytes.size() != 64)
        return std::nullopt;
    BwKey key;
    key.enc.assign(bytes.begin(), bytes.begin() + 32);
    key.mac.assign(bytes.begin() + 32, bytes.end());
    return key;
}

std::optional<BwBytes> decrypt(const QString &encString, const BwKey &key) {
    QString body;
    if (encStringType(encString, &body) != 2 || key.enc.size() != 32 || key.mac.size() != 32)
        return std::nullopt;

    const QStringList parts = body.split(QLatin1Char('|'));
    if (parts.size() != 3)
        return std::nullopt;

    const BwBytes iv = fromBase64(parts.at(0));
    BwBytes data = fromBase64(parts.at(1));
    const BwBytes mac = fromBase64(parts.at(2));
    if (iv.size() != 16 || data.empty() || data.size() % 16 != 0 || mac.size() != 32)
        return std::nullopt;

    try {
        const auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
        hmac->set_key(key.mac);
        hmac->update(iv);
        hmac->update(data);
        if (!hmac->verify_mac(mac))
            return std::nullopt;

        const auto aes = Botan::Cipher_Mode::create_or_throw("AES-256/CBC/PKCS7", Botan::Cipher_Dir::Decryption);
        aes->set_key(key.enc);
        aes->start(iv);
        aes->finish(data);
        return data;
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

std::optional<QString> decryptString(const QString &encString, const BwKey &key) {
    const std::optional<BwBytes> bytes = decrypt(encString, key);
    if (!bytes)
        return std::nullopt;
    return QString::fromUtf8(reinterpret_cast<const char *>(bytes->data()), qsizetype(bytes->size()));
}

std::optional<BwKey> unwrapKey(const QString &encString, const BwKey &key) {
    const std::optional<BwBytes> bytes = decrypt(encString, key);
    return bytes ? keyFromBytes(*bytes) : std::nullopt;
}

std::optional<BwBytes> rsaDecrypt(const QString &encString, const BwBytes &pkcs8PrivateKey) {
    QString body;
    const int type = encStringType(encString, &body);
    const char *padding = type == 3 ? "OAEP(SHA-256)" : type == 4 ? "OAEP(SHA-1)" : nullptr;
    if (!padding)
        return std::nullopt;

    // Types 5 and 6 carried a MAC after a '|'; 3 and 4 are the data alone.
    if (body.contains(QLatin1Char('|')))
        return std::nullopt;

    try {
        Botan::DataSource_Memory source(pkcs8PrivateKey);
        const std::unique_ptr<Botan::Private_Key> privateKey = Botan::PKCS8::load_key(source);
        Botan::System_RNG rng;
        Botan::PK_Decryptor_EME decryptor(*privateKey, rng, padding);
        const BwBytes data = fromBase64(body);
        return decryptor.decrypt(data);
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

}
