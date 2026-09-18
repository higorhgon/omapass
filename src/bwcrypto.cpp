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
#include <botan/version.h>

#include <cstring>

namespace {

// Botan 3 scoped what Botan 2 left loose, and dropped a parameter PKCS#8
// loading no longer needs. Everything else omapass uses is spelled the same
// in both, which is what lets a build on Ubuntu 24.04 (Botan 2.19) work.
#if BOTAN_VERSION_MAJOR >= 3
constexpr auto decryptDirection = Botan::Cipher_Dir::Decryption;
constexpr auto encryptDirection = Botan::Cipher_Dir::Encryption;
#else
constexpr auto decryptDirection = Botan::DECRYPTION;
constexpr auto encryptDirection = Botan::ENCRYPTION;
#endif

std::unique_ptr<Botan::Private_Key> loadPrivateKey(Botan::DataSource &source) {
#if BOTAN_VERSION_MAJOR >= 3
    return Botan::PKCS8::load_key(source);
#else
    // Botan 2 hands back a raw pointer, and wants an RNG it no longer needs.
    Botan::System_RNG rng;
    return std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(source, rng));
#endif
}


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
            hash->derive_key(out.data(), out.size(), password.bytes().constData(),
                             size_t(password.bytes().size()),
                             reinterpret_cast<const uint8_t *>(saltBytes.constData()),
                             size_t(saltBytes.size()));
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
            hash->derive_key(out.data(), out.size(), password.bytes().constData(),
                             size_t(password.bytes().size()), hashedSalt.data(), hashedSalt.size());
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
        // No salt: this is HKDF-Expand only, as the SDK's stretch does.
        // Botan 3 deprecated the pointer form that Botan 2 only has.
        const auto expand = [&hkdf, &material](const char *label) {
#if BOTAN_VERSION_MAJOR >= 3
            return hkdf->derive_key(32, *material, std::span<const uint8_t>(),
                                    std::span(reinterpret_cast<const uint8_t *>(label),
                                              std::strlen(label)));
#else
            return hkdf->derive_key(32, material->data(), material->size(),
                                    static_cast<const uint8_t *>(nullptr), size_t(0),
                                    reinterpret_cast<const uint8_t *>(label), std::strlen(label));
#endif
        };

        BwKey key;
        key.enc = expand("enc");
        key.mac = expand("mac");
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

        const auto aes = Botan::Cipher_Mode::create_or_throw("AES-256/CBC/PKCS7", decryptDirection);
        aes->set_key(key.enc);
        aes->start(iv);
        aes->finish(data);
        return data;
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

std::optional<QString> encrypt(const QByteArray &plaintext, const BwKey &key) {
    if (key.enc.size() != 32 || key.mac.size() != 32)
        return std::nullopt;

    try {
        const BwBytes iv = randomBytes(16);
        BwBytes data(plaintext.cbegin(), plaintext.cend());

        const auto aes = Botan::Cipher_Mode::create_or_throw("AES-256/CBC/PKCS7", encryptDirection);
        aes->set_key(key.enc);
        aes->start(iv);
        aes->finish(data);

        const auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
        hmac->set_key(key.mac);
        hmac->update(iv);
        hmac->update(data);
        const auto mac = hmac->final();

        const auto base64 = [](const BwBytes &bytes) {
            return QByteArray(reinterpret_cast<const char *>(bytes.data()), qsizetype(bytes.size())).toBase64();
        };
        return QStringLiteral("2.") + QString::fromLatin1(base64(iv)) + QLatin1Char('|')
            + QString::fromLatin1(base64(data)) + QLatin1Char('|')
            + QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(mac.data()),
                                             qsizetype(mac.size())).toBase64());
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

BwBytes randomBytes(int size) {
    BwBytes bytes(size_t(size < 0 ? 0 : size));
    try {
        Botan::System_RNG rng;
        rng.randomize(bytes.data(), bytes.size());
    } catch (const std::exception &) {
        bytes.clear();
    }
    return bytes;
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
        const std::unique_ptr<Botan::Private_Key> privateKey = loadPrivateKey(source);
        Botan::System_RNG rng;
        Botan::PK_Decryptor_EME decryptor(*privateKey, rng, padding);
        const BwBytes data = fromBase64(body);
        return decryptor.decrypt(data);
    } catch (const std::exception &) {
        return std::nullopt;
    }
}

}
