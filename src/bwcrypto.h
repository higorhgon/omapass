#pragma once

#include <QString>

#include <botan/secmem.h>

#include <optional>

#include "secret.h"

// Bitwarden's client-side cryptography, as far as reading a vault needs it:
// deriving the master key, unwrapping keys and decrypting EncStrings. Kept to
// what the formats in bw's data.json use; anything else is reported as
// unsupported so the caller can fall back to `bw`.
//
// Keys live in Botan::secure_vector, which wipes its memory when released.

using BwBytes = Botan::secure_vector<uint8_t>;

// A 64-byte symmetric key split into its two halves: AES-256 encryption key
// and HMAC-SHA256 key.
struct BwKey {
    BwBytes enc;
    BwBytes mac;
};

// KdfConfig as stored in data.json (`kdfType` 0 = PBKDF2-SHA256,
// 1 = Argon2id with `memory` in MiB).
struct BwKdf {
    int type = 0;
    int iterations = 0;
    int memory = 0;
    int parallelism = 0;
};

namespace BwCrypto {

// The 32-byte master key before stretching, exactly what the SDK's
// derive_kdf_material returns. Empty for an unknown KDF or bad parameters.
std::optional<BwBytes> deriveKdfMaterial(const Secret &password, const QString &salt, const BwKdf &kdf);

// derive_kdf_material followed by the HKDF-Expand "enc"/"mac" stretch.
std::optional<BwKey> deriveMasterKey(const Secret &password, const QString &salt, const BwKdf &kdf);

// A 64-byte key (enc ‖ mac) as a BwKey; empty when the size is wrong.
std::optional<BwKey> keyFromBytes(const BwBytes &bytes);

// Decrypts a type 2 EncString ("2.iv|data|mac", AES-256-CBC + HMAC-SHA256).
// The MAC is checked in constant time before anything is decrypted; a wrong
// key, a tampered string or any other type returns empty.
std::optional<BwBytes> decrypt(const QString &encString, const BwKey &key);
std::optional<QString> decryptString(const QString &encString, const BwKey &key);

// Encrypts into a type 2 EncString, with a fresh random IV each time. Used
// for omapass' own PIN store, so what it writes reads back through the same
// decrypt() as everything bw wrote.
std::optional<QString> encrypt(const QByteArray &plaintext, const BwKey &key);

// Random bytes from the system generator, for a salt or an IV.
BwBytes randomBytes(int size);

// Decrypts an EncString holding another 64-byte key.
std::optional<BwKey> unwrapKey(const QString &encString, const BwKey &key);

// Decrypts a type 3 (RSA-OAEP-SHA256) or type 4 (RSA-OAEP-SHA1) EncString
// with a PKCS#8 DER private key — how organisation keys are shared.
std::optional<BwBytes> rsaDecrypt(const QString &encString, const BwBytes &pkcs8PrivateKey);

}
