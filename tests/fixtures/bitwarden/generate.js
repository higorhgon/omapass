#!/usr/bin/env node
// Regenerates the Bitwarden fixtures with Bitwarden's own crypto: the SDK
// (PureCrypto) bundled in the installed `bw` CLI, so the tests check omapass
// against the reference implementation rather than against itself.
//
//   node tests/fixtures/bitwarden/generate.js [/usr/lib/node_modules/@bitwarden/cli/build]
//
// The bundle has no entry point for the SDK alone, so a copy of bw.js is made
// in a temporary directory with its CLI start-up swapped for loading the SDK
// and calling `buildFixtures` below.
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

function main() {
    const build = process.argv[2] || "/usr/lib/node_modules/@bitwarden/cli/build";
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "omapass-bw-sdk-"));
    for (const name of fs.readdirSync(build))
        fs.cpSync(path.join(build, name), path.join(dir, name), { recursive: true });
    fs.symlinkSync(path.join(build, "..", "node_modules"), path.join(dir, "node_modules"));

    const bundle = fs.readFileSync(path.join(build, "bw.js"), "utf8");
    const start = "// eslint-disable-next-line @typescript-eslint/no-floating-promises\nmain();";
    if (!bundle.includes(start))
        throw new Error("bw.js layout changed: CLI start-up not found");
    fs.writeFileSync(path.join(dir, "sdk.js"), bundle.replace(start,
        "new CliSdkLoadService().loadAndInit().then(() => SdkLoadService.Ready).then(() => {\n" +
        "    globalThis.PureCrypto = bitwarden_wasm_internal_bg.IEs;\n" +
        "    globalThis.omapassBuildFixtures();\n" +
        "}).catch((e) => { console.error(e); process.exit(1); });"));

    globalThis.omapassBuildFixtures = () => {
        try {
            buildFixtures();
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    };
    require(path.join(dir, "sdk.js"));
}

function buildFixtures() {
    const PC = globalThis.PureCrypto;
    const out = __dirname;
    const utf8 = (s) => new TextEncoder().encode(s);
    const hex = (bytes) => Buffer.from(bytes).toString("hex");

    const password = "omapass-teste-123";
    const email = "teste@exemplo.com";
    // Few iterations keep the tests fast; the algorithm is the same at 600000.
    const pbkdf2 = { pBKDF2: { iterations: 5000 } };
    const argon2 = { argon2id: { iterations: 2, memory: 16, parallelism: 1 } };

    const vectors = {
        password,
        salt: email,
        pbkdf2: { iterations: 5000, masterKey: hex(PC.derive_kdf_material(utf8(password), utf8(email), pbkdf2)) },
        argon2id: { iterations: 2, memory: 16, parallelism: 1,
                    masterKey: hex(PC.derive_kdf_material(utf8(password), utf8(email), argon2)) },
    };

    const symmetricKey = PC.make_user_key_aes256_cbc_hmac();
    vectors.encString = {
        key: hex(symmetricKey),
        plaintext: "Olá, omapass! 🔐",
        encrypted: PC.symmetric_encrypt_string("Olá, omapass! 🔐", symmetricKey),
    };
    vectors.userKeyArgon2id = {
        userKey: hex(symmetricKey),
        wrapped: PC.encrypt_user_key_with_master_password(symmetricKey, password, email, argon2),
    };

    // A whole data.json the way bw stores an account, with every shape the
    // reader has to handle: a folder, a login with its own item key, a legacy
    // login encrypted straight with the user key, an organisation login, a
    // secure note (ignored) and a login in the trash (ignored).
    const userId = "11111111-2222-3333-4444-555555555555";
    const orgId = "99999999-8888-7777-6666-555555555555";
    const userKey = PC.make_user_key_aes256_cbc_hmac();
    const privateKey = PC.rsa_generate_keypair();
    const orgKey = PC.make_user_key_aes256_cbc_hmac();
    const enc = (text, key) => (text == null ? null : PC.symmetric_encrypt_string(text, key));

    const plainItems = [
        { id: "c1", folderId: "f1", organizationId: null, ownKey: true, type: 1, name: "Gmail",
          username: "eu@gmail.com", password: "s3nh@-gm", uri: "https://mail.google.com", notes: "pessoal",
          totp: "otpauth://totp/x?secret=ABC" },
        { id: "c2", folderId: null, organizationId: null, ownKey: false, type: 1, name: "Banco",
          username: "12345", password: "p@ss/banco", uri: null, notes: null, totp: null },
        { id: "c3", folderId: null, organizationId: orgId, ownKey: true, type: 1, name: "Servidor",
          username: "root", password: "org-secret", uri: "ssh://srv", notes: "compartilhado", totp: null },
        { id: "c4", folderId: null, organizationId: null, ownKey: false, type: 2, name: "Nota",
          notes: "só uma nota" },
        { id: "c5", folderId: null, organizationId: null, ownKey: false, type: 1, name: "Apagado",
          username: "x", password: "y", uri: null, notes: null, totp: null, deleted: true },
    ];

    const ciphers = {};
    for (const item of plainItems) {
        const baseKey = item.organizationId ? orgKey : userKey;
        const itemKey = item.ownKey ? PC.make_user_key_aes256_cbc_hmac() : baseKey;
        const cipher = {
            id: item.id, organizationId: item.organizationId, folderId: item.folderId,
            edit: true, viewPassword: true, organizationUseTotp: false, favorite: false,
            revisionDate: "2026-09-17T12:00:00.000Z", type: item.type,
            name: enc(item.name, itemKey), notes: enc(item.notes, itemKey),
            collectionIds: item.organizationId ? ["col1"] : [], creationDate: "2026-09-17T12:00:00.000Z",
            deletedDate: item.deleted ? "2026-09-17T12:30:00.000Z" : null, reprompt: 0,
            key: item.ownKey ? PC.wrap_symmetric_key(itemKey, baseKey) : null,
            fields: [], passwordHistory: [], attachments: null,
        };
        if (item.type === 1) {
            cipher.login = {
                username: enc(item.username, itemKey), password: enc(item.password, itemKey),
                totp: enc(item.totp, itemKey), passwordRevisionDate: null,
                uris: item.uri ? [{ uri: enc(item.uri, itemKey), uriChecksum: null, match: null }] : [],
            };
            if (item.id === "c1")
                cipher.fields = [{ name: enc("pin", itemKey), value: enc("4321", itemKey), type: 1, linkedId: null }];
        } else {
            cipher.secureNote = { type: 0 };
        }
        ciphers[item.id] = cipher;
    }

    const u = (key) => `user_${userId}_${key}`;
    const dataJson = {
        stateVersion: 75,
        global_account_activeAccountId: userId,
        global_account_accounts: { [userId]: { email, emailVerified: true, creationDate: "2026-09-17T12:00:00.000Z" } },
        [u("masterPasswordUnlock_masterPasswordUnlockKey")]: {
            salt: email, kdf: { kdfType: 0, iterations: 5000 },
            masterKeyWrappedUserKey: PC.encrypt_user_key_with_master_password(userKey, password, email, pbkdf2),
        },
        [u("kdfConfig_kdfConfig")]: { kdfType: 0, iterations: 5000 },
        [u("token_accessToken")]: "not-a-real-token",
        [u("crypto_accountCryptographicState")]: { V1: { private_key: PC.wrap_decapsulation_key(privateKey, userKey) } },
        [u("crypto_organizationKeys")]: {
            [orgId]: { type: "organization", key: PC.encapsulate_key_unsigned(orgKey, PC.rsa_extract_public_key(privateKey)) },
        },
        [u("folder_folders")]: { f1: { id: "f1", name: enc("Trabalho/Email", userKey), revisionDate: "2026-09-17T12:00:00.000Z" } },
        [u("ciphers_ciphers")]: ciphers,
    };

    // What reading that data.json must produce, in `bw list items` terms.
    const expected = {
        folders: { f1: "Trabalho/Email" },
        items: plainItems.filter((i) => i.type === 1 && !i.deleted).map((i) => ({
            id: i.id, name: i.name, folderId: i.folderId, organizationId: i.organizationId,
            username: i.username, password: i.password, uri: i.uri, notes: i.notes, totp: i.totp,
        })),
    };

    fs.writeFileSync(path.join(out, "vectors.json"), JSON.stringify(vectors, null, 2) + "\n");
    fs.writeFileSync(path.join(out, "data.json"), JSON.stringify(dataJson, null, 2) + "\n");
    fs.writeFileSync(path.join(out, "expected.json"), JSON.stringify(expected, null, 2) + "\n");
    console.log("fixtures written to " + out);
}

main();
