// Bitwarden's crypto, account, API and index.

#include "support.h"

#include "bitwardenjson.h"
#include "bwaccount.h"
#include "bwapi.h"
#include "bwcrypto.h"
#include "bwsync.h"
#include "i18n.h"

#include <QTcpServer>
#include <QTcpSocket>

namespace {

// An HTTP server on localhost that answers every request with one canned
// response and keeps what it was sent. BwApi waits in a nested event loop on
// this same thread, which is what serves the socket meanwhile.
struct FakeHttpServer {
    QTcpServer server;
    QByteArray response;
    QByteArray lastRequest;

    explicit FakeHttpServer(int status, const QByteArray &body) {
        response = "HTTP/1.1 " + QByteArray::number(status) + " Status\r\n"
                   "Content-Type: application/json\r\n"
                   "Content-Length: " + QByteArray::number(body.size()) + "\r\n"
                   "Connection: close\r\n\r\n" + body;
        server.listen(QHostAddress::LocalHost);
        QObject::connect(&server, &QTcpServer::newConnection, &server, [this]() {
            QTcpSocket *socket = server.nextPendingConnection();
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [this, socket]() {
                lastRequest += socket->readAll();
                const qsizetype headerEnd = lastRequest.indexOf("\r\n\r\n");
                if (headerEnd < 0)
                    return;
                qsizetype length = 0;
                for (const QByteArray &line : lastRequest.left(headerEnd).split('\n')) {
                    if (line.toLower().startsWith("content-length:"))
                        length = line.mid(15).trimmed().toLongLong();
                }
                if (lastRequest.size() < headerEnd + 4 + length)
                    return;
                socket->write(response);
                socket->disconnectFromHost();
            });
            QObject::connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
        });
    }

    QString url() const { return QStringLiteral("http://127.0.0.1:%1").arg(server.serverPort()); }
};

}

class TestBitwarden : public QObject {
    Q_OBJECT

private slots:
    void azureUploadUrlIsOnlyHttpsBlobStorage() {
        QVERIFY(isBwAzureUploadUrl(QStringLiteral(
            "https://sendprod.blob.core.windows.net/sendfiles/abc/def?sv=2019-07-07&sig=x")));
        QVERIFY(isBwAzureUploadUrl(QStringLiteral("https://SendProd.Blob.Core.Windows.Net:443/a")));
        QVERIFY(!isBwAzureUploadUrl(QStringLiteral("http://sendprod.blob.core.windows.net/a")));
        QVERIFY(!isBwAzureUploadUrl(QStringLiteral("https://evil.example/a")));
        QVERIFY(!isBwAzureUploadUrl(QStringLiteral("https://blob.core.windows.net.evil.example/a")));
        QVERIFY(!isBwAzureUploadUrl(QStringLiteral("https://evilblob.core.windows.net/a")));
        QVERIFY(!isBwAzureUploadUrl(QStringLiteral("https://.blob.core.windows.net/a")));
        QVERIFY(!isBwAzureUploadUrl(QStringLiteral("https://x.blob.core.windows.net@evil.example/a")));
        QVERIFY(!isBwAzureUploadUrl(QStringLiteral("https://x.blob.core.windows.net:8443/a")));
        QVERIFY(!isBwAzureUploadUrl(QString()));
    }

    void bitwardenServerIsNormalised() {
        // bitwarden.com, however it is written, is bw's default.
        for (const char *cloud : {"", "  ", "bitwarden.com", "vault.bitwarden.com",
                                  "https://vault.bitwarden.com/", "HTTPS://Bitwarden.com"})
            QCOMPARE(normalizeBwServer(QString::fromUtf8(cloud)), std::optional<QString>(QString()));

        QCOMPARE(normalizeBwServer(QStringLiteral("bitwarden.eu")),
                 std::optional<QString>(QStringLiteral("https://vault.bitwarden.eu")));
        QCOMPARE(normalizeBwServer(QStringLiteral(" vault.example.com ")),
                 std::optional<QString>(QStringLiteral("https://vault.example.com")));
        QCOMPARE(normalizeBwServer(QStringLiteral("https://Vault.Example.com:8443/bw/")),
                 std::optional<QString>(QStringLiteral("https://vault.example.com:8443/bw")));
        QCOMPARE(normalizeBwServer(QStringLiteral("localhost:8099")),
                 std::optional<QString>(QStringLiteral("https://localhost:8099")));

        // bw refuses plain http, and anything that is not an address.
        QVERIFY(!normalizeBwServer(QStringLiteral("http://vault.example.com")));
        QVERIFY(!normalizeBwServer(QStringLiteral("ftp://vault.example.com")));
        QVERIFY(!normalizeBwServer(QStringLiteral("https://")));
        QVERIFY(!normalizeBwServer(QStringLiteral("https://user:pw@vault.example.com")));
        QVERIFY(!normalizeBwServer(QStringLiteral("vault example com")));

        QCOMPARE(bwServerLabel(QString()), QStringLiteral("bitwarden.com"));
        QCOMPARE(bwServerLabel(QStringLiteral("https://vw.lan")), QStringLiteral("https://vw.lan"));
    }

    void bitwardenEntryDataReadsTheFirstUri() {
        const EntryData data = bwEntryData(QJsonDocument::fromJson(bwItemWithExtras).object());
        QCOMPARE(data.username, QStringLiteral("u"));
        QCOMPARE(data.password.toString(), QStringLiteral("p"));
        QCOMPARE(data.url, QStringLiteral("https://a"));
        // The other URIs are the entry's additional URLs.
        QCOMPARE(data.extraUrls, QStringList{QStringLiteral("https://b")});
        QCOMPARE(data.notes, QStringLiteral("n"));
    }

    void bitwardenDisplayNameDropsLeadingBlanks() {
        QCOMPARE(bwDisplayName(QStringLiteral("  Deploy ")), QStringLiteral("Deploy"));
        QCOMPARE(bwDisplayName(QString(QChar(0xFEFF)) + QStringLiteral("Deploy")), QStringLiteral("Deploy"));
        QCOMPARE(bwDisplayName(QStringLiteral("a/b")), QStringLiteral("a") + QChar(0x2215) + QStringLiteral("b"));
        QCOMPARE(bwDisplayName(QStringLiteral("   ")), QStringLiteral("(untitled)"));
    }

    void bitwardenSshKeyIsListedWithAFileReadyKey() {
        const QJsonObject item = QJsonDocument::fromJson(
            R"({"id":"s1","type":5,"name":"Deploy","notes":"n","folderId":null,"deletedDate":null,
                "sshKey":{"privateKey":"-----BEGIN KEY-----\r\nabc\r\n-----END KEY-----"}})").object();
        const EntryData data = bwEntryData(item);
        QCOMPARE(data.password.toString(), QStringLiteral("-----BEGIN KEY-----\nabc\n-----END KEY-----\n"));
        QCOMPARE(data.notes, QStringLiteral("n"));

        const BwIndex index = buildBwIndex({{QStringLiteral("s1"), item}}, {});
        QCOMPARE(index.entries, QStringList({QStringLiteral("Deploy")}));
    }

    void bitwardenIndexMapsFoldersToGroups() {
        const QByteArray folders(bwFolders);
        const QByteArray items(bwItems);

        const BwIndex index = buildBwIndex(bwItemsById(items), bwFoldersById(folders));
        QCOMPARE(index.groups, QStringList({QStringLiteral("Empty"), QStringLiteral("Work"),
                                            QStringLiteral("Work/Mail")}));
        QCOMPARE(index.entries, QStringList({QStringLiteral("A note"), QStringLiteral("Bank"),
                                             QStringLiteral("Lost"), QStringLiteral("Work/Mail/Gmail")}));
        QCOMPARE(index.items.value(QStringLiteral("Work/Mail/Gmail")).id, QStringLiteral("i1"));
        QCOMPARE(index.folders.value(QStringLiteral("Work/Mail")), QStringLiteral("f1"));
        QVERIFY(!index.folders.contains(QStringLiteral("Work")));
        QVERIFY(!index.folders.contains(QStringLiteral("No Folder")));
    }

    void bitwardenIndexDisambiguatesDuplicateNames() {
        const QByteArray items(bwDuplicateItems);

        const BwIndex index = buildBwIndex(bwItemsById(items), {});
        QVERIFY(index.items.contains(QStringLiteral("Mail [aaaaaaaa]")));
        QVERIFY(index.items.contains(QStringLiteral("Mail [bbbbbbbb]")));
        QVERIFY(!index.items.contains(QStringLiteral("Mail")));
        const QString slashed = QStringLiteral("a") + QChar(0x2215) + QStringLiteral("b");
        QCOMPARE(index.items.value(slashed).name, QStringLiteral("a/b"));
    }

    void bitwardenKdfMatchesTheSdk() {
        const QJsonObject v = bwFixture("vectors.json");
        const Secret password(v.value("password").toString());
        const QString salt = v.value("salt").toString();

        const QJsonObject pbkdf2 = v.value("pbkdf2").toObject();
        BwKdf kdf;
        kdf.type = 0;
        kdf.iterations = pbkdf2.value("iterations").toInt();
        QCOMPARE(BwCrypto::deriveKdfMaterial(password, salt, kdf), bwHex(pbkdf2.value("masterKey").toString()));

        const QJsonObject argon2 = v.value("argon2id").toObject();
        kdf.type = 1;
        kdf.iterations = argon2.value("iterations").toInt();
        kdf.memory = argon2.value("memory").toInt();
        kdf.parallelism = argon2.value("parallelism").toInt();
        QCOMPARE(BwCrypto::deriveKdfMaterial(password, salt, kdf), bwHex(argon2.value("masterKey").toString()));

        kdf.type = 7;
        QVERIFY(!BwCrypto::deriveKdfMaterial(password, salt, kdf));
    }

    void bitwardenEncStringsDecryptAndRejectTampering() {
        const QJsonObject v = bwFixture("vectors.json").value("encString").toObject();
        const std::optional<BwKey> key = BwCrypto::keyFromBytes(bwHex(v.value("key").toString()));
        QVERIFY(key);

        const QString encrypted = v.value("encrypted").toString();
        QCOMPARE(BwCrypto::decryptString(encrypted, *key), std::optional<QString>(v.value("plaintext").toString()));

        // A flipped bit anywhere fails the MAC before decryption.
        QString tampered = encrypted;
        const int dataStart = tampered.indexOf(QLatin1Char('|')) + 1;
        tampered[dataStart] = tampered[dataStart] == QLatin1Char('A') ? QLatin1Char('B') : QLatin1Char('A');
        QVERIFY(!BwCrypto::decryptString(tampered, *key));

        BwKey wrongKey = *key;
        wrongKey.mac[0] ^= 1;
        QVERIFY(!BwCrypto::decryptString(encrypted, wrongKey));

        QVERIFY(!BwCrypto::decryptString(QStringLiteral("7.") + encrypted.mid(2), *key));
        QVERIFY(!BwCrypto::decryptString(QStringLiteral("garbage"), *key));
    }

    void bitwardenEncryptRoundTripsAndSaltsEachTime() {
        const std::optional<BwKey> key = BwCrypto::keyFromBytes(BwCrypto::randomBytes(64));
        QVERIFY(key);

        const QByteArray plaintext = QByteArrayLiteral("senha mestra com acentuação");
        const std::optional<QString> first = BwCrypto::encrypt(plaintext, *key);
        const std::optional<QString> second = BwCrypto::encrypt(plaintext, *key);
        QVERIFY(first && second);
        QVERIFY(first->startsWith(QLatin1String("2.")));
        // A fresh IV every time, so the same text never looks the same twice.
        QVERIFY(*first != *second);

        QCOMPARE(BwCrypto::decryptString(*first, *key),
                 std::optional<QString>(QString::fromUtf8(plaintext)));

        QString tampered = *first;
        const int macStart = tampered.lastIndexOf(QLatin1Char('|')) + 1;
        tampered[macStart] = tampered[macStart] == QLatin1Char('A') ? QLatin1Char('B') : QLatin1Char('A');
        QVERIFY(!BwCrypto::decryptString(tampered, *key));

        const std::optional<BwKey> otherKey = BwCrypto::keyFromBytes(BwCrypto::randomBytes(64));
        QVERIFY(!BwCrypto::decryptString(*first, *otherKey));
    }

    void bitwardenMasterPasswordUnwrapsTheUserKey() {
        const QJsonObject v = bwFixture("vectors.json");
        const QJsonObject wrapped = v.value("userKeyArgon2id").toObject();
        const QJsonObject argon2 = v.value("argon2id").toObject();
        BwKdf kdf;
        kdf.type = 1;
        kdf.iterations = argon2.value("iterations").toInt();
        kdf.memory = argon2.value("memory").toInt();
        kdf.parallelism = argon2.value("parallelism").toInt();

        const std::optional<BwKey> masterKey =
            BwCrypto::deriveMasterKey(Secret(v.value("password").toString()), v.value("salt").toString(), kdf);
        QVERIFY(masterKey);
        const std::optional<BwKey> userKey = BwCrypto::unwrapKey(wrapped.value("wrapped").toString(), *masterKey);
        QVERIFY(userKey);
        BwBytes joined = userKey->enc;
        joined.insert(joined.end(), userKey->mac.begin(), userKey->mac.end());
        QCOMPARE(joined, bwHex(wrapped.value("userKey").toString()));

        const std::optional<BwKey> wrongMaster =
            BwCrypto::deriveMasterKey(Secret(QStringLiteral("errada")), v.value("salt").toString(), kdf);
        QVERIFY(!BwCrypto::unwrapKey(wrapped.value("wrapped").toString(), *wrongMaster));
    }

    void bitwardenLoginErrorsAreClassified() {
        QCOMPARE(classifyBwLoginMessage(QStringLiteral("Username or password is incorrect. Try again"), false),
                 BwLoginError::WrongPassword);
        QCOMPARE(classifyBwLoginMessage(QStringLiteral("invalid_username_or_password"), false),
                 BwLoginError::WrongPassword);
        // Once the password went through, a refusal is about the code.
        QCOMPARE(classifyBwLoginMessage(QStringLiteral("Two-step token is invalid. Try again."), true),
                 BwLoginError::InvalidCode);
        QCOMPARE(classifyBwLoginMessage(QStringLiteral("Invalid TOTP code"), true), BwLoginError::InvalidCode);
        QCOMPARE(classifyBwLoginMessage(QStringLiteral("Something else"), false), BwLoginError::Other);
        QCOMPARE(classifyBwLoginMessage(QString(), false), BwLoginError::Other);
    }

    void bitwardenTwoStepMethodsOmapassCanAskFor() {
        // Authenticator, e-mail and YubiKey OTP, in that order; Duo (2),
        // passkeys (7) and the rest are left out.
        QCOMPARE(bwSupportedTwoFactor({7, 3, 1, 0, 2}), QList<int>({0, 1, 3}));
        QCOMPARE(bwSupportedTwoFactor({1}), QList<int>({1}));
        QVERIFY(bwSupportedTwoFactor({2, 7}).isEmpty());
    }

    void bitwardenApiAddressesFollowTheServer() {
        QCOMPARE(BwApi::identityUrl(QString()), QStringLiteral("https://identity.bitwarden.com"));
        QCOMPARE(BwApi::apiUrl(QString()), QStringLiteral("https://api.bitwarden.com"));
        QCOMPARE(BwApi::identityUrl(QStringLiteral("https://vault.bitwarden.eu")),
                 QStringLiteral("https://identity.bitwarden.eu"));
        QCOMPARE(BwApi::apiUrl(QStringLiteral("https://vault.bitwarden.eu")), QStringLiteral("https://api.bitwarden.eu"));
        QCOMPARE(BwApi::identityUrl(QStringLiteral("https://vw.lan:8443/bw")),
                 QStringLiteral("https://vw.lan:8443/bw/identity"));
        QCOMPARE(BwApi::apiUrl(QStringLiteral("https://vw.lan")), QStringLiteral("https://vw.lan/api"));
    }

    void bitwardenResponsesAreReadInCamelCase() {
        // How Bitwarden answers a login that needs a second step.
        const QJsonObject json = BwApi::camelized(QJsonDocument::fromJson(
            R"({"TwoFactorProviders2":{"0":null,"1":{"Email":"a***@b.com"}},"SsoEmail2faSessionToken":"t",
                "ErrorModel":{"Message":"Two factor required.","Object":"error"},"error_description":"x"})").object());
        QVERIFY(json.contains("twoFactorProviders2"));
        QVERIFY(json.value("twoFactorProviders2").toObject().contains("1"));
        QCOMPARE(json.value("twoFactorProviders2").toObject().value("1").toObject().value("email").toString(),
                 QStringLiteral("a***@b.com"));
        QCOMPARE(json.value("ssoEmail2faSessionToken").toString(), QStringLiteral("t"));

        BwResponse response;
        response.failure = BwResponse::Failure::Http;
        response.status = 400;
        response.json = json;
        QCOMPARE(response.message(), QStringLiteral("Two factor required."));

        response.json = QJsonObject{{"message", "The model state is invalid."},
                                    {"validationErrors", QJsonObject{{"Name", QJsonArray{"Name is too long."}}}}};
        QCOMPARE(response.message(), QStringLiteral("Name is too long."));

        response.json = QJsonObject();
        response.networkError = QStringLiteral("boom");
        QCOMPARE(response.message(), QStringLiteral("boom"));
    }

    void bitwardenMasterPasswordHashMatchesTheReference() {
        // base64(PBKDF2-SHA256(masterKey, password, 1)), computed apart from
        // omapass from the SDK's own master key.
        const QJsonObject v = bwFixture("vectors.json");
        const Secret hash = BwCrypto::masterPasswordHash(bwHex(v.value("pbkdf2").toObject().value("masterKey").toString()),
                                                         Secret(v.value("password").toString()));
        QCOMPARE(hash.toString(), QStringLiteral("ds9ELf+Hij7EVdmNphywwCy4tksKVEFsC9KhOdpTHBs="));
    }

    void bitwardenAccountDecryptsEveryKindOfLogin() {
        const BwAccountState state = bwStateFromFixture();
        const QJsonObject v = bwFixture("vectors.json");
        BwKeys keys;
        QCOMPARE(BwAccount::unlock(state, Secret(v.value("password").toString()), &keys), BwAccount::Unlock::Ok);
        QCOMPARE(keys.organizations.size(), 1);

        QHash<QString, QJsonObject> items;
        QHash<QString, QString> folders;
        BwAccount::decryptVault(state, keys, &items, &folders);

        const QJsonObject expected = bwFixture("expected.json");
        QCOMPARE(folders.value(QStringLiteral("f1")), QStringLiteral("Trabalho/Email"));
        QCOMPARE(folders.size(), 1);

        const QJsonArray expectedItems = expected.value("items").toArray();
        // The secure note is listed; the login in the trash is left out.
        QCOMPARE(items.size(), expectedItems.size());
        for (const QJsonValue &value : expectedItems) {
            const QJsonObject want = value.toObject();
            const QString id = want.value("id").toString();
            QVERIFY2(items.contains(id), qPrintable(id));

            const QJsonObject item = items.value(id);
            const EntryData data = bwEntryData(item);
            QCOMPARE(item.value("name").toString(), want.value("name").toString());
            QCOMPARE(item.value("folderId"), want.value("folderId"));
            QCOMPARE(item.value("organizationId"), want.value("organizationId"));
            QCOMPARE(data.username, want.value("username").toString());
            QCOMPARE(data.password.toString(), want.value("password").toString());
            QCOMPARE(data.url, want.value("uri").toString());
            QCOMPARE(data.notes, want.value("notes").toString());
            QCOMPARE(item.value("login").toObject().value("totp"), want.value("totp"));
        }

        const BwIndex index = buildBwIndex(items, folders);
        QVERIFY(index.items.contains(QStringLiteral("Trabalho/Email/Gmail")));
        QVERIFY(index.items.contains(QStringLiteral("Servidor")));
    }

    void bitwardenAccountRejectsAWrongPassword() {
        BwKeys keys;
        QCOMPARE(BwAccount::unlock(bwStateFromFixture(), Secret(QStringLiteral("errada")), &keys),
                 BwAccount::Unlock::WrongPassword);

        BwAccountState unknownKdf = bwStateFromFixture();
        unknownKdf.kdf.type = 9;
        QCOMPARE(BwAccount::unlock(unknownKdf, Secret(QStringLiteral("x")), &keys), BwAccount::Unlock::Unsupported);
    }

    void bitwardenAccountSkipsOnlyWhatDoesNotDecrypt() {
        // One login in a format this does not read: it is left out, and the
        // rest of the vault still opens — there is no other client to fall
        // back to.
        BwAccountState state = bwStateFromFixture();
        for (int i = 0; i < state.ciphers.size(); ++i) {
            QJsonObject cipher = state.ciphers.at(i).toObject();
            if (cipher.value("id").toString() == QLatin1String("c2")) {
                cipher.insert("name", QStringLiteral("7.bmV3LWZvcm1hdA=="));
                state.ciphers.replace(i, cipher);
            }
        }
        BwKeys keys;
        QCOMPARE(BwAccount::unlock(state, Secret(bwFixture("vectors.json").value("password").toString()), &keys),
                 BwAccount::Unlock::Ok);
        QHash<QString, QJsonObject> items;
        QHash<QString, QString> folders;
        int undecryptable = -1;
        BwAccount::decryptVault(state, keys, &items, &folders, &undecryptable);
        QVERIFY(!items.contains(QStringLiteral("c2")));
        QCOMPARE(items.size(), bwFixture("expected.json").value("items").toArray().size() - 1);
        // ...but it is counted, so the user hears about it.
        QCOMPARE(undecryptable, 1);
    }

    void bitwardenCountsOnlyWhatShouldHaveOpened() {
        // An unsupported cipher type (not listed) and a login in the trash are
        // left out on purpose; neither counts as lost.
        BwAccountState state = bwStateFromFixture();
        state.ciphers.append(QJsonObject{{"id", "desconhecido"}, {"type", 99}, {"name", "7.bmV3"}});
        state.ciphers.append(QJsonObject{{"id", "lixo"}, {"type", 1}, {"name", "7.bmV3"},
                                         {"deletedDate", "2026-01-01T00:00:00Z"}});
        BwKeys keys;
        QCOMPARE(BwAccount::unlock(state, Secret(bwFixture("vectors.json").value("password").toString()), &keys),
                 BwAccount::Unlock::Ok);
        QHash<QString, QJsonObject> items;
        QHash<QString, QString> folders;
        int undecryptable = -1;
        BwAccount::decryptVault(state, keys, &items, &folders, &undecryptable);
        QCOMPARE(undecryptable, 0);

        // Unreadable note, card and identity count as lost since they are listed.
        state.ciphers.append(QJsonObject{{"id", "nota"}, {"type", 2}, {"name", "7.bmV3"}});
        state.ciphers.append(QJsonObject{{"id", "cartao"}, {"type", 3}, {"name", "7.bmV3"}});
        state.ciphers.append(QJsonObject{{"id", "identidade"}, {"type", 4}, {"name", "7.bmV3"}});
        BwAccount::decryptVault(state, keys, &items, &folders, &undecryptable);
        QCOMPARE(undecryptable, 3);

        // A folder whose name does not open does count.
        state.folders.append(QJsonObject{{"id", "pasta"}, {"name", "2.aXY=|ZGF0YQ==|bWFj"}});
        BwAccount::decryptVault(state, keys, &items, &folders, &undecryptable);
        QCOMPARE(undecryptable, 4);
    }

    void bitwardenKdfOutsideTheSafeRangeIsRefused() {
        const auto kdf = [](int type, int iterations, int memory = 0, int parallelism = 0) {
            BwKdf k;
            k.type = type;
            k.iterations = iterations;
            k.memory = memory;
            k.parallelism = parallelism;
            return k;
        };
        // The edges the official clients accept are accepted.
        QVERIFY(BwCrypto::kdfIsSafe(kdf(0, 5000)));
        QVERIFY(BwCrypto::kdfIsSafe(kdf(0, 2000000)));
        QVERIFY(BwCrypto::kdfIsSafe(kdf(1, 2, 16, 1)));
        QVERIFY(BwCrypto::kdfIsSafe(kdf(1, 10, 1024, 16)));
        // One step past them is not, nor is a KDF nobody knows.
        QVERIFY(!BwCrypto::kdfIsSafe(kdf(0, 4999)));
        QVERIFY(!BwCrypto::kdfIsSafe(kdf(0, 2000001)));
        QVERIFY(!BwCrypto::kdfIsSafe(kdf(0, 1)));
        QVERIFY(!BwCrypto::kdfIsSafe(kdf(1, 1, 16, 1)));
        QVERIFY(!BwCrypto::kdfIsSafe(kdf(1, 11, 16, 1)));
        QVERIFY(!BwCrypto::kdfIsSafe(kdf(1, 3, 15, 1)));
        QVERIFY(!BwCrypto::kdfIsSafe(kdf(1, 3, 1025, 1)));
        QVERIFY(!BwCrypto::kdfIsSafe(kdf(1, 3, 64, 0)));
        QVERIFY(!BwCrypto::kdfIsSafe(kdf(1, 3, 64, 17)));
        QVERIFY(!BwCrypto::kdfIsSafe(kdf(9, 600000)));

        // Nothing is derived from parameters that are refused...
        QVERIFY(!BwCrypto::deriveKdfMaterial(Secret(QStringLiteral("x")), QStringLiteral("a@b.com"), kdf(0, 1)));

        // ...and an account saved with them does not try.
        BwAccountState weak = bwStateFromFixture();
        weak.kdf = kdf(0, 1);
        BwKeys keys;
        QCOMPARE(BwAccount::unlock(weak, Secret(QStringLiteral("x")), &keys), BwAccount::Unlock::UnsafeKdf);
    }

    void bitwardenApiCallSendsTheTokenAndReadsCamelCase() {
        FakeHttpServer server(200, R"({"Id": "u1", "Profile": {"Name": "Fulano"}})");
        QVERIFY(server.server.isListening());

        const BwResponse response =
            BwApi::call(server.url(), "GET", QStringLiteral("/sync"), Secret(QStringLiteral("o-token")));
        QVERIFY2(response.ok(), qPrintable(response.networkError));
        QCOMPARE(response.json.value("id").toString(), QStringLiteral("u1"));
        QCOMPARE(response.json.value("profile").toObject().value("name").toString(), QStringLiteral("Fulano"));

        QVERIFY(server.lastRequest.startsWith("GET /api/sync "));
        QVERIFY(server.lastRequest.contains("Authorization: Bearer o-token\r\n"));
        QVERIFY(server.lastRequest.contains("Device-Type: 25\r\n"));
        QVERIFY(server.lastRequest.contains("Cache-Control: no-store\r\n"));
    }

    void bitwardenApiTokenSendsAnEncodedForm() {
        FakeHttpServer server(200, R"({"access_token": "a"})");
        const BwApi::Form form{{QStringLiteral("grant_type"), QStringLiteral("password")},
                               {QStringLiteral("username"), QStringLiteral("a@b.com")},
                               {QStringLiteral("password"), QStringLiteral("a+b&c=d")}};
        const BwResponse response = BwApi::token(server.url(), form);
        QVERIFY2(response.ok(), qPrintable(response.networkError));

        QVERIFY(server.lastRequest.startsWith("POST /identity/connect/token "));
        const QByteArray body = server.lastRequest.mid(server.lastRequest.indexOf("\r\n\r\n") + 4);
        const QList<QByteArray> fields = body.split('&');
        QVERIFY(fields.contains("grant_type=password"));
        QVERIFY(fields.contains("username=a%40b.com"));
        // A '+' or '&' in the hash must not change what the server reads.
        QVERIFY(fields.contains("password=a%2Bb%26c%3Dd"));
        QVERIFY(fields.contains("client_id=cli"));
        QVERIFY(fields.contains("deviceIdentifier=" + BwApi::deviceIdentifier().toLatin1()));
    }

    void bitwardenApiErrorsCarryTheServerMessage() {
        FakeHttpServer server(400, R"({"error": "invalid_grant", "ErrorModel": {"Message": "Senha errada."}})");
        const BwResponse response = BwApi::token(server.url(), {});
        QVERIFY(!response.ok());
        QCOMPARE(response.failure, BwResponse::Failure::Http);
        QCOMPARE(response.status, 400);
        QCOMPARE(response.message(), QStringLiteral("Senha errada."));
    }

    void bitwardenApiWithNobodyListeningIsUnreachable() {
        quint16 port = 0;
        {
            QTcpServer closed;
            QVERIFY(closed.listen(QHostAddress::LocalHost));
            port = closed.serverPort();
        }
        const BwResponse response =
            BwApi::call(QStringLiteral("http://127.0.0.1:%1").arg(port), "GET", QStringLiteral("/sync"), Secret());
        QCOMPARE(response.failure, BwResponse::Failure::Unreachable);
        QCOMPARE(response.status, 0);
    }

    void bitwardenSyncDoesNotTakeAWeakerKdf() {
        BwAccountState state;
        state.kdf.type = 0;
        state.kdf.iterations = 600000;
        const QJsonObject sync = BwApi::camelized(QJsonDocument::fromJson(R"({
            "Profile": {"Id": "u1"},
            "UserDecryption": {"MasterPasswordUnlock": {"Kdf": {"KdfType": 0, "Iterations": 1}}}})").object());
        BwAccount::applySync(&state, sync);
        QCOMPARE(state.kdf.type, 0);
        QCOMPARE(state.kdf.iterations, 600000);
    }

    void bitwardenEditKeepsWhatItDoesNotModel() {
        const BwAccountState state = bwStateFromFixture();
        BwKeys keys;
        QCOMPARE(BwAccount::unlock(state, Secret(bwFixture("vectors.json").value("password").toString()), &keys),
                 BwAccount::Unlock::Ok);

        // The organisation login: its own item key, wrapped with the
        // organisation's, and what the server has in it beyond the form.
        QJsonObject original;
        for (const QJsonValue &value : state.ciphers) {
            if (!value.toObject().value("organizationId").toString().isEmpty())
                original = value.toObject();
        }
        QVERIFY(!original.isEmpty());
        original.insert("revisionDate", QStringLiteral("2026-01-01T00:00:00.000Z"));
        original.insert("fields", QJsonArray{QJsonObject{{"name", "2.keep|me|intact"}, {"type", 1}}});
        QJsonObject login = original.value("login").toObject();
        QJsonArray uris = login.value("uris").toArray();
        uris.append(QJsonObject{{"uri", "2.second|uri|kept"}, {"match", 3}});
        login.insert("uris", uris);
        login.insert("totp", QStringLiteral("2.totp|kept|asis"));
        original.insert("login", login);

        const std::optional<BwKey> key = BwAccount::cipherKey(original, keys);
        QVERIFY(key);

        EntryData data;
        data.username = QStringLiteral("novo-usuario");
        data.password = Secret(QStringLiteral("senha-nova"));
        data.url = QStringLiteral("https://c.example");
        data.extraUrls = QStringList{QStringLiteral("https://segunda.example")};
        data.otp = Secret(QStringLiteral("otpauth://totp/Org?secret=JBSWY3DPEHPK3PXP"));
        const QJsonObject request = BwAccount::cipherRequest(original, QStringLiteral("senha-velha"),
                                                             QStringLiteral("Novo nome"), QStringLiteral("f1"),
                                                             data, *key, QStringLiteral("user-1"));

        QCOMPARE(request.value("encryptedFor").toString(), QStringLiteral("user-1"));
        QCOMPARE(request.value("lastKnownRevisionDate").toString(), QStringLiteral("2026-01-01T00:00:00.000Z"));
        QCOMPARE(request.value("organizationId"), original.value("organizationId"));
        QCOMPARE(request.value("key"), original.value("key"));
        QCOMPARE(request.value("folderId").toString(), QStringLiteral("f1"));
        QCOMPARE(decrypted(request.value("name"), *key), QStringLiteral("Novo nome"));
        QVERIFY(request.value("notes").isNull());
        QCOMPARE(request.value("fields"), original.value("fields"));

        const QJsonObject newLogin = request.value("login").toObject();
        QCOMPARE(decrypted(newLogin.value("username"), *key), QStringLiteral("novo-usuario"));
        QCOMPARE(decrypted(newLogin.value("password"), *key), QStringLiteral("senha-nova"));
        // The form carries the TOTP now, so it is what was given, encrypted.
        QCOMPARE(decrypted(newLogin.value("totp"), *key),
                 QStringLiteral("otpauth://totp/Org?secret=JBSWY3DPEHPK3PXP"));
        QVERIFY(!newLogin.value("passwordRevisionDate").toString().isEmpty());

        const QJsonArray newUris = newLogin.value("uris").toArray();
        QCOMPARE(newUris.size(), uris.size());
        QCOMPARE(decrypted(newUris.at(0).toObject().value("uri"), *key), QStringLiteral("https://c.example"));
        QCOMPARE(decrypted(newUris.at(0).toObject().value("uriChecksum"), *key),
                 QString::fromLatin1(QCryptographicHash::hash("https://c.example", QCryptographicHash::Sha256).toBase64()));
        // The second URI is the form's additional one now, in the place (and
        // with the match setting) of the one that was there.
        QCOMPARE(decrypted(newUris.last().toObject().value("uri"), *key), QStringLiteral("https://segunda.example"));
        QCOMPARE(newUris.last().toObject().value("match").toInt(), 3);

        // The old password goes into the history, newest first.
        const QJsonArray history = request.value("passwordHistory").toArray();
        QCOMPARE(history.size(), 1);
        QCOMPARE(decrypted(history.at(0).toObject().value("password"), *key), QStringLiteral("senha-velha"));

        // The same password again leaves the history alone.
        data.password = Secret(QStringLiteral("senha-velha"));
        const QJsonObject unchanged = BwAccount::cipherRequest(original, QStringLiteral("senha-velha"),
                                                               QStringLiteral("x"), QString(), data, *key,
                                                               QStringLiteral("user-1"));
        QVERIFY(unchanged.value("passwordHistory").toArray().isEmpty());
        QVERIFY(unchanged.value("folderId").isNull());

        // And an emptied TOTP is removed.
        data.otp = Secret();
        const QJsonObject cleared = BwAccount::cipherRequest(original, QStringLiteral("senha-velha"),
                                                             QStringLiteral("x"), QString(), data, *key,
                                                             QStringLiteral("user-1"));
        QVERIFY(cleared.value("login").toObject().value("totp").isNull());
    }

    void bitwardenEntryDataReadsTheTotp() {
        QJsonObject item{{"type", 1},
                         {"login", QJsonObject{{"username", "a"}, {"totp", "steam://JBSWY3DPEHPK3PXP"}}}};
        QCOMPARE(bwEntryData(item).otp.toString(), QStringLiteral("steam://JBSWY3DPEHPK3PXP"));
        item.insert("login", QJsonObject{{"username", "a"}, {"totp", QJsonValue::Null}});
        QVERIFY(bwEntryData(item).otp.isEmpty());
    }

    void bitwardenCreatesSshCipher() {
        const auto key = BwCrypto::keyFromBytes(BwCrypto::randomBytes(64));
        EntryData data;
        data.password = Secret(QStringLiteral("private"));
        data.sshPublicKey = QStringLiteral("ssh-ed25519 YWJj");
        const auto request = BwAccount::cipherRequest({}, {}, QStringLiteral("Deploy"), {}, data, *key, {});
        QCOMPARE(request.value("type").toInt(), 5);
        QVERIFY(!request.contains("login"));
        const auto ssh = request.value("sshKey").toObject();
        QCOMPARE(decrypted(ssh.value("privateKey"), *key), data.password.toString());
        QCOMPARE(decrypted(ssh.value("publicKey"), *key), data.sshPublicKey);
        QCOMPARE(decrypted(ssh.value("keyFingerprint"), *key),
                 QStringLiteral("SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0"));
        data.sshPublicKey += QStringLiteral(" deploy");
        const auto edited = BwAccount::cipherRequest(request, data.password.toString(), QStringLiteral("Deploy"),
                                                    {}, data, *key, {});
        QCOMPARE(decrypted(edited.value("sshKey").toObject().value("publicKey"), *key), data.sshPublicKey);
    }

    void bitwardenNewItemStartsFromABlankLogin() {
        const std::optional<BwKey> key = BwCrypto::keyFromBytes(BwCrypto::randomBytes(64));
        EntryData data;
        data.password = Secret(QStringLiteral("p"));
        const QJsonObject request = BwAccount::cipherRequest(QJsonObject(), QString(), QStringLiteral("Site"),
                                                             QString(), data, *key, QStringLiteral("u"));
        QCOMPARE(request.value("type").toInt(), 1);
        QVERIFY(request.value("organizationId").isNull());
        QVERIFY(!request.contains("lastKnownRevisionDate"));
        QCOMPARE(decrypted(request.value("name"), *key), QStringLiteral("Site"));
        const QJsonObject login = request.value("login").toObject();
        QVERIFY(login.value("uris").toArray().isEmpty());
        QVERIFY(login.value("username").isNull());
        QCOMPARE(decrypted(login.value("password"), *key), QStringLiteral("p"));
        QVERIFY(request.value("passwordHistory").isNull());
    }

    void bitwardenSyncUpdatesTheAccount() {
        BwAccountState state;
        state.salt = QStringLiteral("a@b.com");
        state.kdf.type = 0;
        state.kdf.iterations = 600000;
        const QJsonObject sync = BwApi::camelized(QJsonDocument::fromJson(R"({
            "Profile": {"Id": "u1", "Key": "2.user|key|x", "PrivateKey": "2.private|key|x",
                        "Organizations": [{"Id": "o1", "Key": "4.orgkey"}, {"Id": "o2", "Key": null}]},
            "UserDecryption": {"MasterPasswordUnlock": {"Kdf": {"KdfType": 1, "Iterations": 3, "Memory": 64,
                               "Parallelism": 4}, "Salt": "a@b.com", "MasterKeyEncryptedUserKey": "2.newer|key|x"}},
            "Folders": [{"Id": "f1", "Name": "2.n|a|me"}],
            "Ciphers": [{"Id": "c1", "Type": 1}]})").object());
        BwAccount::applySync(&state, sync);

        QCOMPARE(state.userId, QStringLiteral("u1"));
        QCOMPARE(state.userKey, QStringLiteral("2.newer|key|x"));
        QCOMPARE(state.privateKey, QStringLiteral("2.private|key|x"));
        QCOMPARE(state.kdf.type, 1);
        QCOMPARE(state.kdf.memory, 64);
        QCOMPARE(state.kdf.parallelism, 4);
        QCOMPARE(state.organizationKeys, QJsonObject({{"o1", "4.orgkey"}}));
        QCOMPARE(state.folders.size(), 1);
        QCOMPARE(state.ciphers.first().toObject().value("id").toString(), QStringLiteral("c1"));
    }

    void bitwardenAccountIsSavedPerServer() {
        QDir(BwAccount::directory()).removeRecursively();

        QCOMPARE(BwAccount::refPath(QStringLiteral("a@b.com"), QString()), QStringLiteral("bitwarden:a@b.com"));
        const QString selfHosted = BwAccount::refPath(QStringLiteral("a@b.com"), QStringLiteral("https://vw.lan"));
        QCOMPARE(selfHosted, QStringLiteral("bitwarden:a@b.com|https://vw.lan"));
        QCOMPARE(BwAccount::emailOf(selfHosted), QStringLiteral("a@b.com"));
        QCOMPARE(BwAccount::serverOf(selfHosted), QStringLiteral("https://vw.lan"));
        QCOMPARE(BwAccount::serverOf(QStringLiteral("bitwarden:a@b.com")), QString());

        BwAccountState state = bwStateFromFixture();
        state.server = QStringLiteral("https://vw.lan");
        state.userId = QStringLiteral("u1");
        state.refreshToken = QStringLiteral("2.refresh|token|x");
        QString error;
        QVERIFY2(BwAccount::save(state, &error), qPrintable(error));

        const QString path = BwAccount::refPath(state.email, state.server);
        QCOMPARE(BwAccount::refPaths(), QStringList({path}));
        const std::optional<BwAccountState> loaded = BwAccount::load(path);
        QVERIFY(loaded);
        QCOMPARE(loaded->userKey, state.userKey);
        QCOMPARE(loaded->refreshToken, state.refreshToken);
        QCOMPARE(loaded->userId, state.userId);
        QCOMPARE(loaded->kdf.iterations, state.kdf.iterations);
        QCOMPARE(loaded->ciphers, state.ciphers);
        QVERIFY(!BwAccount::load(BwAccount::refPath(state.email, QString())));

        // Readable by the user only.
        const QFileInfo dir(BwAccount::directory());
        QCOMPARE(dir.permissions() & (QFileDevice::ReadGroup | QFileDevice::ReadOther), QFileDevice::Permissions());

        BwAccount::remove(path);
        QVERIFY(BwAccount::refPaths().isEmpty());
        QDir(BwAccount::directory()).removeRecursively();
    }

    void bitwardenSecureNoteDecryptIndexAndRequest() {
        const auto key = BwCrypto::keyFromBytes(BwCrypto::randomBytes(64));
        QVERIFY(key);

        EntryData data;
        data.isNote = true;
        data.notes = QStringLiteral("Conteudo confidencial da nota");
        const QJsonObject req = BwAccount::cipherRequest({}, {}, QStringLiteral("Chave de recuperacao"),
                                                         QString(), data, *key, QStringLiteral("u1"));
        QCOMPARE(req.value("type").toInt(), 2);
        QVERIFY(!req.contains("login"));
        QVERIFY(!req.contains("sshKey"));
        QCOMPARE(req.value("secureNote").toObject().value("type").toInt(), 0);
        QCOMPARE(decrypted(req.value("name"), *key), QStringLiteral("Chave de recuperacao"));
        QCOMPARE(decrypted(req.value("notes"), *key), QStringLiteral("Conteudo confidencial da nota"));

        QJsonObject cipher = req;
        cipher.insert(QStringLiteral("id"), QStringLiteral("note-1"));
        BwKeys keys;
        keys.user = *key;
        const std::optional<QJsonObject> item = BwAccount::decryptCipher(cipher, keys);
        QVERIFY(item);
        QCOMPARE(item->value("type").toInt(), 2);
        QCOMPARE(item->value("name").toString(), QStringLiteral("Chave de recuperacao"));
        QCOMPARE(item->value("notes").toString(), QStringLiteral("Conteudo confidencial da nota"));

        const EntryData parsed = bwEntryData(*item);
        QVERIFY(parsed.isNote);
        QCOMPARE(parsed.notes, QStringLiteral("Conteudo confidencial da nota"));

        const BwIndex index = buildBwIndex({{QStringLiteral("note-1"), *item}}, {});
        QCOMPARE(index.entries, QStringList({QStringLiteral("Chave de recuperacao")}));
    }

    void bitwardenSendCryptoAndUrls() {
        const BwBytes seed = BwCrypto::randomBytes(16);
        const std::optional<BwKey> sendKey = BwCrypto::deriveSendKey(seed);
        QVERIFY(sendKey);
        QCOMPARE(sendKey->enc.size(), size_t(32));
        QCOMPARE(sendKey->mac.size(), size_t(32));

        // Same seed always derives the same key.
        const std::optional<BwKey> again = BwCrypto::deriveSendKey(seed);
        QVERIFY(again);
        QCOMPARE(again->enc, sendKey->enc);
        QCOMPARE(again->mac, sendKey->mac);

        // EncArrayBuffer round-trip + tamper rejection.
        const QByteArray fileContent("Arquivo secreto de teste 1234567890");
        const std::optional<QByteArray> encrypted = BwCrypto::encryptBuffer(fileContent, *sendKey);
        QVERIFY(encrypted);
        QCOMPARE(uint8_t(encrypted->at(0)), uint8_t(2));
        const std::optional<BwBytes> decryptedBytes = BwCrypto::decryptBuffer(*encrypted, *sendKey);
        QVERIFY(decryptedBytes);
        QCOMPARE(QByteArray(reinterpret_cast<const char *>(decryptedBytes->data()),
                            qsizetype(decryptedBytes->size())),
                 fileContent);

        QByteArray tampered = *encrypted;
        tampered[tampered.size() - 1] = char(tampered[tampered.size() - 1] ^ 0x01);
        QVERIFY(!BwCrypto::decryptBuffer(tampered, *sendKey));

        // Password hash & share URLs.
        const QString hash = BwCrypto::sendPasswordHash(Secret(QStringLiteral("segredo")), seed);
        QCOMPARE(QByteArray::fromBase64(hash.toLatin1()).size(), 32);

        const QString cloudUrl = BwCrypto::sendUrl(QString(), QStringLiteral("abc123"), seed);
        QVERIFY(cloudUrl.startsWith(QStringLiteral("https://vault.bitwarden.com/#/send/abc123/")));
        const QString vwUrl = BwCrypto::sendUrl(QStringLiteral("https://limeira.dev.internal"),
                                                QStringLiteral("xyz789"), seed);
        QVERIFY(vwUrl.startsWith(QStringLiteral("https://limeira.dev.internal/#/send/xyz789/")));
    }

    void bitwardenNotificationsUrlAndSignalRDecoder() {
        QCOMPARE(BwApi::notificationsUrl(QString()),
                 QStringLiteral("wss://notifications.bitwarden.com/hub"));
        QCOMPARE(BwApi::notificationsUrl(QStringLiteral("https://vault.bitwarden.eu")),
                 QStringLiteral("wss://notifications.bitwarden.eu/hub"));
        QCOMPARE(BwApi::notificationsUrl(QStringLiteral("https://limeira.dev.internal")),
                 QStringLiteral("wss://limeira.dev.internal/notifications/hub"));

        // Build a SignalR MessagePack Invocation frame:
        // [1, {}, null, "ReceiveMessage", [{"Type": 0, "Payload": {"Id": "cid-42"}}]]
        QByteArray msg;
        msg.append(char(0x95));  // fixarray(5)
        msg.append(char(0x01));  // 1 (Invocation)
        msg.append(char(0x80));  // fixmap(0) headers
        msg.append(char(0xc0));  // nil invocationId
        const QByteArray target("ReceiveMessage");
        msg.append(char(0xa0 | target.size()));
        msg.append(target);
        msg.append(char(0x91));  // fixarray(1) arguments
        msg.append(char(0x82));  // fixmap(2) envelope
        msg.append(char(0xa4));
        msg.append("Type");
        msg.append(char(0x00));  // 0 = SyncCipherUpdate
        msg.append(char(0xa7));
        msg.append("Payload");
        msg.append(char(0x81));  // fixmap(1) payload
        msg.append(char(0xa2));
        msg.append("Id");
        const QByteArray cid("cid-42");
        msg.append(char(0xa0 | cid.size()));
        msg.append(cid);

        // Prepend varint length + a SignalR Ping frame (\x02\x91\x06).
        QByteArray framed;
        framed.append(char(msg.size()));
        framed.append(msg);
        framed.append(QByteArray("\x02\x91\x06", 3));

        const QVector<QVariant> decoded = BwSync::decodeSignalRFrames(framed);
        QCOMPARE(decoded.size(), 2);

        const std::optional<BwSyncEvent> ev = BwSync::parseNotification(decoded.at(0));
        QVERIFY(ev);
        QCOMPARE(ev->kind, BwSyncEvent::Kind::CipherChanged);
        QCOMPARE(ev->cipherId, QStringLiteral("cid-42"));

        // Ping is not a sync event.
        QVERIFY(!BwSync::parseNotification(decoded.at(1)));
    }

    void bitwardenEditRequestStripsResponseOnlyAndLegacyDataFields() {
        const auto key = BwCrypto::keyFromBytes(BwCrypto::randomBytes(64));
        QVERIFY(key);

        QJsonObject existing{
            {"id", "c-1"},
            {"object", "cipherDetails"},
            {"type", 1},
            {"revisionDate", "2026-11-25T10:00:00Z"},
            {"creationDate", "2026-01-01T00:00:00Z"},
            {"edit", true},
            {"viewPassword", true},
            {"data", QJsonObject{{"username", "2.stale|data|mac"}}},
            {"login", QJsonObject{{"uri", "2.stale|uri|mac"}, {"uris", QJsonArray()}}},
        };
        EntryData edited;
        edited.username = QStringLiteral("novo@exemplo.com");
        edited.password = Secret(QStringLiteral("nova-senha"));
        edited.url = QStringLiteral("https://exemplo.com");

        const QJsonObject req = BwAccount::cipherRequest(existing, QStringLiteral("velha"),
                                                         QStringLiteral("Site"), QString(),
                                                         edited, *key, QStringLiteral("user-1"));
        QVERIFY(!req.contains("data"));
        QVERIFY(!req.contains("object"));
        QVERIFY(!req.contains("id"));
        QVERIFY(!req.contains("revisionDate"));
        QCOMPARE(req.value("lastKnownRevisionDate").toString(), QStringLiteral("2026-11-25T10:00:00Z"));
        const QJsonObject login = req.value("login").toObject();
        QVERIFY(!login.contains("uri"));
        QCOMPARE(decrypted(login.value("username"), *key), QStringLiteral("novo@exemplo.com"));
        QCOMPARE(decrypted(login.value("password"), *key), QStringLiteral("nova-senha"));
    }

    void bitwardenCardAndIdentityDecryptIndexAndRequest() {
        const auto key = BwCrypto::keyFromBytes(BwCrypto::randomBytes(64));
        QVERIFY(key);
        BwKeys keys;
        keys.user = *key;

        // Card (type 3)
        EntryData cardData;
        cardData.isCard = true;
        cardData.card.cardholderName = QStringLiteral("Higor");
        cardData.card.brand = QStringLiteral("Visa");
        cardData.card.number = Secret(QStringLiteral("4111111111111234"));
        cardData.card.expMonth = QStringLiteral("12");
        cardData.card.expYear = QStringLiteral("2029");
        cardData.card.code = Secret(QStringLiteral("987"));
        cardData.notes = QStringLiteral("Cartao principal");

        QJsonObject cardReq = BwAccount::cipherRequest({}, {}, QStringLiteral("Nubank"), QString(),
                                                       cardData, *key, QStringLiteral("u1"));
        QCOMPARE(cardReq.value("type").toInt(), 3);
        QVERIFY(!cardReq.contains("login"));
        cardReq.insert(QStringLiteral("id"), QStringLiteral("card-1"));
        const std::optional<QJsonObject> decCard = BwAccount::decryptCipher(cardReq, keys);
        QVERIFY(decCard);
        const EntryData parsedCard = bwEntryData(*decCard);
        QVERIFY(parsedCard.isCard);
        QCOMPARE(parsedCard.card.cardholderName, QStringLiteral("Higor"));
        QCOMPARE(parsedCard.card.brand, QStringLiteral("Visa"));
        QCOMPARE(parsedCard.card.number.toString(), QStringLiteral("4111111111111234"));
        QCOMPARE(parsedCard.card.expMonth, QStringLiteral("12"));
        QCOMPARE(parsedCard.card.expYear, QStringLiteral("2029"));
        QCOMPARE(parsedCard.card.code.toString(), QStringLiteral("987"));
        QCOMPARE(parsedCard.notes, QStringLiteral("Cartao principal"));

        // Identity (type 4)
        EntryData idData;
        idData.isIdentity = true;
        idData.identity.firstName = QStringLiteral("Higor");
        idData.identity.lastName = QStringLiteral("Goncalves");
        idData.identity.email = QStringLiteral("higor@exemplo.com");
        idData.identity.phone = QStringLiteral("+55 11 99999-0000");
        idData.identity.city = QStringLiteral("Limeira");
        idData.identity.postalCode = QStringLiteral("13480-000");
        idData.identity.ssn = Secret(QStringLiteral("123.456.789-00"));

        QJsonObject idReq = BwAccount::cipherRequest({}, {}, QStringLiteral("Dados Pessoais"), QString(),
                                                     idData, *key, QStringLiteral("u1"));
        QCOMPARE(idReq.value("type").toInt(), 4);
        QVERIFY(!idReq.contains("login"));
        idReq.insert(QStringLiteral("id"), QStringLiteral("id-1"));
        const std::optional<QJsonObject> decId = BwAccount::decryptCipher(idReq, keys);
        QVERIFY(decId);
        const EntryData parsedId = bwEntryData(*decId);
        QVERIFY(parsedId.isIdentity);
        QCOMPARE(parsedId.identity.firstName, QStringLiteral("Higor"));
        QCOMPARE(parsedId.identity.lastName, QStringLiteral("Goncalves"));
        QCOMPARE(parsedId.identity.email, QStringLiteral("higor@exemplo.com"));
        QCOMPARE(parsedId.identity.city, QStringLiteral("Limeira"));
        QCOMPARE(parsedId.identity.ssn.toString(), QStringLiteral("123.456.789-00"));

        const BwIndex index = buildBwIndex({{QStringLiteral("card-1"), *decCard},
                                            {QStringLiteral("id-1"), *decId}}, {});
        QCOMPARE(index.entries, QStringList({QStringLiteral("Dados Pessoais"), QStringLiteral("Nubank")}));
    }

    void bitwardenCustomFieldsCollectionsTrashAndSends() {
        const auto userKey = BwCrypto::keyFromBytes(BwCrypto::randomBytes(64));
        const auto orgKey = BwCrypto::keyFromBytes(BwCrypto::randomBytes(64));
        QVERIFY(userKey && orgKey);
        BwKeys keys;
        keys.user = *userKey;
        keys.organizations.insert(QStringLiteral("org-1"), *orgKey);

        // Custom fields + viewPassword + Trash (includeDeleted)
        EntryData data;
        data.username = QStringLiteral("user");
        data.password = Secret(QStringLiteral("pass"));
        data.customFieldsLoaded = true;
        data.customFields.append({QStringLiteral("PIN"), Secret(QStringLiteral("4321")), 1});
        data.customFields.append({QStringLiteral("Ambiente"), Secret(QStringLiteral("prod")), 0});

        QJsonObject cipher = BwAccount::cipherRequest({}, {}, QStringLiteral("Srv"), QString(),
                                                      data, *userKey, QStringLiteral("u1"));
        cipher.insert(QStringLiteral("id"), QStringLiteral("c-cf"));
        cipher.insert(QStringLiteral("viewPassword"), false);
        cipher.insert(QStringLiteral("deletedDate"), QStringLiteral("2026-11-26T10:00:00Z"));

        // Excluded from normal decrypt, included when includeDeleted == true.
        QVERIFY(!BwAccount::decryptCipher(cipher, keys, false));
        const std::optional<QJsonObject> trashed = BwAccount::decryptCipher(cipher, keys, true);
        QVERIFY(trashed);
        const EntryData parsed = bwEntryData(*trashed);
        QCOMPARE(parsed.viewPassword, false);
        QCOMPARE(parsed.customFields.size(), 2);
        QCOMPARE(parsed.customFields.at(0).name, QStringLiteral("PIN"));
        QCOMPARE(parsed.customFields.at(0).value.toString(), QStringLiteral("4321"));
        QCOMPARE(parsed.customFields.at(0).type, 1);

        // Collection decryption
        const QJsonObject col{
            {QStringLiteral("id"), QStringLiteral("col-1")},
            {QStringLiteral("organizationId"), QStringLiteral("org-1")},
            {QStringLiteral("name"), *BwCrypto::encrypt(QByteArray("Infraestrutura"), *orgKey)}
        };
        QCOMPARE(BwAccount::decryptCollection(col, keys), QStringLiteral("Infraestrutura"));

        // Send decryption
        const BwBytes seed = BwCrypto::randomBytes(16);
        const auto sendKey = BwCrypto::deriveSendKey(seed);
        QVERIFY(sendKey);
        const QByteArray seedBytes(reinterpret_cast<const char *>(seed.data()), qsizetype(seed.size()));
        const QJsonObject send{
            {QStringLiteral("id"), QStringLiteral("s-1")},
            {QStringLiteral("accessId"), QStringLiteral("acc123")},
            {QStringLiteral("type"), 0},
            {QStringLiteral("key"), *BwCrypto::encrypt(seedBytes, *userKey)},
            {QStringLiteral("name"), *BwCrypto::encrypt(QByteArray("Senha temporaria"), *sendKey)},
            {QStringLiteral("accessCount"), 1},
            {QStringLiteral("maxAccessCount"), 5},
            {QStringLiteral("deletionDate"), QStringLiteral("2026-12-01T00:00:00Z")}
        };
        const std::optional<QJsonObject> decSend =
            BwAccount::decryptSend(send, *userKey, QStringLiteral("https://limeira.dev.internal"));
        QVERIFY(decSend);
        QCOMPARE(decSend->value("name").toString(), QStringLiteral("Senha temporaria"));
        QVERIFY(decSend->value("url").toString().startsWith(QStringLiteral("https://limeira.dev.internal/#/send/acc123/")));
    }
};

OMAPASS_TEST(TestBitwarden)
#include "tst_bitwarden.moc"
