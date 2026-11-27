#include "support.h"

#include "updater.h"

#include <botan/sodium.h>

class TestUpdater : public QObject {
    Q_OBJECT

private slots:
    void comparesSemanticVersions() {
        QCOMPARE(Updater::compareVersions(QStringLiteral("1.4.0"), QStringLiteral("1.4.0")), 0);
        QCOMPARE(Updater::compareVersions(QStringLiteral("v1.4.1"), QStringLiteral("1.4.0")), 1);
        QCOMPARE(Updater::compareVersions(QStringLiteral("1.10.0"), QStringLiteral("1.4.9")), 1);
        QCOMPARE(Updater::compareVersions(QStringLiteral("1.3.9"), QStringLiteral("1.4.0")), -1);
        QCOMPARE(Updater::compareVersions(QStringLiteral("2.0"), QStringLiteral("1.9.9")), 1);
    }

    void selectsRightAssetPerPlatform() {
        const QByteArray payload =
            "{"
            "\"tag_name\": \"v1.5.0\","
            "\"html_url\": \"https://github.com/higorhgon/omapass/releases/tag/v1.5.0\","
            "\"assets\": ["
            "{\"name\": \"omapass-1.5.0-x86_64.AppImage\", \"browser_download_url\": \"https://example.com/omapass.AppImage\"},"
            "{\"name\": \"omapass-1.5.0-windows-x64-setup.exe\", \"browser_download_url\": \"https://example.com/omapass-setup.exe\"},"
            "{\"name\": \"omapass-1.5.0-windows-x64.zip\", \"browser_download_url\": \"https://example.com/omapass.zip\"},"
            "{\"name\": \"omapass-1.5.0-macos-x64.dmg\", \"browser_download_url\": \"https://example.com/omapass.dmg\"},"
            "{\"name\": \"SHA256SUMS\", \"browser_download_url\": \"https://example.com/SHA256SUMS\"}"
            "]"
            "}";

        Updater::ReleaseInfo info;
        QString error;

        QVERIFY(Updater::parseLatestRelease(payload, Updater::Platform::AppImage, &info, &error));
        QCOMPARE(info.version, QStringLiteral("1.5.0"));
        QCOMPARE(info.packageAsset.name, QStringLiteral("omapass-1.5.0-x86_64.AppImage"));
        QCOMPARE(info.checksumsAsset.name, QStringLiteral("SHA256SUMS"));

        QVERIFY(Updater::parseLatestRelease(payload, Updater::Platform::Windows, &info, &error));
        QCOMPARE(info.packageAsset.name, QStringLiteral("omapass-1.5.0-windows-x64-setup.exe"));

        QVERIFY(Updater::parseLatestRelease(payload, Updater::Platform::MacOS, &info, &error));
        QCOMPARE(info.packageAsset.name, QStringLiteral("omapass-1.5.0-macos-x64.dmg"));
    }

    void parsesSha256SumsFile() {
        const QByteArray sums =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  omapass-1.5.0-x86_64.AppImage\n"
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 *omapass-1.5.0-macos-x64.dmg\n";
        QCOMPARE(Updater::parseSha256ForFile(sums, QStringLiteral("omapass-1.5.0-x86_64.AppImage")),
                 QStringLiteral("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
        QCOMPARE(Updater::parseSha256ForFile(sums, QStringLiteral("omapass-1.5.0-macos-x64.dmg")),
                 QStringLiteral("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"));
        QVERIFY(Updater::parseSha256ForFile(sums, QStringLiteral("missing.exe")).isEmpty());
    }

    void verifiesChecksumsSignature() {
        QByteArray pk(32, '\0');
        QByteArray sk(64, '\0');
        Botan::Sodium::crypto_sign_ed25519_keypair(reinterpret_cast<uint8_t *>(pk.data()),
                                                   reinterpret_cast<uint8_t *>(sk.data()));
        const QByteArray sums = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  omapass.AppImage\n";
        QByteArray sig(64, '\0');
        unsigned long long sigLen = 0;
        Botan::Sodium::crypto_sign_ed25519_detached(reinterpret_cast<uint8_t *>(sig.data()), &sigLen,
                                                    reinterpret_cast<const uint8_t *>(sums.constData()),
                                                    size_t(sums.size()),
                                                    reinterpret_cast<const uint8_t *>(sk.constData()));

        QVERIFY(Updater::verifyChecksumsSignature(sums, sig, pk));

        QByteArray tampered = sums;
        tampered[0] = 'f';
        QVERIFY(!Updater::verifyChecksumsSignature(tampered, sig, pk));
        QVERIFY(!Updater::verifyChecksumsSignature(sums, sig.left(63), pk));
        QVERIFY(!Updater::verifyChecksumsSignature(sums, {}, pk));
        // Signed by a key that is not the release one.
        QVERIFY(!Updater::verifyChecksumsSignature(sums, sig));
    }

    void picksSignatureAsset() {
        const QByteArray payload =
            "{\"tag_name\": \"v1.6.0\", \"assets\": ["
            "{\"name\": \"omapass-1.6.0-x86_64.AppImage\", \"browser_download_url\": \"https://example.com/a\"},"
            "{\"name\": \"SHA256SUMS\", \"browser_download_url\": \"https://example.com/s\"},"
            "{\"name\": \"SHA256SUMS.sig\", \"browser_download_url\": \"https://example.com/s.sig\"}"
            "]}";
        Updater::ReleaseInfo info;
        QString error;
        QVERIFY(Updater::parseLatestRelease(payload, Updater::Platform::AppImage, &info, &error));
        QCOMPARE(info.checksumsAsset.name, QStringLiteral("SHA256SUMS"));
        QCOMPARE(info.signatureAsset.name, QStringLiteral("SHA256SUMS.sig"));
    }

    void replacesAppImageAtomicallyAndSetsExecBit() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());

        const QString target = dir.filePath(QStringLiteral("omapass.AppImage"));
        const QString incoming = dir.filePath(QStringLiteral("omapass.AppImage.new"));

        {
            QFile f(target);
            QVERIFY(f.open(QIODevice::WriteOnly));
            f.write("old-version");
        }
        {
            QFile f(incoming);
            QVERIFY(f.open(QIODevice::WriteOnly));
            f.write("new-version");
        }

        QString error;
        QVERIFY(Updater::replaceAppImage(target, incoming, &error));
        QVERIFY(error.isEmpty());
        QVERIFY(!QFile::exists(incoming));
        QVERIFY(!QFile::exists(target + QStringLiteral(".old")));

        QFile result(target);
        QVERIFY(result.open(QIODevice::ReadOnly));
        QCOMPARE(result.readAll(), QByteArray("new-version"));
        QVERIFY(QFileInfo(target).isExecutable());
    }

    void disabledOnRegularLinuxBuild() {
#if defined(Q_OS_LINUX)
        const QByteArray prev = qgetenv("APPIMAGE");
        const auto restore = qScopeGuard([&]() {
            if (prev.isNull())
                qunsetenv("APPIMAGE");
            else
                qputenv("APPIMAGE", prev);
        });
        qunsetenv("APPIMAGE");
        QVERIFY(!Updater::supported());
        QCOMPARE(Updater::currentPlatform(), Updater::Platform::Unsupported);
#endif
    }
};

OMAPASS_TEST(TestUpdater)

#include "tst_updater.moc"
