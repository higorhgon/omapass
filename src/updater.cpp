#include "updater.h"

#include "i18n.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QProcess>
#include <QRegularExpression>
#include <QStandardPaths>

#include <botan/sodium.h>

namespace {

const auto latestReleaseEndpoint = QStringLiteral("https://api.github.com/repos/higorhgon/omapass/releases/latest");
const auto defaultReleasesPage = QStringLiteral("https://github.com/higorhgon/omapass/releases/latest");

// Public half of the Ed25519 key that signs SHA256SUMS in the release
// workflow (secret OMAPASS_UPDATE_SIGNING_KEY). The checksums come from the
// same release as the package, so only this signature ties them to us.
const auto releasePublicKeyHex = QByteArrayLiteral("0dcb718251b4eafa9bf820c86cf0c5565df27b3f6fd8f178aa140f7fa603d056");
const auto checksumsName = QStringLiteral("SHA256SUMS");
const auto signatureName = QStringLiteral("SHA256SUMS.sig");

QString stripVersionPrefix(QString version) {
    version = version.trimmed();
    if (version.startsWith(QLatin1Char('v')) || version.startsWith(QLatin1Char('V')))
        version.remove(0, 1);
    return version;
}

QList<int> versionParts(const QString &raw) {
    const QString cleaned = stripVersionPrefix(raw);
    const QString mainPart = cleaned.section(QLatin1Char('-'), 0, 0);
    QList<int> parts;
    for (const QString &token : mainPart.split(QLatin1Char('.'), Qt::SkipEmptyParts)) {
        bool ok = false;
        const int number = token.toInt(&ok);
        if (!ok)
            break;
        parts.append(number);
    }
    return parts;
}

bool assetMatchesPlatform(const QString &name, Updater::Platform platform) {
    const QString lower = name.toLower();
    switch (platform) {
    case Updater::Platform::AppImage:
        return lower.endsWith(QLatin1String(".appimage"));
    case Updater::Platform::Windows:
        return lower.endsWith(QLatin1String("-setup.exe"));
    case Updater::Platform::MacOS:
        return lower.endsWith(QLatin1String(".dmg"));
    case Updater::Platform::Unsupported:
        return false;
    }
    return false;
}

QNetworkRequest makeRequest(const QUrl &url, bool jsonApi) {
    QNetworkRequest req(url);
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                     QNetworkRequest::NoLessSafeRedirectPolicy);
    req.setHeader(QNetworkRequest::UserAgentHeader,
                  QStringLiteral("omapass/") + QCoreApplication::applicationVersion());
    if (jsonApi)
        req.setRawHeader("Accept", "application/vnd.github+json");
    return req;
}

QString sha256OfFile(const QString &path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return {};
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!hash.addData(&file))
        return {};
    return QString::fromLatin1(hash.result().toHex()).toLower();
}

}

Updater::Updater(QObject *parent) : QObject(parent) {}

Updater::Platform Updater::currentPlatform() {
#if defined(Q_OS_WIN)
    return Platform::Windows;
#elif defined(Q_OS_MACOS)
    return Platform::MacOS;
#elif defined(Q_OS_LINUX)
    const QString appImage = qEnvironmentVariable("APPIMAGE").trimmed();
    if (!appImage.isEmpty() && QFileInfo::exists(appImage))
        return Platform::AppImage;
    return Platform::Unsupported;
#else
    return Platform::Unsupported;
#endif
}

bool Updater::supported() {
    return currentPlatform() != Platform::Unsupported;
}

QString Updater::currentVersion() const {
    return QCoreApplication::applicationVersion();
}

int Updater::compareVersions(const QString &a, const QString &b) {
    const QList<int> left = versionParts(a);
    const QList<int> right = versionParts(b);
    const int count = qMax(left.size(), right.size());
    for (int i = 0; i < count; ++i) {
        const int lv = i < left.size() ? left.at(i) : 0;
        const int rv = i < right.size() ? right.at(i) : 0;
        if (lv != rv)
            return lv < rv ? -1 : 1;
    }
    return 0;
}

bool Updater::parseLatestRelease(const QByteArray &json, Platform platform,
                                 ReleaseInfo *info, QString *error) {
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(json, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        if (error)
            *error = I18n::t(QStringLiteral("update.invalid_response"));
        return false;
    }

    const QJsonObject obj = doc.object();
    const QString tag = stripVersionPrefix(obj.value(QStringLiteral("tag_name")).toString());
    if (tag.isEmpty()) {
        if (error)
            *error = I18n::t(QStringLiteral("update.invalid_response"));
        return false;
    }

    ReleaseInfo parsed;
    parsed.version = tag;
    parsed.htmlUrl = QUrl(obj.value(QStringLiteral("html_url")).toString());
    if (!parsed.htmlUrl.isValid())
        parsed.htmlUrl = QUrl(defaultReleasesPage);

    ReleaseAsset fallbackExe;
    const QJsonArray assets = obj.value(QStringLiteral("assets")).toArray();
    for (const QJsonValue &entry : assets) {
        const QJsonObject asset = entry.toObject();
        const QString name = asset.value(QStringLiteral("name")).toString();
        const QUrl downloadUrl(asset.value(QStringLiteral("browser_download_url")).toString());
        if (name.isEmpty() || !downloadUrl.isValid())
            continue;

        if (name == checksumsName) {
            parsed.checksumsAsset = {name, downloadUrl};
            continue;
        }
        if (name == signatureName) {
            parsed.signatureAsset = {name, downloadUrl};
            continue;
        }
        if (assetMatchesPlatform(name, platform) && !parsed.packageAsset.url.isValid()) {
            parsed.packageAsset = {name, downloadUrl};
        } else if (platform == Platform::Windows && name.toLower().endsWith(QLatin1String(".exe"))
                   && !fallbackExe.url.isValid()) {
            fallbackExe = {name, downloadUrl};
        }
    }

    if (!parsed.packageAsset.url.isValid() && fallbackExe.url.isValid())
        parsed.packageAsset = fallbackExe;

    *info = parsed;
    return true;
}

QString Updater::parseSha256ForFile(const QByteArray &sumsData, const QString &fileName) {
    const QString text = QString::fromUtf8(sumsData);
    const QString target = QFileInfo(fileName).fileName();
    static const QRegularExpression re(QStringLiteral("^([0-9a-fA-F]{64})\\s+\\*?(.+)$"));
    for (const QString &line : text.split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
        const QRegularExpressionMatch match = re.match(line.trimmed());
        if (!match.hasMatch())
            continue;
        const QString candidate = QFileInfo(match.captured(2).trimmed()).fileName();
        if (candidate == target)
            return match.captured(1).toLower();
    }
    return {};
}

bool Updater::verifyChecksumsSignature(const QByteArray &sumsData, const QByteArray &signature,
                                       const QByteArray &publicKey) {
    const QByteArray key = publicKey.isEmpty() ? QByteArray::fromHex(releasePublicKeyHex) : publicKey;
    if (key.size() != int(Botan::Sodium::crypto_sign_ed25519_PUBLICKEYBYTES)
        || signature.size() != int(Botan::Sodium::crypto_sign_ed25519_BYTES) || sumsData.isEmpty())
        return false;
    return Botan::Sodium::crypto_sign_ed25519_verify_detached(
               reinterpret_cast<const uint8_t *>(signature.constData()),
               reinterpret_cast<const uint8_t *>(sumsData.constData()), size_t(sumsData.size()),
               reinterpret_cast<const uint8_t *>(key.constData()))
           == 0;
}

bool Updater::replaceAppImage(const QString &targetPath, const QString &newFilePath, QString *error) {
    const QFileDevice::Permissions execPerms =
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner
        | QFileDevice::ReadGroup | QFileDevice::ExeGroup
        | QFileDevice::ReadOther | QFileDevice::ExeOther;
    if (!QFile::setPermissions(newFilePath, execPerms)) {
        if (error)
            *error = I18n::t(QStringLiteral("update.install_failed"));
        return false;
    }

    const QString backupPath = targetPath + QStringLiteral(".old");
    if (QFile::exists(backupPath))
        QFile::remove(backupPath);

    if (QFile::exists(targetPath) && !QFile::rename(targetPath, backupPath)) {
        if (error)
            *error = I18n::t(QStringLiteral("update.not_writable"));
        return false;
    }

    if (!QFile::rename(newFilePath, targetPath)) {
        // Restore the previous binary if swapping the new one in failed.
        if (QFile::exists(backupPath))
            QFile::rename(backupPath, targetPath);
        if (error)
            *error = I18n::t(QStringLiteral("update.install_failed"));
        return false;
    }

    QFile::remove(backupPath);
    return true;
}

void Updater::setStatus(const QString &text, bool isError) {
    m_statusText = text;
    m_statusIsError = isError;
    emit stateChanged();
}

void Updater::checkForUpdates(bool manual) {
    if (!supported() || m_checking || m_downloading)
        return;

    m_checking = true;
    if (manual)
        setStatus(I18n::t(QStringLiteral("update.checking")), false);
    else
        emit stateChanged();

    QNetworkReply *reply = m_network.get(makeRequest(QUrl(latestReleaseEndpoint), true));
    m_activeReply = reply;
    connect(reply, &QNetworkReply::finished, this, [this, reply, manual]() {
        m_checking = false;
        const QNetworkReply::NetworkError netErr = reply->error();
        const QString errStr = reply->errorString();
        const QByteArray payload = reply->readAll();
        reply->deleteLater();

        if (netErr != QNetworkReply::NoError) {
            if (manual)
                setStatus(I18n::t(QStringLiteral("update.check_failed"), QStringLiteral("err"), errStr), true);
            else
                emit stateChanged();
            return;
        }

        ReleaseInfo info;
        QString parseErr;
        if (!parseLatestRelease(payload, currentPlatform(), &info, &parseErr)) {
            if (manual)
                setStatus(parseErr, true);
            else
                emit stateChanged();
            return;
        }

        m_latestVersion = info.version;
        m_releaseUrl = info.htmlUrl;
        m_packageAsset = info.packageAsset;
        m_checksumsAsset = info.checksumsAsset;
        m_signatureAsset = info.signatureAsset;
        m_updateAvailable = compareVersions(info.version, currentVersion()) > 0
                            && m_packageAsset.url.isValid();

        if (m_updateAvailable) {
            setStatus(I18n::t(QStringLiteral("update.available"),
                              QStringLiteral("version"), m_latestVersion), false);
        } else if (manual) {
            setStatus(I18n::t(QStringLiteral("update.up_to_date")), false);
        } else {
            emit stateChanged();
        }
    });
}

void Updater::installUpdate() {
    if (!supported() || !m_updateAvailable || m_downloading || !m_packageAsset.url.isValid())
        return;

    m_downloading = true;
    m_progress = 0;
    emit progressChanged();
    setStatus(I18n::t(QStringLiteral("update.downloading"), QStringLiteral("percent"), QStringLiteral("0")),
              false);

    // Without signed checksums there is nothing to trust the package by, so
    // the update stops instead of installing it unverified.
    if (!m_checksumsAsset.url.isValid() || !m_signatureAsset.url.isValid()) {
        failInstall(I18n::t(QStringLiteral("update.unsigned")));
        return;
    }

    QNetworkReply *reply = m_network.get(makeRequest(m_checksumsAsset.url, false));
    m_activeReply = reply;
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const QNetworkReply::NetworkError netErr = reply->error();
        const QString errStr = reply->errorString();
        const QByteArray data = reply->readAll();
        reply->deleteLater();
        if (netErr != QNetworkReply::NoError) {
            failInstall(I18n::t(QStringLiteral("update.download_failed"), QStringLiteral("err"), errStr));
            return;
        }
        fetchSignature(data);
    });
}

void Updater::fetchSignature(const QByteArray &sumsData) {
    QNetworkReply *reply = m_network.get(makeRequest(m_signatureAsset.url, false));
    m_activeReply = reply;
    connect(reply, &QNetworkReply::finished, this, [this, reply, sumsData]() {
        const QNetworkReply::NetworkError netErr = reply->error();
        const QString errStr = reply->errorString();
        const QByteArray signature = reply->readAll();
        reply->deleteLater();
        if (netErr != QNetworkReply::NoError) {
            failInstall(I18n::t(QStringLiteral("update.download_failed"), QStringLiteral("err"), errStr));
            return;
        }
        if (!verifyChecksumsSignature(sumsData, signature)) {
            failInstall(I18n::t(QStringLiteral("update.signature_failed")));
            return;
        }
        const QString expected = parseSha256ForFile(sumsData, m_packageAsset.name);
        if (expected.isEmpty()) {
            failInstall(I18n::t(QStringLiteral("update.checksum_failed")));
            return;
        }
        startPackageDownload(expected);
    });
}

void Updater::failInstall(const QString &message) {
    m_downloading = false;
    setStatus(message, true);
}

void Updater::startPackageDownload(const QString &expectedSha256) {
    QString destPath;
    if (currentPlatform() == Platform::AppImage) {
        const QString currentAppImage = qEnvironmentVariable("APPIMAGE").trimmed();
        destPath = currentAppImage + QStringLiteral(".new");
    } else if (currentPlatform() == Platform::MacOS) {
        const QString downloads = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
        const QString dir = downloads.isEmpty()
            ? QStandardPaths::writableLocation(QStandardPaths::TempLocation) : downloads;
        QDir().mkpath(dir);
        destPath = QDir(dir).filePath(QFileInfo(m_packageAsset.name).fileName());
    } else {
        const QString temp = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
        QDir().mkpath(temp);
        destPath = QDir(temp).filePath(QFileInfo(m_packageAsset.name).fileName());
    }

    auto *outFile = new QFile(destPath, this);
    if (!outFile->open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        outFile->deleteLater();
        m_downloading = false;
        setStatus(I18n::t(QStringLiteral("update.not_writable")), true);
        return;
    }

    QNetworkReply *reply = m_network.get(makeRequest(m_packageAsset.url, false));
    m_activeReply = reply;

    connect(reply, &QNetworkReply::readyRead, this, [reply, outFile]() {
        outFile->write(reply->readAll());
    });
    connect(reply, &QNetworkReply::downloadProgress, this, [this](qint64 received, qint64 total) {
        if (total <= 0)
            return;
        const int pct = qBound(0, static_cast<int>((received * 100) / total), 100);
        if (pct != m_progress) {
            m_progress = pct;
            emit progressChanged();
            setStatus(I18n::t(QStringLiteral("update.downloading"),
                              QStringLiteral("percent"), QString::number(pct)), false);
        }
    });
    connect(reply, &QNetworkReply::finished, this, [this, reply, outFile, destPath, expectedSha256]() {
        outFile->write(reply->readAll());
        outFile->flush();
        outFile->close();
        outFile->deleteLater();

        const QNetworkReply::NetworkError netErr = reply->error();
        const QString errStr = reply->errorString();
        reply->deleteLater();

        if (netErr != QNetworkReply::NoError) {
            QFile::remove(destPath);
            m_downloading = false;
            setStatus(I18n::t(QStringLiteral("update.download_failed"), QStringLiteral("err"), errStr), true);
            return;
        }

        finishInstall(destPath, expectedSha256);
    });
}

void Updater::finishInstall(const QString &downloadedPath, const QString &expectedSha256) {
    if (expectedSha256.isEmpty() || sha256OfFile(downloadedPath) != expectedSha256) {
        QFile::remove(downloadedPath);
        failInstall(I18n::t(QStringLiteral("update.checksum_failed")));
        return;
    }

    const Platform platform = currentPlatform();
    if (platform == Platform::AppImage) {
        const QString target = qEnvironmentVariable("APPIMAGE").trimmed();
        QString error;
        if (!replaceAppImage(target, downloadedPath, &error)) {
            QFile::remove(downloadedPath);
            m_downloading = false;
            setStatus(error, true);
            return;
        }
        m_downloading = false;
        QProcess::startDetached(target, {});
        QCoreApplication::quit();
        return;
    }

    if (platform == Platform::Windows) {
        m_downloading = false;
        if (!QProcess::startDetached(downloadedPath, {})) {
            setStatus(I18n::t(QStringLiteral("update.install_failed")), true);
            return;
        }
        QCoreApplication::quit();
        return;
    }

    if (platform == Platform::MacOS) {
        m_downloading = false;
        m_updateAvailable = false;
        QDesktopServices::openUrl(QUrl::fromLocalFile(downloadedPath));
        setStatus(I18n::t(QStringLiteral("update.dmg_opened")), false);
        return;
    }

    m_downloading = false;
    emit stateChanged();
}

void Updater::openReleasePage() const {
    const QUrl target = m_releaseUrl.isValid() ? m_releaseUrl : QUrl(defaultReleasesPage);
    QDesktopServices::openUrl(target);
}
