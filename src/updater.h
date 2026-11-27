#pragma once

#include <QNetworkAccessManager>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QUrl>

class QNetworkReply;

// Self-updater for standalone builds: Linux AppImage, Windows installer (.exe)
// and macOS disk image (.dmg). Disabled on distro packages (such as Arch Linux)
// where the system package manager owns updates.
class Updater : public QObject {
    Q_OBJECT

    Q_PROPERTY(bool supported READ supported CONSTANT)
    Q_PROPERTY(bool checking READ checking NOTIFY stateChanged)
    Q_PROPERTY(bool downloading READ downloading NOTIFY stateChanged)
    Q_PROPERTY(bool updateAvailable READ updateAvailable NOTIFY stateChanged)
    Q_PROPERTY(QString currentVersion READ currentVersion CONSTANT)
    Q_PROPERTY(QString latestVersion READ latestVersion NOTIFY stateChanged)
    Q_PROPERTY(QString releaseUrl READ releaseUrl NOTIFY stateChanged)
    Q_PROPERTY(int progress READ progress NOTIFY progressChanged)
    Q_PROPERTY(QString statusText READ statusText NOTIFY stateChanged)
    Q_PROPERTY(bool statusIsError READ statusIsError NOTIFY stateChanged)

public:
    enum class Platform {
        Unsupported,
        AppImage,
        Windows,
        MacOS,
    };

    struct ReleaseAsset {
        QString name;
        QUrl url;
    };

    struct ReleaseInfo {
        QString version;
        QUrl htmlUrl;
        ReleaseAsset packageAsset;
        ReleaseAsset checksumsAsset;
        ReleaseAsset signatureAsset;
    };

    explicit Updater(QObject *parent = nullptr);

    static Platform currentPlatform();
    static bool supported();
    static int compareVersions(const QString &a, const QString &b);
    static bool parseLatestRelease(const QByteArray &json, Platform platform,
                                   ReleaseInfo *info, QString *error);
    static QString parseSha256ForFile(const QByteArray &sumsData, const QString &fileName);
    // Ed25519 signature (64 raw bytes) of SHA256SUMS, checked against the
    // release public key compiled into the app unless another one is given.
    static bool verifyChecksumsSignature(const QByteArray &sumsData, const QByteArray &signature,
                                         const QByteArray &publicKey = {});
    static bool replaceAppImage(const QString &targetPath, const QString &newFilePath,
                                QString *error);

    bool checking() const { return m_checking; }
    bool downloading() const { return m_downloading; }
    bool updateAvailable() const { return m_updateAvailable; }
    QString currentVersion() const;
    QString latestVersion() const { return m_latestVersion; }
    QString releaseUrl() const { return m_releaseUrl.toString(); }
    int progress() const { return m_progress; }
    QString statusText() const { return m_statusText; }
    bool statusIsError() const { return m_statusIsError; }

    Q_INVOKABLE void checkForUpdates(bool manual = false);
    Q_INVOKABLE void installUpdate();
    Q_INVOKABLE void openReleasePage() const;

signals:
    void stateChanged();
    void progressChanged();

private:
    void setStatus(const QString &text, bool isError);
    void fetchSignature(const QByteArray &sumsData);
    void failInstall(const QString &message);
    void startPackageDownload(const QString &expectedSha256);
    void finishInstall(const QString &downloadedPath, const QString &expectedSha256);

    QNetworkAccessManager m_network;
    QPointer<QNetworkReply> m_activeReply;

    bool m_checking = false;
    bool m_downloading = false;
    bool m_updateAvailable = false;
    int m_progress = 0;

    QString m_latestVersion;
    QUrl m_releaseUrl;
    ReleaseAsset m_packageAsset;
    ReleaseAsset m_checksumsAsset;
    ReleaseAsset m_signatureAsset;
    QString m_statusText;
    bool m_statusIsError = false;
};
