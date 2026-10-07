#include "bwapi.h"

#include <QEventLoop>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSettings>
#include <QTimer>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QUrlQuery>
#include <QUuid>

#include <atomic>

namespace {

const auto deviceSetting = QStringLiteral("bitwarden/deviceIdentifier");

// What the official CLI presents itself as. Bitwarden only accepts a known
// client id, and the device type decides how the login shows up in the
// account's device list ("CLI").
const auto clientId = QStringLiteral("cli");
const auto deviceType = QStringLiteral("25");   // DeviceType.LinuxCLI
const auto clientVersion = QStringLiteral("2026.2.0");
const auto deviceName = QStringLiteral("omapass");

// Long enough for a slow link and Argon2-heavy servers, short enough that a
// server that never answers does not hold a background task for good.
constexpr int timeoutMs = 30000;

// Set when the application is on its way out (see BwApi::abortAll).
std::atomic<bool> abortRequested{false};

QJsonValue camelizedValue(const QJsonValue &value);

QJsonArray camelizedArray(const QJsonArray &array) {
    QJsonArray out;
    for (const QJsonValue &value : array)
        out.append(camelizedValue(value));
    return out;
}

QJsonValue camelizedValue(const QJsonValue &value) {
    if (value.isObject())
        return BwApi::camelized(value.toObject());
    if (value.isArray())
        return camelizedArray(value.toArray());
    return value;
}

// Certificates to trust besides the system's, for a server with one of its
// own (a self-signed one, or from an internal CA): a PEM file, possibly with
// several, named by OMAPASS_CA_CERTS. Read once.
const QList<QSslCertificate> &extraCaCertificates() {
    static const QList<QSslCertificate> certificates = []() {
        const QString path = qEnvironmentVariable("OMAPASS_CA_CERTS");
        return path.isEmpty() ? QList<QSslCertificate>()
                              : QSslCertificate::fromPath(path, QSsl::Pem);
    }();
    return certificates;
}

void addCommonHeaders(QNetworkRequest *request) {
    if (!extraCaCertificates().isEmpty()) {
        QSslConfiguration ssl = request->sslConfiguration();
        ssl.addCaCertificates(extraCaCertificates());
        request->setSslConfiguration(ssl);
    }
    request->setRawHeader("Accept", "application/json");
    request->setRawHeader("Device-Type", deviceType.toLatin1());
    request->setRawHeader("Bitwarden-Client-Name", clientId.toLatin1());
    request->setRawHeader("Bitwarden-Client-Version", clientVersion.toLatin1());
    request->setRawHeader("User-Agent", "omapass");
    request->setRawHeader("Cache-Control", "no-store");
    request->setTransferTimeout(timeoutMs);
}

BwResponse send(QNetworkRequest request, const QByteArray &method, QByteArray body) {
    BwResponse response;
    if (abortRequested) {
        response.failure = BwResponse::Failure::Unreachable;
        return response;
    }

    QNetworkAccessManager manager;
    QEventLoop loop;

    QNetworkReply *reply = body.isNull() ? manager.sendCustomRequest(request, method)
                                         : manager.sendCustomRequest(request, method, body);
    body.fill('\0');
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);

    // The loop runs on a worker thread nothing else can reach, so a request
    // to give up is polled for rather than delivered.
    QTimer abortPoll;
    abortPoll.setInterval(100);
    QObject::connect(&abortPoll, &QTimer::timeout, reply, [reply]() {
        if (abortRequested)
            reply->abort();
    });
    abortPoll.start();
    loop.exec();
    abortPoll.stop();

    response.status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    QByteArray content = reply->readAll();
    const QJsonDocument document = QJsonDocument::fromJson(content);
    content.fill('\0');
    if (document.isObject())
        response.json = BwApi::camelized(document.object());

    const QNetworkReply::NetworkError error = reply->error();
    if (response.status == 0) {
        response.failure = error == QNetworkReply::SslHandshakeFailedError
            ? BwResponse::Failure::Certificate
            : BwResponse::Failure::Unreachable;
        response.networkError = reply->errorString();
    } else if (response.status < 200 || response.status >= 300) {
        response.failure = BwResponse::Failure::Http;
        response.networkError = reply->errorString();
    }

    reply->deleteLater();
    return response;
}

}

QString BwResponse::message() const {
    // Identity answers {error, error_description, errorModel: {message}},
    // the API {message, validationErrors}; the most specific one wins.
    const QJsonObject model = json.value(QStringLiteral("errorModel")).toObject();
    const QString modelMessage = model.value(QStringLiteral("message")).toString();
    if (!modelMessage.isEmpty())
        return modelMessage;

    const QJsonObject validation = json.value(QStringLiteral("validationErrors")).toObject();
    for (auto it = validation.constBegin(); it != validation.constEnd(); ++it) {
        const QJsonArray messages = it.value().toArray();
        if (!messages.isEmpty() && !messages.first().toString().isEmpty())
            return messages.first().toString();
    }

    for (const char *key : {"message", "error_description", "error"}) {
        const QString text = json.value(QLatin1String(key)).toString();
        if (!text.isEmpty())
            return text;
    }
    return networkError;
}

QJsonObject BwApi::camelized(const QJsonObject &object) {
    QJsonObject out;
    for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
        QString key = it.key();
        if (!key.isEmpty() && key.at(0).isUpper())
            key[0] = key.at(0).toLower();
        out.insert(key, camelizedValue(it.value()));
    }
    return out;
}

void BwApi::abortAll() {
    abortRequested = true;
}

QString BwApi::identityUrl(const QString &server) {
    if (server.isEmpty())
        return QStringLiteral("https://identity.bitwarden.com");
    if (server == QLatin1String("https://vault.bitwarden.eu"))
        return QStringLiteral("https://identity.bitwarden.eu");
    return server + QStringLiteral("/identity");
}

QString BwApi::apiUrl(const QString &server) {
    if (server.isEmpty())
        return QStringLiteral("https://api.bitwarden.com");
    if (server == QLatin1String("https://vault.bitwarden.eu"))
        return QStringLiteral("https://api.bitwarden.eu");
    return server + QStringLiteral("/api");
}

QString BwApi::deviceIdentifier() {
    QSettings settings;
    QString id = settings.value(deviceSetting).toString();
    if (id.isEmpty()) {
        id = QUuid::createUuid().toString(QUuid::WithoutBraces);
        settings.setValue(deviceSetting, id);
    }
    return id;
}

BwResponse BwApi::token(const QString &server, const Form &form) {
    QNetworkRequest request(QUrl(identityUrl(server) + QStringLiteral("/connect/token")));
    addCommonHeaders(&request);
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QStringLiteral("application/x-www-form-urlencoded; charset=utf-8"));

    Form full = form;
    full << qMakePair(QStringLiteral("scope"), QStringLiteral("api offline_access"))
         << qMakePair(QStringLiteral("client_id"), clientId)
         << qMakePair(QStringLiteral("deviceType"), deviceType)
         << qMakePair(QStringLiteral("deviceIdentifier"), deviceIdentifier())
         << qMakePair(QStringLiteral("deviceName"), deviceName);

    QUrlQuery query;
    for (const auto &[key, value] : std::as_const(full))
        query.addQueryItem(QString::fromLatin1(QUrl::toPercentEncoding(key)),
                           QString::fromLatin1(QUrl::toPercentEncoding(value)));
    QString encoded = query.toString(QUrl::FullyEncoded);
    QByteArray body = encoded.toLatin1();
    encoded.fill(QChar(0));
    return send(request, "POST", body);
}

BwResponse BwApi::call(const QString &server, const QByteArray &method, const QString &path,
                       const Secret &accessToken, const QJsonObject &body, bool hasBody) {
    QNetworkRequest request(QUrl(apiUrl(server) + path));
    addCommonHeaders(&request);
    if (!accessToken.isEmpty()) {
        QByteArray header = "Bearer " + accessToken.toString().toLatin1();
        request.setRawHeader("Authorization", header);
        header.fill('\0');
    }

    QByteArray payload;
    if (hasBody || !body.isEmpty()) {
        request.setHeader(QNetworkRequest::ContentTypeHeader,
                          QStringLiteral("application/json; charset=utf-8"));
        payload = QJsonDocument(body).toJson(QJsonDocument::Compact);
    }
    return send(request, method, payload);
}

BwResponse BwApi::prelogin(const QString &server, const QString &email) {
    QNetworkRequest request(QUrl(identityUrl(server) + QStringLiteral("/accounts/prelogin")));
    addCommonHeaders(&request);
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QStringLiteral("application/json; charset=utf-8"));
    const QJsonObject body{{QStringLiteral("email"), email}};
    return send(request, "POST", QJsonDocument(body).toJson(QJsonDocument::Compact));
}
