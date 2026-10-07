#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QList>
#include <QPair>
#include <QString>

#include "secret.h"

// The Bitwarden server API, spoken directly: the same requests the official
// clients make, to bitwarden.com, the EU cloud or a server of your own
// (Vaultwarden, self-hosted Bitwarden). It replaces the `bw` CLI, which
// started a Node program for every call and took seconds each time.
//
// Calls are synchronous and meant for a worker thread: each one runs its own
// network manager and event loop, so it can be made from any thread.
//
// Responses are returned with their keys in camelCase whatever the server
// used: Bitwarden answers the identity endpoints in PascalCase ("Key",
// "TwoFactorProviders2") and the rest in camelCase, and Vaultwarden has
// changed between the two over the years.

struct BwResponse {
    enum class Failure {
        None,
        Unreachable,   // no answer: DNS, refused, timeout…
        Certificate,   // TLS did not verify
        Http,          // the server answered with an error status
    };

    Failure failure = Failure::None;
    int status = 0;
    QJsonObject json;
    QString networkError;

    bool ok() const { return failure == Failure::None && status >= 200 && status < 300; }
    // The server's own explanation of an error, when it gave one.
    QString message() const;
};

namespace BwApi {

// Where a server's identity and API live. `server` is normalised (see
// normalizeBwServer): empty for bitwarden.com, which keeps them on hosts of
// their own, as does the EU cloud.
QString identityUrl(const QString &server);
QString apiUrl(const QString &server);

// The identifier this installation presents as its device: Bitwarden
// remembers known devices by it, so it is made once and kept.
QString deviceIdentifier();

using Form = QList<QPair<QString, QString>>;

// POST {identity}/connect/token with a form body. Its 400 answers carry the
// two-step and new-device challenges, so they are returned like any other.
BwResponse token(const QString &server, const Form &form);

// A call to {api}, authenticated when `accessToken` is given. `body`, when
// not null, is sent as JSON.
BwResponse call(const QString &server, const QByteArray &method, const QString &path,
                const Secret &accessToken, const QJsonObject &body = QJsonObject(),
                bool hasBody = false);

// Gives up on every request in flight and refuses new ones, for when the
// application quits: a sync waiting on a slow server would otherwise keep
// the process alive, window gone, until the server answered.
void abortAll();

// POST {identity}/accounts/prelogin: the account's KDF settings.
BwResponse prelogin(const QString &server, const QString &email);

// Keys turned to camelCase at every level ("TwoFactorProviders2" →
// "twoFactorProviders2"). Exposed for the tests.
QJsonObject camelized(const QJsonObject &object);

}
