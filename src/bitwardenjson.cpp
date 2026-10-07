#include "bitwardenjson.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUrl>

#include <algorithm>

namespace {

const QString euServer = QStringLiteral("https://vault.bitwarden.eu");

}

std::optional<QString> normalizeBwServer(const QString &input) {
    QString text = input.trimmed();
    if (text.isEmpty())
        return QString();
    if (!text.contains(QLatin1String("://")))
        text.prepend(QLatin1String("https://"));

    const QUrl url(text, QUrl::StrictMode);
    if (!url.isValid() || url.scheme().compare(QLatin1String("https"), Qt::CaseInsensitive) != 0
        || url.host().isEmpty() || !url.userInfo().isEmpty() || url.hasQuery() || url.hasFragment())
        return std::nullopt;

    const QString host = url.host().toLower();
    QString path = url.path();
    while (path.endsWith(QLatin1Char('/')))
        path.chop(1);
    if (url.port() == -1 && path.isEmpty()) {
        if (host == QLatin1String("bitwarden.com") || host == QLatin1String("vault.bitwarden.com"))
            return QString();
        if (host == QLatin1String("bitwarden.eu") || host == QLatin1String("vault.bitwarden.eu"))
            return euServer;
    }

    QUrl clean;
    clean.setScheme(QStringLiteral("https"));
    clean.setHost(host);
    clean.setPort(url.port());
    clean.setPath(path);
    return clean.toString();
}

QString bwServerLabel(const QString &serverUrl) {
    return serverUrl.isEmpty() ? QStringLiteral("bitwarden.com") : serverUrl;
}

QString bwDisplayName(const QString &name) {
    QString display = name;
    display.replace(QLatin1Char('/'), QChar(0x2215));
    return display.trimmed().isEmpty() ? QStringLiteral("(untitled)") : display;
}

BwIndex buildBwIndex(const QHash<QString, QJsonObject> &items, const QHash<QString, QString> &folders) {
    BwIndex index;

    QStringList groups;
    for (auto it = folders.cbegin(); it != folders.cend(); ++it) {
        index.folders.insert(it.value(), it.key());
        const QStringList parts = it.value().split(QLatin1Char('/'));
        for (int i = 1; i <= parts.size(); ++i) {
            const QString group = parts.mid(0, i).join(QLatin1Char('/'));
            if (!groups.contains(group))
                groups.append(group);
        }
    }
    groups.sort();
    index.groups = groups;

    struct Candidate {
        QString path;
        BwItemRef ref;
    };
    QVector<Candidate> candidates;
    QHash<QString, int> pathCount;

    for (const QJsonObject &item : items) {
        if (item.value(QStringLiteral("type")).toInt() != 1)
            continue;
        const QJsonValue deleted = item.value(QStringLiteral("deletedDate"));
        if (!deleted.isNull() && !deleted.isUndefined())
            continue;

        BwItemRef ref;
        ref.id = item.value(QStringLiteral("id")).toString();
        ref.name = item.value(QStringLiteral("name")).toString();
        ref.folderId = item.value(QStringLiteral("folderId")).toString();
        if (ref.id.isEmpty())
            continue;

        // An item pointing at a folder we did not get back sits at the root.
        const QString group = folders.value(ref.folderId);
        const QString display = bwDisplayName(ref.name);
        const QString path = group.isEmpty() ? display : group + QLatin1Char('/') + display;

        candidates.append({path, ref});
        pathCount[path] += 1;
    }

    for (const Candidate &candidate : std::as_const(candidates)) {
        QString path = candidate.path;
        if (pathCount.value(path) > 1)
            path += QStringLiteral(" [") + candidate.ref.id.left(8) + QLatin1Char(']');
        index.entries.append(path);
        index.items.insert(path, candidate.ref);
    }
    index.entries.sort();

    return index;
}

EntryData bwEntryData(const QJsonObject &item) {
    const QJsonObject login = item.value(QStringLiteral("login")).toObject();
    const QJsonArray uris = login.value(QStringLiteral("uris")).toArray();

    EntryData data;
    data.username = login.value(QStringLiteral("username")).toString();
    data.password = Secret(login.value(QStringLiteral("password")).toString());
    data.url = uris.isEmpty() ? QString()
                              : uris.first().toObject().value(QStringLiteral("uri")).toString();
    data.notes = item.value(QStringLiteral("notes")).toString();
    return data;
}

BwLoginError classifyBwLoginMessage(const QString &message, bool sentCode) {
    const auto has = [&message](const char *text) {
        return message.contains(QLatin1String(text), Qt::CaseInsensitive);
    };

    if (message.trimmed().isEmpty())
        return BwLoginError::Other;
    // With the password already accepted, a refused code is all it can be.
    if (sentCode)
        return BwLoginError::InvalidCode;
    if (has("Username or password is incorrect") || has("invalid_username_or_password")
        || has("Invalid master password"))
        return BwLoginError::WrongPassword;
    if (has("email") && (has("invalid") || has("not valid")))
        return BwLoginError::InvalidEmail;
    return BwLoginError::Other;
}

QList<int> bwSupportedTwoFactor(const QList<int> &providers) {
    QList<int> supported;
    for (int method : {0, 1, 3}) {
        if (providers.contains(method))
            supported.append(method);
    }
    return supported;
}
