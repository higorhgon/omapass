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

bool isBwAzureUploadUrl(const QString &url) {
    const QUrl parsed(url, QUrl::StrictMode);
    if (!parsed.isValid() || parsed.scheme() != QLatin1String("https") || !parsed.userInfo().isEmpty())
        return false;
    if (parsed.port() != -1 && parsed.port() != 443)
        return false;
    const QString host = parsed.host().toLower();
    static const QString suffix = QStringLiteral(".blob.core.windows.net");
    return host.size() > suffix.size() && host.endsWith(suffix);
}

QString bwServerLabel(const QString &serverUrl) {
    return serverUrl.isEmpty() ? QStringLiteral("bitwarden.com") : serverUrl;
}

QString bwDisplayName(const QString &name) {
    // Leading blanks and zero-width characters (a stray space, a BOM from a
    // paste) would show as padding in the name column.
    const auto skippable = [](QChar c) {
        return c.isSpace() || c.category() == QChar::Other_Format;
    };
    int first = 0;
    int last = name.size();
    while (first < last && skippable(name.at(first)))
        ++first;
    while (last > first && skippable(name.at(last - 1)))
        --last;

    QString display = name.mid(first, last - first);
    display.replace(QLatin1Char('/'), QChar(0x2215));
    return display.isEmpty() ? QStringLiteral("(untitled)") : display;
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
        const int type = item.value(QStringLiteral("type")).toInt();
        if (type < 1 || type > 5)
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

namespace {

void populateCommonItemFields(const QJsonObject &item, EntryData *data) {
    data->viewPassword = item.value(QStringLiteral("viewPassword")).toBool(true);
    data->customFieldsLoaded = true;
    const QJsonArray fields = item.value(QStringLiteral("fields")).toArray();
    for (const QJsonValue &fv : fields) {
        const QJsonObject fo = fv.toObject();
        CustomField cf;
        cf.type = fo.value(QStringLiteral("type")).toInt();
        cf.name = fo.value(QStringLiteral("name")).toString();
        cf.value = Secret(fo.value(QStringLiteral("value")).toString());
        data->customFields.append(cf);
    }
}

}

EntryData bwEntryData(const QJsonObject &item) {
    const int type = item.value(QStringLiteral("type")).toInt();
    if (type == 2) {
        EntryData data;
        data.isNote = true;
        data.notes = item.value(QStringLiteral("notes")).toString();
        populateCommonItemFields(item, &data);
        return data;
    }
    if (type == 3) {
        const QJsonObject card = item.value(QStringLiteral("card")).toObject();
        EntryData data;
        data.isCard = true;
        data.card.cardholderName = card.value(QStringLiteral("cardholderName")).toString();
        data.card.brand = card.value(QStringLiteral("brand")).toString();
        data.card.number = Secret(card.value(QStringLiteral("number")).toString());
        data.card.expMonth = card.value(QStringLiteral("expMonth")).toString();
        data.card.expYear = card.value(QStringLiteral("expYear")).toString();
        data.card.code = Secret(card.value(QStringLiteral("code")).toString());
        data.notes = item.value(QStringLiteral("notes")).toString();
        populateCommonItemFields(item, &data);
        return data;
    }
    if (type == 4) {
        const QJsonObject id = item.value(QStringLiteral("identity")).toObject();
        EntryData data;
        data.isIdentity = true;
        data.identity.title = id.value(QStringLiteral("title")).toString();
        data.identity.firstName = id.value(QStringLiteral("firstName")).toString();
        data.identity.middleName = id.value(QStringLiteral("middleName")).toString();
        data.identity.lastName = id.value(QStringLiteral("lastName")).toString();
        data.identity.company = id.value(QStringLiteral("company")).toString();
        data.identity.email = id.value(QStringLiteral("email")).toString();
        data.identity.phone = id.value(QStringLiteral("phone")).toString();
        data.identity.address1 = id.value(QStringLiteral("address1")).toString();
        data.identity.address2 = id.value(QStringLiteral("address2")).toString();
        data.identity.address3 = id.value(QStringLiteral("address3")).toString();
        data.identity.city = id.value(QStringLiteral("city")).toString();
        data.identity.state = id.value(QStringLiteral("state")).toString();
        data.identity.postalCode = id.value(QStringLiteral("postalCode")).toString();
        data.identity.country = id.value(QStringLiteral("country")).toString();
        data.identity.ssn = Secret(id.value(QStringLiteral("ssn")).toString());
        data.identity.passportNumber = Secret(id.value(QStringLiteral("passportNumber")).toString());
        data.identity.licenseNumber = Secret(id.value(QStringLiteral("licenseNumber")).toString());
        data.identity.username = id.value(QStringLiteral("username")).toString();
        data.notes = item.value(QStringLiteral("notes")).toString();
        populateCommonItemFields(item, &data);
        return data;
    }
    if (type == 5) {
        // The private key is what a key file holds: LF line ends and a final
        // newline, which ssh refuses to load without.
        QString key = item.value(QStringLiteral("sshKey")).toObject()
                          .value(QStringLiteral("privateKey")).toString();
        key.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
        key.replace(QLatin1Char('\r'), QLatin1Char('\n'));
        key = key.trimmed();
        if (!key.isEmpty())
            key += QLatin1Char('\n');

        EntryData data;
        data.password = Secret(key);
        data.sshPublicKey = item.value(QStringLiteral("sshKey")).toObject().value(QStringLiteral("publicKey")).toString();
        data.notes = item.value(QStringLiteral("notes")).toString();
        populateCommonItemFields(item, &data);
        return data;
    }

    const QJsonObject login = item.value(QStringLiteral("login")).toObject();
    const QJsonArray uris = login.value(QStringLiteral("uris")).toArray();

    EntryData data;
    data.username = login.value(QStringLiteral("username")).toString();
    data.password = Secret(login.value(QStringLiteral("password")).toString());
    data.url = uris.isEmpty() ? QString()
                              : uris.first().toObject().value(QStringLiteral("uri")).toString();
    for (int i = 1; i < uris.size(); ++i) {
        const QString uri = uris.at(i).toObject().value(QStringLiteral("uri")).toString().trimmed();
        if (!uri.isEmpty())
            data.extraUrls.append(uri);
    }
    data.notes = item.value(QStringLiteral("notes")).toString();
    data.otp = Secret(login.value(QStringLiteral("totp")).toString());
    populateCommonItemFields(item, &data);
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
