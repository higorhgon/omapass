#include "bitwardenjson.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <algorithm>

namespace {

QJsonValue nullableString(const QString &text) {
    return text.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(text);
}

QJsonObject blankLoginItem() {
    QJsonObject login;
    login.insert(QStringLiteral("uris"), QJsonArray());
    login.insert(QStringLiteral("username"), QJsonValue::Null);
    login.insert(QStringLiteral("password"), QJsonValue::Null);
    login.insert(QStringLiteral("totp"), QJsonValue::Null);

    QJsonObject item;
    item.insert(QStringLiteral("organizationId"), QJsonValue::Null);
    item.insert(QStringLiteral("collectionIds"), QJsonValue::Null);
    item.insert(QStringLiteral("folderId"), QJsonValue::Null);
    item.insert(QStringLiteral("type"), 1);
    item.insert(QStringLiteral("name"), QString());
    item.insert(QStringLiteral("notes"), QJsonValue::Null);
    item.insert(QStringLiteral("favorite"), false);
    item.insert(QStringLiteral("fields"), QJsonArray());
    item.insert(QStringLiteral("login"), login);
    item.insert(QStringLiteral("secureNote"), QJsonValue::Null);
    item.insert(QStringLiteral("card"), QJsonValue::Null);
    item.insert(QStringLiteral("identity"), QJsonValue::Null);
    item.insert(QStringLiteral("reprompt"), 0);
    return item;
}

}

BwStatus parseBwStatus(const QString &json) {
    BwStatus status;
    const QJsonObject object = QJsonDocument::fromJson(json.trimmed().toUtf8()).object();
    status.status = object.value(QStringLiteral("status")).toString();
    status.userEmail = object.value(QStringLiteral("userEmail")).toString();
    return status;
}

QString bwDisplayName(const QString &name) {
    QString display = name;
    display.replace(QLatin1Char('/'), QChar(0x2215));
    return display.trimmed().isEmpty() ? QStringLiteral("(untitled)") : display;
}

BwIndex buildBwIndex(const QByteArray &itemsJson, const QByteArray &foldersJson) {
    BwIndex index;

    QHash<QString, QString> folderNames; // id → name
    const QJsonArray folders = QJsonDocument::fromJson(foldersJson).array();
    for (const QJsonValue &value : folders) {
        const QJsonObject folder = value.toObject();
        const QString id = folder.value(QStringLiteral("id")).toString();
        QString name = folder.value(QStringLiteral("name")).toString();
        while (name.endsWith(QLatin1Char('/')))
            name.chop(1);
        // `bw list folders` includes a "No Folder" pseudo-folder with a null id.
        if (id.isEmpty() || name.isEmpty())
            continue;
        folderNames.insert(id, name);
        index.folders.insert(name, id);
    }

    QStringList groups;
    for (const QString &name : std::as_const(folderNames)) {
        const QStringList parts = name.split(QLatin1Char('/'));
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

    const QJsonArray items = QJsonDocument::fromJson(itemsJson).array();
    for (const QJsonValue &value : items) {
        const QJsonObject item = value.toObject();
        if (item.value(QStringLiteral("type")).toInt() != 1)
            continue;
        if (!item.value(QStringLiteral("deletedDate")).isNull()
            && !item.value(QStringLiteral("deletedDate")).isUndefined())
            continue;

        BwItemRef ref;
        ref.id = item.value(QStringLiteral("id")).toString();
        ref.name = item.value(QStringLiteral("name")).toString();
        ref.folderId = item.value(QStringLiteral("folderId")).toString();
        if (ref.id.isEmpty())
            continue;

        // An item pointing at a folder we did not get back sits at the root.
        const QString group = folderNames.value(ref.folderId);
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

QByteArray applyBwEntryData(const QByteArray &itemJson, const QString &name,
                            const QString &folderId, const EntryData &data) {
    QJsonObject item = itemJson.isEmpty() ? blankLoginItem()
                                          : QJsonDocument::fromJson(itemJson).object();

    item.insert(QStringLiteral("name"), name);
    item.insert(QStringLiteral("folderId"), nullableString(folderId));
    item.insert(QStringLiteral("notes"), nullableString(data.notes));

    QJsonObject login = item.value(QStringLiteral("login")).toObject();
    login.insert(QStringLiteral("username"), nullableString(data.username));
    login.insert(QStringLiteral("password"), nullableString(data.password.toString()));

    QJsonArray uris = login.value(QStringLiteral("uris")).toArray();
    if (data.url.isEmpty()) {
        if (!uris.isEmpty())
            uris.removeFirst();
    } else if (uris.isEmpty()) {
        uris.append(QJsonObject{{QStringLiteral("match"), QJsonValue::Null},
                                {QStringLiteral("uri"), data.url}});
    } else {
        QJsonObject first = uris.first().toObject();
        first.insert(QStringLiteral("uri"), data.url);
        uris.replace(0, first);
    }
    login.insert(QStringLiteral("uris"), uris);
    item.insert(QStringLiteral("login"), login);

    return QJsonDocument(item).toJson(QJsonDocument::Compact);
}

QByteArray bwFolderJson(const QString &name) {
    return QJsonDocument(QJsonObject{{QStringLiteral("name"), name}}).toJson(QJsonDocument::Compact);
}

BwLoginError classifyBwError(const QString &output) {
    const auto has = [&output](const char *text) {
        return output.contains(QLatin1String(text), Qt::CaseInsensitive);
    };

    if (output.trimmed().isEmpty())
        return BwLoginError::None;
    if (has("Username or password is incorrect") || has("Invalid master password")
        || has("Master password is required"))
        return BwLoginError::WrongPassword;
    if (has("Email address is invalid"))
        return BwLoginError::InvalidEmail;
    if (has("Two-step token is invalid") || has("Invalid verification code")
        || has("Invalid two-step login method") || has("Code is required")
        || has("Invalid email or verification code"))
        return BwLoginError::InvalidCode;
    if (has("already logged in"))
        return BwLoginError::AlreadyLoggedIn;
    return BwLoginError::Other;
}

BwPrompt detectBwPrompt(const QString &stderrText) {
    // Checked from the most specific prompt down: a later prompt in the same
    // run always comes after the earlier ones in the stream.
    const int device = stderrText.lastIndexOf(QLatin1String("New device verification required"));
    const int code = stderrText.lastIndexOf(QLatin1String("Two-step login code:"));
    const int method = stderrText.lastIndexOf(QLatin1String("Two-step login method:"));

    const int latest = std::max({device, code, method});
    if (latest < 0)
        return BwPrompt::None;
    if (latest == device)
        return BwPrompt::NewDeviceCode;
    if (latest == code)
        return BwPrompt::TwoFactorCode;
    return BwPrompt::TwoFactorMethod;
}
