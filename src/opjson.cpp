#include "opjson.h"

#include <QJsonArray>
#include <QJsonDocument>

#include <algorithm>

namespace {

// The categories omapass models. `op` also knows credit cards, identities,
// SSH keys and a dozen more, which a title/username/password/URL/notes form
// cannot round-trip.
const auto loginCategory = QStringLiteral("LOGIN");
const auto passwordCategory = QStringLiteral("PASSWORD");

QJsonObject blankLoginItem() {
    QJsonObject item;
    item.insert(QStringLiteral("title"), QString());
    item.insert(QStringLiteral("category"), loginCategory);
    item.insert(QStringLiteral("tags"), QJsonArray());
    item.insert(QStringLiteral("fields"), QJsonArray());
    item.insert(QStringLiteral("urls"), QJsonArray());
    return item;
}

// The item's tags, as 1Password stores them: normalised, without repeats and
// in the order that decides which one places the item.
QStringList itemTags(const QJsonObject &item) {
    QStringList tags;
    const QJsonArray array = item.value(QStringLiteral("tags")).toArray();
    for (const QJsonValue &value : array) {
        const QString tag = opNormalizeTag(value.toString());
        if (!tag.isEmpty() && !tags.contains(tag))
            tags.append(tag);
    }
    tags.sort();
    return tags;
}

// The tag an item is filed under here: an item can carry several, but the
// entry list is a tree, so the first in alphabetical order wins.
QString placingTag(const QStringList &sortedTags) {
    return sortedTags.isEmpty() ? QString() : sortedTags.first();
}

QString fieldValue(const QJsonObject &item, const QString &purpose) {
    const QJsonArray fields = item.value(QStringLiteral("fields")).toArray();
    for (const QJsonValue &value : fields) {
        const QJsonObject field = value.toObject();
        if (field.value(QStringLiteral("purpose")).toString() == purpose)
            return field.value(QStringLiteral("value")).toString();
    }
    return QString();
}

// Writes a built-in field, keeping the object `op` gave us (its id, section
// and label) when the item already has it. A field that is not there and has
// nothing to say is not created.
void setFieldValue(QJsonArray *fields, const QString &purpose, const QString &id,
                   const QString &type, const QString &value) {
    for (int i = 0; i < fields->size(); ++i) {
        QJsonObject field = fields->at(i).toObject();
        if (field.value(QStringLiteral("purpose")).toString() != purpose)
            continue;
        field.insert(QStringLiteral("value"), value);
        fields->replace(i, field);
        return;
    }

    if (value.isEmpty())
        return;

    QJsonObject field;
    field.insert(QStringLiteral("id"), id);
    field.insert(QStringLiteral("type"), type);
    field.insert(QStringLiteral("purpose"), purpose);
    field.insert(QStringLiteral("label"), id);
    field.insert(QStringLiteral("value"), value);
    fields->append(field);
}

// The URL omapass shows and edits: the one marked primary, or the first.
int primaryUrlIndex(const QJsonArray &urls) {
    for (int i = 0; i < urls.size(); ++i) {
        if (urls.at(i).toObject().value(QStringLiteral("primary")).toBool())
            return i;
    }
    return urls.isEmpty() ? -1 : 0;
}

}

QString OpAccount::key() const {
    return shorthand.isEmpty() ? userUuid : shorthand;
}

QVector<OpAccount> parseOpAccounts(const QByteArray &json) {
    QVector<OpAccount> accounts;
    const QJsonArray array = QJsonDocument::fromJson(json).array();
    for (const QJsonValue &value : array) {
        const QJsonObject object = value.toObject();
        OpAccount account;
        account.shorthand = object.value(QStringLiteral("shorthand")).toString();
        account.email = object.value(QStringLiteral("email")).toString();
        account.url = object.value(QStringLiteral("url")).toString();
        account.userUuid = object.value(QStringLiteral("user_uuid")).toString();
        if (!account.key().isEmpty())
            accounts.append(account);
    }
    return accounts;
}

QHash<QString, QJsonObject> parseOpItems(const QByteArray &itemsJson) {
    QHash<QString, QJsonObject> items;
    const QJsonArray array = QJsonDocument::fromJson(itemsJson).array();
    for (const QJsonValue &value : array) {
        const QJsonObject item = value.toObject();
        const QString id = item.value(QStringLiteral("id")).toString();
        if (!id.isEmpty())
            items.insert(id, item);
    }
    return items;
}

QHash<QString, QString> parseOpVaults(const QByteArray &vaultsJson) {
    QHash<QString, QString> vaults;
    const QJsonArray array = QJsonDocument::fromJson(vaultsJson).array();
    for (const QJsonValue &value : array) {
        const QJsonObject vault = value.toObject();
        const QString id = vault.value(QStringLiteral("id")).toString();
        const QString name = vault.value(QStringLiteral("name")).toString();
        if (!id.isEmpty() && !name.isEmpty())
            vaults.insert(id, name);
    }
    return vaults;
}

QString opDisplayName(const QString &name) {
    QString display = name;
    display.replace(QLatin1Char('/'), QChar(0x2215));
    return display.trimmed().isEmpty() ? QStringLiteral("(untitled)") : display;
}

QString opVaultOf(const QString &path) {
    return path.section(QLatin1Char('/'), 0, 0);
}

QString opTagPathOf(const QString &path) {
    return path.section(QLatin1Char('/'), 1);
}

QString opNormalizeTag(const QString &tag) {
    QStringList parts;
    const QStringList raw = tag.split(QLatin1Char('/'));
    for (const QString &part : raw) {
        const QString trimmed = part.trimmed();
        if (!trimmed.isEmpty())
            parts.append(trimmed);
    }
    return parts.join(QLatin1Char('/'));
}

OpIndex buildOpIndex(const QHash<QString, QJsonObject> &items,
                     const QHash<QString, QString> &vaults) {
    OpIndex index;

    QStringList groups;
    const auto addGroup = [&groups](const QString &group) {
        if (!group.isEmpty() && !groups.contains(group))
            groups.append(group);
    };

    for (auto it = vaults.cbegin(); it != vaults.cend(); ++it) {
        const QString name = opDisplayName(it.value());
        index.vaults.insert(name, it.key());
        addGroup(name);
    }

    struct Candidate {
        QString path;
        OpItemRef ref;
    };
    QVector<Candidate> candidates;
    QHash<QString, int> pathCount;

    for (const QJsonObject &item : items) {
        const QString category = item.value(QStringLiteral("category")).toString();
        if (category != loginCategory && category != passwordCategory)
            continue;

        OpItemRef ref;
        ref.id = item.value(QStringLiteral("id")).toString();
        ref.title = item.value(QStringLiteral("title")).toString();
        const QJsonObject vault = item.value(QStringLiteral("vault")).toObject();
        ref.vaultId = vault.value(QStringLiteral("id")).toString();
        ref.vaultName = vault.value(QStringLiteral("name")).toString();
        // `op item get` names the vault; a listing trimmed to ids still can
        // be placed, as long as the vault came back in `op vault list`.
        if (ref.vaultName.isEmpty())
            ref.vaultName = vaults.value(ref.vaultId);
        ref.tagPath = placingTag(itemTags(item));
        if (ref.id.isEmpty())
            continue;

        const QString vaultGroup = opDisplayName(ref.vaultName);
        index.vaults.insert(vaultGroup, ref.vaultId);

        QString group = vaultGroup;
        addGroup(group);
        if (!ref.tagPath.isEmpty()) {
            const QStringList parts = ref.tagPath.split(QLatin1Char('/'));
            for (const QString &part : parts) {
                group += QLatin1Char('/') + part;
                addGroup(group);
            }
        }

        const QString path = group + QLatin1Char('/') + opDisplayName(ref.title);
        candidates.append({path, ref});
        pathCount[path] += 1;
    }

    groups.sort();
    index.groups = groups;

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

OpIndex buildOpIndex(const QByteArray &itemsJson, const QByteArray &vaultsJson) {
    return buildOpIndex(parseOpItems(itemsJson), parseOpVaults(vaultsJson));
}

EntryData opEntryData(const QJsonObject &item) {
    EntryData data;
    data.username = fieldValue(item, QStringLiteral("USERNAME"));
    data.password = Secret(fieldValue(item, QStringLiteral("PASSWORD")));
    data.notes = fieldValue(item, QStringLiteral("NOTES"));

    const QJsonArray urls = item.value(QStringLiteral("urls")).toArray();
    const int primary = primaryUrlIndex(urls);
    if (primary >= 0)
        data.url = urls.at(primary).toObject().value(QStringLiteral("href")).toString();
    return data;
}

bool opHasPasskey(const QJsonObject &item) {
    if (item.contains(QStringLiteral("passkey")))
        return true;
    const QJsonArray fields = item.value(QStringLiteral("fields")).toArray();
    for (const QJsonValue &value : fields) {
        if (value.toObject().value(QStringLiteral("id")).toString() == QLatin1String("passkey"))
            return true;
    }
    return false;
}

QByteArray applyOpEntryData(const QByteArray &itemJson, const QString &title,
                            const QString &tagPath, const EntryData &data) {
    QJsonObject item = itemJson.isEmpty() ? blankLoginItem()
                                          : QJsonDocument::fromJson(itemJson).object();

    item.insert(QStringLiteral("title"), title);

    // Only the tag that placed the item is replaced; the others are the
    // user's own filing and have nothing to do with the group it was moved
    // to.
    QStringList tags = itemTags(item);
    const QString placing = placingTag(tags);
    if (!placing.isEmpty())
        tags.removeAll(placing);
    const QString moved = opNormalizeTag(tagPath);
    if (!moved.isEmpty() && !tags.contains(moved))
        tags.append(moved);
    tags.sort();
    item.insert(QStringLiteral("tags"), QJsonArray::fromStringList(tags));

    QJsonArray fields = item.value(QStringLiteral("fields")).toArray();
    setFieldValue(&fields, QStringLiteral("USERNAME"), QStringLiteral("username"),
                  QStringLiteral("STRING"), data.username);
    setFieldValue(&fields, QStringLiteral("PASSWORD"), QStringLiteral("password"),
                  QStringLiteral("CONCEALED"), data.password.toString());
    setFieldValue(&fields, QStringLiteral("NOTES"), QStringLiteral("notesPlain"),
                  QStringLiteral("STRING"), data.notes);
    item.insert(QStringLiteral("fields"), fields);

    QJsonArray urls = item.value(QStringLiteral("urls")).toArray();
    const int primary = primaryUrlIndex(urls);
    if (data.url.isEmpty()) {
        if (primary >= 0)
            urls.removeAt(primary);
    } else if (primary < 0) {
        QJsonObject url;
        url.insert(QStringLiteral("label"), QStringLiteral("website"));
        url.insert(QStringLiteral("primary"), true);
        url.insert(QStringLiteral("href"), data.url);
        urls.append(url);
    } else {
        QJsonObject url = urls.at(primary).toObject();
        url.insert(QStringLiteral("href"), data.url);
        urls.replace(primary, url);
    }
    item.insert(QStringLiteral("urls"), urls);

    return QJsonDocument(item).toJson(QJsonDocument::Compact);
}

QByteArray opNewItemJson(const QString &title, const QString &vaultId,
                         const QString &tagPath, const EntryData &data) {
    QJsonObject item = blankLoginItem();
    QJsonObject vault;
    vault.insert(QStringLiteral("id"), vaultId);
    item.insert(QStringLiteral("vault"), vault);

    const QByteArray json = QJsonDocument(item).toJson(QJsonDocument::Compact);
    return applyOpEntryData(json, title, tagPath, data);
}

OpError classifyOpError(const QString &output) {
    const auto has = [&output](const char *text) {
        return output.contains(QLatin1String(text), Qt::CaseInsensitive);
    };

    if (output.trimmed().isEmpty())
        return OpError::None;
    if (has("session expired"))
        return OpError::SessionExpired;
    if (has("not currently signed in") || has("you are not authenticated")
        || has("Authentication required"))
        return OpError::NotSignedIn;
    if (has("No accounts configured") || has("account couldn't be found")
        || has("no account found"))
        return OpError::NoAccount;
    if (has("Incorrect Secret Key") || has("invalid secret key")
        || has("secret key was the wrong length") || has("unrecognized secret key version"))
        return OpError::WrongSecretKey;
    if (has("username/password authentication failed") || has("bad credentials")
        || has("invalid credentials"))
        return OpError::WrongPassword;
    if (has("authentication code") && (has("invalid") || has("incorrect")))
        return OpError::WrongCode;
    if (has("rate limit exceeded") || has("rate-limited") || has("Too many requests"))
        return OpError::RateLimited;
    return OpError::Other;
}

OpPrompt detectOpPrompt(const QString &stderrText) {
    // Checked by where they are in the stream, not by a fixed order: `op`
    // asks for the address, the e-mail, the Secret Key, the password and
    // then, if the account has it, the two-step code — and each prompt is
    // redrawn as the answer is typed.
    const int address = stderrText.lastIndexOf(QLatin1String("sign-in address"));
    const int email = stderrText.lastIndexOf(QLatin1String("email address for your account"));
    const int secretKey = stderrText.lastIndexOf(QLatin1String("Enter the Secret Key"));
    const int password = stderrText.lastIndexOf(QLatin1String("Enter the password for"));
    const int code = stderrText.lastIndexOf(QLatin1String("authentication code"));

    const int latest = std::max({address, email, secretKey, password, code});
    if (latest < 0)
        return OpPrompt::None;
    if (latest == code)
        return OpPrompt::TwoFactorCode;
    if (latest == password)
        return OpPrompt::Password;
    if (latest == secretKey)
        return OpPrompt::SecretKey;
    if (latest == email)
        return OpPrompt::Email;
    return OpPrompt::SignInAddress;
}
