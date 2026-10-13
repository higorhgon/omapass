#include "kdbx.h"

#include <QDateTime>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QTimeZone>
#include <QUuid>
#include <QXmlStreamReader>
#include <QXmlStreamWriter>

#include <botan/block_cipher.h>
#include <botan/cipher_mode.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pwdhash.h>
#include <botan/secmem.h>
#include <botan/stream_cipher.h>
#include <botan/system_rng.h>
#include <botan/version.h>

#include <zlib.h>

#include <cstring>
#include <vector>

#include "i18n.h"

namespace {

using Bytes = Botan::secure_vector<uint8_t>;

#if BOTAN_VERSION_MAJOR >= 3
constexpr auto decryptDirection = Botan::Cipher_Dir::Decryption;
constexpr auto encryptDirection = Botan::Cipher_Dir::Encryption;
#else
constexpr auto decryptDirection = Botan::DECRYPTION;
constexpr auto encryptDirection = Botan::ENCRYPTION;
#endif

constexpr quint32 signature1 = 0x9AA2D903;
constexpr quint32 signature2 = 0xB54BFB67;

// Guards against a hostile file asking for the moon.
constexpr qint64 maxPlainSize = 512LL * 1024 * 1024;
constexpr quint64 maxArgonKiB = 4ULL * 1024 * 1024;
constexpr quint64 maxKdfRounds = 4000000000ULL;
constexpr int blockSize = 1024 * 1024;

const QByteArray cipherAes = QByteArray::fromHex("31c1f2e6bf714350be5805216afc5aff");
const QByteArray cipherChaCha = QByteArray::fromHex("d6038a2b8b6f4cb5a524339a31dbb59a");
const QByteArray cipherTwofish = QByteArray::fromHex("ad68f29f576f4bb9a36ad47af965346c");
const QByteArray kdfAes = QByteArray::fromHex("c9d9f39a628a4460bf740d08c18a4fea");
const QByteArray kdfArgon2d = QByteArray::fromHex("ef636ddf8c29444b91f7a9a403e30a0c");
const QByteArray kdfArgon2id = QByteArray::fromHex("9e298b1956db4773b23dfc3ec6f0a1e6");
const QByteArray salsaIv = QByteArray::fromHex("e830094b97205d2a");

const QString noUuid = QStringLiteral("AAAAAAAAAAAAAAAAAAAAAA==");

Bytes toBytes(const QByteArray &data) {
    return Bytes(data.cbegin(), data.cend());
}

QByteArray toArray(const Bytes &data) {
    return QByteArray(reinterpret_cast<const char *>(data.data()), qsizetype(data.size()));
}

Bytes randomBytes(size_t size) {
    Bytes bytes(size);
    if (size > 0)
        Botan::system_rng().randomize(bytes.data(), bytes.size());
    return bytes;
}

Bytes sha256(const QByteArray &a, const QByteArray &b = QByteArray(), const QByteArray &c = QByteArray()) {
    const auto hash = Botan::HashFunction::create_or_throw("SHA-256");
    hash->update(reinterpret_cast<const uint8_t *>(a.constData()), size_t(a.size()));
    hash->update(reinterpret_cast<const uint8_t *>(b.constData()), size_t(b.size()));
    hash->update(reinterpret_cast<const uint8_t *>(c.constData()), size_t(c.size()));
    return Bytes(hash->final());
}

Bytes sha512(const QByteArray &a, const QByteArray &b = QByteArray(), const QByteArray &c = QByteArray()) {
    const auto hash = Botan::HashFunction::create_or_throw("SHA-512");
    hash->update(reinterpret_cast<const uint8_t *>(a.constData()), size_t(a.size()));
    hash->update(reinterpret_cast<const uint8_t *>(b.constData()), size_t(b.size()));
    hash->update(reinterpret_cast<const uint8_t *>(c.constData()), size_t(c.size()));
    return Bytes(hash->final());
}

Bytes hmacSha256(const Bytes &key, const QByteArray &a, const QByteArray &b = QByteArray(),
                 const QByteArray &c = QByteArray()) {
    const auto mac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
    mac->set_key(key.data(), key.size());
    mac->update(reinterpret_cast<const uint8_t *>(a.constData()), size_t(a.size()));
    mac->update(reinterpret_cast<const uint8_t *>(b.constData()), size_t(b.size()));
    mac->update(reinterpret_cast<const uint8_t *>(c.constData()), size_t(c.size()));
    return Bytes(mac->final());
}

QByteArray le32(quint32 value) {
    QByteArray out(4, '\0');
    for (int i = 0; i < 4; ++i)
        out[i] = char((value >> (8 * i)) & 0xFF);
    return out;
}

QByteArray le64(quint64 value) {
    QByteArray out(8, '\0');
    for (int i = 0; i < 8; ++i)
        out[i] = char((value >> (8 * i)) & 0xFF);
    return out;
}

QByteArray le16(quint16 value) {
    QByteArray out(2, '\0');
    out[0] = char(value & 0xFF);
    out[1] = char(value >> 8);
    return out;
}

// A reader over a byte buffer that records running past the end.
class Cursor {
public:
    explicit Cursor(const QByteArray &data) : m_data(data) {}

    bool ok() const { return !m_failed; }
    bool atEnd() const { return m_pos >= m_data.size(); }
    qsizetype pos() const { return m_pos; }
    qsizetype remaining() const { return m_data.size() - m_pos; }

    QByteArray bytes(qsizetype count) {
        if (count < 0 || count > remaining()) {
            m_failed = true;
            m_pos = m_data.size();
            return QByteArray();
        }
        const QByteArray out = m_data.mid(m_pos, count);
        m_pos += count;
        return out;
    }
    quint64 number(int size) {
        const QByteArray raw = bytes(size);
        quint64 value = 0;
        for (int i = 0; i < raw.size(); ++i)
            value |= quint64(quint8(raw[i])) << (8 * i);
        return value;
    }
    quint8 u8() { return quint8(number(1)); }
    quint16 u16() { return quint16(number(2)); }
    quint32 u32() { return quint32(number(4)); }
    quint64 u64() { return number(8); }

private:
    const QByteArray &m_data;
    qsizetype m_pos = 0;
    bool m_failed = false;
};

// ---------------------------------------------------------------- zlib

bool gunzip(const QByteArray &in, QByteArray *out) {
    z_stream stream;
    std::memset(&stream, 0, sizeof(stream));
    if (inflateInit2(&stream, 15 + 32) != Z_OK)
        return false;
    stream.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(in.constData()));
    stream.avail_in = uInt(in.size());

    out->clear();
    QByteArray chunk(64 * 1024, '\0');
    int result = Z_OK;
    while (result != Z_STREAM_END) {
        stream.next_out = reinterpret_cast<Bytef *>(chunk.data());
        stream.avail_out = uInt(chunk.size());
        result = inflate(&stream, Z_NO_FLUSH);
        if (result != Z_OK && result != Z_STREAM_END) {
            inflateEnd(&stream);
            return false;
        }
        out->append(chunk.constData(), chunk.size() - int(stream.avail_out));
        if (out->size() > maxPlainSize) {
            inflateEnd(&stream);
            return false;
        }
        if (result == Z_OK && stream.avail_in == 0 && stream.avail_out != 0) {
            inflateEnd(&stream);
            return false;   // truncated
        }
    }
    inflateEnd(&stream);
    return true;
}

bool gzip(const QByteArray &in, QByteArray *out) {
    z_stream stream;
    std::memset(&stream, 0, sizeof(stream));
    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return false;
    stream.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(in.constData()));
    stream.avail_in = uInt(in.size());

    out->clear();
    QByteArray chunk(64 * 1024, '\0');
    int result = Z_OK;
    while (result != Z_STREAM_END) {
        stream.next_out = reinterpret_cast<Bytef *>(chunk.data());
        stream.avail_out = uInt(chunk.size());
        result = deflate(&stream, Z_FINISH);
        if (result != Z_OK && result != Z_STREAM_END && result != Z_BUF_ERROR) {
            deflateEnd(&stream);
            return false;
        }
        out->append(chunk.constData(), chunk.size() - int(stream.avail_out));
    }
    deflateEnd(&stream);
    return true;
}

// ---------------------------------------------------------------- XML tree

struct XNode {
    QString name;
    QList<QPair<QString, QString>> attrs;
    QString text;
    std::vector<std::unique_ptr<XNode>> children;

    XNode *child(const QString &childName) const {
        for (const auto &node : children) {
            if (node->name == childName)
                return node.get();
        }
        return nullptr;
    }
    QList<XNode *> childrenNamed(const QString &childName) const {
        QList<XNode *> out;
        for (const auto &node : children) {
            if (node->name == childName)
                out.append(node.get());
        }
        return out;
    }
    QString childText(const QString &childName) const {
        const XNode *node = child(childName);
        return node ? node->text : QString();
    }
    XNode *add(const QString &childName, const QString &childText = QString()) {
        auto node = std::make_unique<XNode>();
        node->name = childName;
        node->text = childText;
        XNode *raw = node.get();
        children.push_back(std::move(node));
        return raw;
    }
    QString attr(const QString &attrName) const {
        for (const auto &pair : attrs) {
            if (pair.first == attrName)
                return pair.second;
        }
        return QString();
    }
    void setAttr(const QString &attrName, const QString &value) {
        for (auto &pair : attrs) {
            if (pair.first == attrName) {
                pair.second = value;
                return;
            }
        }
        attrs.append({attrName, value});
    }
    // The text of the child `childName`, created when missing.
    void setChildText(const QString &childName, const QString &value) {
        XNode *node = child(childName);
        if (!node)
            node = add(childName);
        node->text = value;
    }
    std::unique_ptr<XNode> clone() const {
        auto copy = std::make_unique<XNode>();
        copy->name = name;
        copy->attrs = attrs;
        copy->text = text;
        for (const auto &node : children)
            copy->children.push_back(node->clone());
        return copy;
    }
    std::unique_ptr<XNode> detach(XNode *node) {
        for (auto it = children.begin(); it != children.end(); ++it) {
            if (it->get() == node) {
                std::unique_ptr<XNode> out = std::move(*it);
                children.erase(it);
                return out;
            }
        }
        return nullptr;
    }
};

std::unique_ptr<XNode> parseXml(const QByteArray &data) {
    QXmlStreamReader reader(data);
    std::unique_ptr<XNode> root;
    std::vector<XNode *> stack;

    while (!reader.atEnd()) {
        switch (reader.readNext()) {
        case QXmlStreamReader::StartElement: {
            XNode *node = nullptr;
            if (stack.empty()) {
                if (root)
                    return nullptr;
                root = std::make_unique<XNode>();
                node = root.get();
            } else {
                node = stack.back()->add(QString());
            }
            node->name = reader.name().toString();
            for (const QXmlStreamAttribute &attribute : reader.attributes())
                node->attrs.append({attribute.name().toString(), attribute.value().toString()});
            stack.push_back(node);
            break;
        }
        case QXmlStreamReader::EndElement:
            if (stack.empty())
                return nullptr;
            // Whitespace between child elements is layout, not content.
            if (!stack.back()->children.empty())
                stack.back()->text.clear();
            stack.pop_back();
            break;
        case QXmlStreamReader::Characters:
            if (!stack.empty())
                stack.back()->text += reader.text().toString();
            break;
        default:
            break;
        }
    }
    if (reader.hasError() || !root || !stack.empty())
        return nullptr;
    return root;
}

QString xmlSafe(const QString &text) {
    // XML 1.0 has no spelling for most control characters.
    QString out;
    out.reserve(text.size());
    for (QChar c : text) {
        const ushort u = c.unicode();
        if (u >= 0x20 || u == 0x09 || u == 0x0A || u == 0x0D)
            out.append(c);
    }
    return out;
}

void writeXml(QXmlStreamWriter &writer, const XNode &node) {
    writer.writeStartElement(node.name);
    for (const auto &pair : node.attrs)
        writer.writeAttribute(pair.first, pair.second);
    if (node.children.empty()) {
        if (!node.text.isEmpty())
            writer.writeCharacters(xmlSafe(node.text));
    } else {
        for (const auto &child : node.children)
            writeXml(writer, *child);
    }
    writer.writeEndElement();
}

// Every <Value Protected="True"> in document order — the order the inner
// stream cipher ran in.
void collectProtected(XNode &node, std::vector<XNode *> *out) {
    if (node.name == QLatin1String("Value") && node.attr(QStringLiteral("Protected")).compare(QLatin1String("True"), Qt::CaseInsensitive) == 0)
        out->push_back(&node);
    for (const auto &child : node.children)
        collectProtected(*child, out);
}

// ---------------------------------------------------------------- stream ciphers

class InnerStream {
public:
    bool init(quint32 id, const QByteArray &key) {
        try {
            if (id == 3) {
                const Bytes digest = sha512(key);
                m_cipher = Botan::StreamCipher::create_or_throw("ChaCha(20)");
                m_cipher->set_key(digest.data(), 32);
                m_cipher->set_iv(digest.data() + 32, 12);
                return true;
            }
            if (id == 2) {
                const Bytes digest = sha256(key);
                m_cipher = Botan::StreamCipher::create_or_throw("Salsa20");
                m_cipher->set_key(digest.data(), digest.size());
                m_cipher->set_iv(reinterpret_cast<const uint8_t *>(salsaIv.constData()), size_t(salsaIv.size()));
                return true;
            }
        } catch (const std::exception &) {
        }
        return false;
    }
    QByteArray apply(const QByteArray &in) {
        QByteArray out(in.size(), '\0');
        if (!in.isEmpty()) {
            m_cipher->cipher(reinterpret_cast<const uint8_t *>(in.constData()),
                             reinterpret_cast<uint8_t *>(out.data()), size_t(in.size()));
        }
        return out;
    }

private:
    std::unique_ptr<Botan::StreamCipher> m_cipher;
};

// Outer cipher over the whole payload.
bool applyCipher(const QByteArray &cipherId, const Bytes &key, const Bytes &iv, Bytes *data,
                 bool encrypt) {
    try {
        if (cipherId == cipherChaCha) {
            const auto stream = Botan::StreamCipher::create_or_throw("ChaCha(20)");
            stream->set_key(key.data(), key.size());
            stream->set_iv(iv.data(), iv.size());
            if (!data->empty())
                stream->cipher(data->data(), data->data(), data->size());
            return true;
        }
        const char *spec = cipherId == cipherAes ? "AES-256/CBC/PKCS7"
                         : cipherId == cipherTwofish ? "Twofish/CBC/PKCS7" : nullptr;
        if (!spec)
            return false;
        const auto mode = Botan::Cipher_Mode::create_or_throw(spec, encrypt ? encryptDirection : decryptDirection);
        mode->set_key(key);
        mode->start(iv);
        mode->finish(*data);
        return true;
    } catch (const std::exception &) {
        return false;
    }
}

// ---------------------------------------------------------------- time

QString timeStamp(bool binary) {
    const QDateTime now = QDateTime::currentDateTimeUtc();
    if (!binary)
        return now.toString(QStringLiteral("yyyy-MM-ddTHH:mm:ssZ"));
    const QDateTime epoch(QDate(1, 1, 1), QTime(0, 0), QTimeZone::UTC);
    const qint64 seconds = epoch.secsTo(now);
    return QString::fromLatin1(le64(quint64(seconds)).toBase64());
}

QString newUuid() {
    const Bytes raw = randomBytes(16);
    return QString::fromLatin1(toArray(raw).toBase64());
}

}  // namespace

// ================================================================ Impl

class KdbxDatabase::Impl {
public:
    int major = 4;
    int minor = 0;
    QByteArray cipherId = cipherAes;
    bool compressed = true;

    // KDF
    QByteArray kdfId = kdfArgon2d;
    Bytes kdfSalt;                // AES-KDF seed / Argon2 salt
    quint64 aesRounds = 0;
    quint32 argonParallelism = 2;
    quint64 argonMemory = 64ULL * 1024 * 1024;   // bytes
    quint64 argonIterations = 10;
    quint32 argonVersion = 0x13;

    Bytes transformed;            // the transformed key, kept to save without a new KDF
    quint32 innerStreamId = 3;
    QList<QByteArray> binaries;   // KDBX 4 inner-header attachments: flag byte + data
    QByteArray publicCustomData;  // KDBX 4 header field 12, verbatim

    std::unique_ptr<XNode> xml;   // <KeePassFile>

    bool binaryTimes() const { return major >= 4; }

    XNode *meta() const { return xml ? xml->child(QStringLiteral("Meta")) : nullptr; }
    XNode *rootGroup() const {
        XNode *root = xml ? xml->child(QStringLiteral("Root")) : nullptr;
        return root ? root->child(QStringLiteral("Group")) : nullptr;
    }

    // -- key derivation
    bool transform(const Bytes &composite, QString *detail);

    // -- tree
    static QString stringOf(const XNode &entry, const QString &key);
    static void setString(XNode &entry, const QString &key, const QString &value, bool isProtected);
    XNode *findGroup(const QString &path) const;
    XNode *ensureGroup(const QString &path);
    XNode *findEntry(const QString &path, XNode **parent = nullptr) const;
    XNode *parentOf(const XNode *target) const;
    XNode *recycleBin(bool create);
    bool insideBin(const XNode *node) const;
    std::unique_ptr<XNode> makeGroup(const QString &name) const;
    std::unique_ptr<XNode> makeEntry(const KdbxEntry &entry) const;
    void touch(XNode &node, const QString &field) const;
    void recordDeleted(const QString &uuid);
    void fill(XNode &entry, const KdbxEntry &data) const;
    void walk(const XNode &group, const QString &prefix, QStringList *entries, QStringList *groups,
              QList<QPair<QString, KdbxEntry>> *all, const XNode *skip = nullptr) const;
    static KdbxEntry read(const XNode &entry);

private:
    static XNode *search(XNode &node, const XNode *target);
};

bool KdbxDatabase::Impl::transform(const Bytes &composite, QString *detail) {
    try {
        if (kdfId == kdfAes) {
            if (kdfSalt.size() != 32) {
                *detail = QStringLiteral("AES-KDF seed");
                return false;
            }
            if (aesRounds == 0 || aesRounds > maxKdfRounds) {
                *detail = QStringLiteral("AES-KDF rounds");
                return false;
            }
            const auto aes = Botan::BlockCipher::create_or_throw("AES-256");
            aes->set_key(kdfSalt.data(), kdfSalt.size());
            Bytes key = composite;
            for (quint64 i = 0; i < aesRounds; ++i)
                aes->encrypt_n(key.data(), key.data(), 2);
            transformed = sha256(toArray(key));
            return true;
        }
        if (kdfId == kdfArgon2d || kdfId == kdfArgon2id) {
            const quint64 kib = argonMemory / 1024;
            if (kdfSalt.size() < 8 || argonParallelism == 0 || argonParallelism > 255 || argonIterations == 0
                || argonIterations > 1000000 || kib < 8 || kib > maxArgonKiB) {
                *detail = QStringLiteral("Argon2 parameters");
                return false;
            }
            if (argonVersion != 0x13) {
                *detail = QStringLiteral("Argon2 version");
                return false;
            }
            const auto family = Botan::PasswordHashFamily::create_or_throw(
                kdfId == kdfArgon2d ? "Argon2d" : "Argon2id");
            const auto hash = family->from_params(size_t(kib), size_t(argonIterations), size_t(argonParallelism));
            Bytes out(32);
            hash->derive_key(out.data(), out.size(), reinterpret_cast<const char *>(composite.data()),
                             composite.size(), kdfSalt.data(), kdfSalt.size());
            transformed = out;
            return true;
        }
    } catch (const std::exception &error) {
        *detail = QString::fromUtf8(error.what());
        return false;
    }
    *detail = QStringLiteral("KDF");
    return false;
}

// ---- tree helpers

QString KdbxDatabase::Impl::stringOf(const XNode &entry, const QString &key) {
    for (const XNode *item : entry.childrenNamed(QStringLiteral("String"))) {
        if (item->childText(QStringLiteral("Key")) == key)
            return item->childText(QStringLiteral("Value"));
    }
    return QString();
}

void KdbxDatabase::Impl::setString(XNode &entry, const QString &key, const QString &value, bool isProtected) {
    for (XNode *item : entry.childrenNamed(QStringLiteral("String"))) {
        if (item->childText(QStringLiteral("Key")) != key)
            continue;
        XNode *valueNode = item->child(QStringLiteral("Value"));
        if (!valueNode)
            valueNode = item->add(QStringLiteral("Value"));
        valueNode->text = value;
        return;
    }

    // New strings go after the last existing one, ahead of Times and the rest.
    auto item = std::make_unique<XNode>();
    item->name = QStringLiteral("String");
    item->add(QStringLiteral("Key"), key);
    XNode *valueNode = item->add(QStringLiteral("Value"), value);
    if (isProtected)
        valueNode->setAttr(QStringLiteral("Protected"), QStringLiteral("True"));

    size_t at = entry.children.size();
    for (size_t i = 0; i < entry.children.size(); ++i) {
        if (entry.children[i]->name == QLatin1String("String"))
            at = i + 1;
    }
    entry.children.insert(entry.children.begin() + long(at), std::move(item));
}

XNode *KdbxDatabase::Impl::findGroup(const QString &path) const {
    XNode *group = rootGroup();
    if (!group)
        return nullptr;
    const QStringList parts = path.split(QLatin1Char('/'), Qt::SkipEmptyParts);
    for (const QString &part : parts) {
        XNode *next = nullptr;
        for (XNode *candidate : group->childrenNamed(QStringLiteral("Group"))) {
            if (candidate->childText(QStringLiteral("Name")) == part) {
                next = candidate;
                break;
            }
        }
        if (!next)
            return nullptr;
        group = next;
    }
    return group;
}

std::unique_ptr<XNode> KdbxDatabase::Impl::makeGroup(const QString &name) const {
    auto group = std::make_unique<XNode>();
    group->name = QStringLiteral("Group");
    group->add(QStringLiteral("UUID"), newUuid());
    group->add(QStringLiteral("Name"), name);
    group->add(QStringLiteral("Notes"));
    group->add(QStringLiteral("IconID"), QStringLiteral("48"));
    XNode *times = group->add(QStringLiteral("Times"));
    const QString now = timeStamp(binaryTimes());
    times->add(QStringLiteral("CreationTime"), now);
    times->add(QStringLiteral("LastModificationTime"), now);
    times->add(QStringLiteral("LastAccessTime"), now);
    times->add(QStringLiteral("ExpiryTime"), now);
    times->add(QStringLiteral("Expires"), QStringLiteral("False"));
    times->add(QStringLiteral("UsageCount"), QStringLiteral("0"));
    times->add(QStringLiteral("LocationChanged"), now);
    group->add(QStringLiteral("IsExpanded"), QStringLiteral("True"));
    group->add(QStringLiteral("DefaultAutoTypeSequence"));
    group->add(QStringLiteral("EnableAutoType"), QStringLiteral("null"));
    group->add(QStringLiteral("EnableSearching"), QStringLiteral("null"));
    group->add(QStringLiteral("LastTopVisibleEntry"), noUuid);
    return group;
}

XNode *KdbxDatabase::Impl::ensureGroup(const QString &path) {
    XNode *group = rootGroup();
    if (!group)
        return nullptr;
    const QStringList parts = path.split(QLatin1Char('/'), Qt::SkipEmptyParts);
    for (const QString &part : parts) {
        XNode *next = nullptr;
        for (XNode *candidate : group->childrenNamed(QStringLiteral("Group"))) {
            if (candidate->childText(QStringLiteral("Name")) == part) {
                next = candidate;
                break;
            }
        }
        if (!next) {
            // Groups go after the entries' siblings' groups, ahead of entries.
            auto created = makeGroup(part);
            next = created.get();
            size_t at = group->children.size();
            for (size_t i = 0; i < group->children.size(); ++i) {
                if (group->children[i]->name == QLatin1String("Entry")) {
                    at = i;
                    break;
                }
            }
            group->children.insert(group->children.begin() + long(at), std::move(created));
        }
        group = next;
    }
    return group;
}

XNode *KdbxDatabase::Impl::findEntry(const QString &path, XNode **parent) const {
    const int slash = path.lastIndexOf(QLatin1Char('/'));
    const QString groupPath = slash < 0 ? QString() : path.left(slash);
    const QString title = slash < 0 ? path : path.mid(slash + 1);
    XNode *group = findGroup(groupPath);
    if (!group)
        return nullptr;
    for (XNode *entry : group->childrenNamed(QStringLiteral("Entry"))) {
        if (stringOf(*entry, QStringLiteral("Title")) == title) {
            if (parent)
                *parent = group;
            return entry;
        }
    }
    return nullptr;
}

XNode *KdbxDatabase::Impl::search(XNode &node, const XNode *target) {
    for (const auto &child : node.children) {
        if (child.get() == target)
            return &node;
        if (XNode *found = search(*child, target))
            return found;
    }
    return nullptr;
}

XNode *KdbxDatabase::Impl::parentOf(const XNode *target) const {
    XNode *root = rootGroup();
    return root ? search(*root, target) : nullptr;
}

XNode *KdbxDatabase::Impl::recycleBin(bool create) {
    XNode *metaNode = meta();
    XNode *root = rootGroup();
    if (!metaNode || !root)
        return nullptr;

    const QString wanted = metaNode->childText(QStringLiteral("RecycleBinUUID"));
    if (!wanted.isEmpty() && wanted != noUuid) {
        std::vector<XNode *> stack{root};
        while (!stack.empty()) {
            XNode *group = stack.back();
            stack.pop_back();
            if (group->childText(QStringLiteral("UUID")) == wanted)
                return group;
            for (XNode *sub : group->childrenNamed(QStringLiteral("Group")))
                stack.push_back(sub);
        }
    }
    if (!create)
        return nullptr;

    auto bin = makeGroup(QStringLiteral("Recycle Bin"));
    bin->setChildText(QStringLiteral("IconID"), QStringLiteral("43"));
    bin->setChildText(QStringLiteral("EnableAutoType"), QStringLiteral("False"));
    bin->setChildText(QStringLiteral("EnableSearching"), QStringLiteral("False"));
    XNode *raw = bin.get();
    metaNode->setChildText(QStringLiteral("RecycleBinUUID"), raw->childText(QStringLiteral("UUID")));
    metaNode->setChildText(QStringLiteral("RecycleBinChanged"), timeStamp(binaryTimes()));
    size_t at = root->children.size();
    for (size_t i = 0; i < root->children.size(); ++i) {
        if (root->children[i]->name == QLatin1String("Entry")) {
            at = i;
            break;
        }
    }
    root->children.insert(root->children.begin() + long(at), std::move(bin));
    return raw;
}

bool KdbxDatabase::Impl::insideBin(const XNode *node) const {
    const XNode *bin = const_cast<Impl *>(this)->recycleBin(false);
    if (!bin)
        return false;
    for (const XNode *at = node; at; at = parentOf(at)) {
        if (at == bin)
            return true;
    }
    return false;
}

void KdbxDatabase::Impl::touch(XNode &node, const QString &field) const {
    XNode *times = node.child(QStringLiteral("Times"));
    if (!times)
        times = node.add(QStringLiteral("Times"));
    times->setChildText(field, timeStamp(binaryTimes()));
}

void KdbxDatabase::Impl::recordDeleted(const QString &uuid) {
    XNode *root = xml ? xml->child(QStringLiteral("Root")) : nullptr;
    if (!root)
        return;
    XNode *deleted = root->child(QStringLiteral("DeletedObjects"));
    if (!deleted)
        deleted = root->add(QStringLiteral("DeletedObjects"));
    XNode *object = deleted->add(QStringLiteral("DeletedObject"));
    object->add(QStringLiteral("UUID"), uuid);
    object->add(QStringLiteral("DeletionTime"), timeStamp(binaryTimes()));
}

void KdbxDatabase::Impl::fill(XNode &entry, const KdbxEntry &data) const {
    setString(entry, QStringLiteral("Title"), data.title, false);
    setString(entry, QStringLiteral("UserName"), data.username, false);
    setString(entry, QStringLiteral("Password"), data.password.toString(), true);
    setString(entry, QStringLiteral("URL"), data.url, false);
    setString(entry, QStringLiteral("Notes"), data.notes, false);

    // A password that was written before may sit in a node without the flag
    // (another client's choice); the protection setting of the database says.
    for (XNode *item : entry.childrenNamed(QStringLiteral("String"))) {
        if (item->childText(QStringLiteral("Key")) == QLatin1String("Password")) {
            if (XNode *value = item->child(QStringLiteral("Value")))
                value->setAttr(QStringLiteral("Protected"), QStringLiteral("True"));
        }
    }
}

std::unique_ptr<XNode> KdbxDatabase::Impl::makeEntry(const KdbxEntry &data) const {
    auto entry = std::make_unique<XNode>();
    entry->name = QStringLiteral("Entry");
    entry->add(QStringLiteral("UUID"), newUuid());
    entry->add(QStringLiteral("IconID"), QStringLiteral("0"));
    entry->add(QStringLiteral("ForegroundColor"));
    entry->add(QStringLiteral("BackgroundColor"));
    entry->add(QStringLiteral("OverrideURL"));
    entry->add(QStringLiteral("Tags"));
    XNode *times = entry->add(QStringLiteral("Times"));
    const QString now = timeStamp(binaryTimes());
    times->add(QStringLiteral("CreationTime"), now);
    times->add(QStringLiteral("LastModificationTime"), now);
    times->add(QStringLiteral("LastAccessTime"), now);
    times->add(QStringLiteral("ExpiryTime"), now);
    times->add(QStringLiteral("Expires"), QStringLiteral("False"));
    times->add(QStringLiteral("UsageCount"), QStringLiteral("0"));
    times->add(QStringLiteral("LocationChanged"), now);
    fill(*entry, data);
    XNode *autoType = entry->add(QStringLiteral("AutoType"));
    autoType->add(QStringLiteral("Enabled"), QStringLiteral("True"));
    autoType->add(QStringLiteral("DataTransferObfuscation"), QStringLiteral("0"));
    entry->add(QStringLiteral("History"));
    return entry;
}

KdbxEntry KdbxDatabase::Impl::read(const XNode &entry) {
    KdbxEntry out;
    out.title = stringOf(entry, QStringLiteral("Title"));
    out.username = stringOf(entry, QStringLiteral("UserName"));
    out.password = Secret(stringOf(entry, QStringLiteral("Password")));
    out.url = stringOf(entry, QStringLiteral("URL"));
    out.notes = stringOf(entry, QStringLiteral("Notes"));
    return out;
}

void KdbxDatabase::Impl::walk(const XNode &group, const QString &prefix, QStringList *entries,
                              QStringList *groups, QList<QPair<QString, KdbxEntry>> *all,
                              const XNode *skip) const {
    for (const XNode *entry : group.childrenNamed(QStringLiteral("Entry"))) {
        const QString title = stringOf(*entry, QStringLiteral("Title"));
        const QString path = prefix + title;
        if (entries)
            entries->append(path);
        if (all)
            all->append({path, read(*entry)});
    }
    for (const XNode *sub : group.childrenNamed(QStringLiteral("Group"))) {
        if (sub == skip)
            continue;
        const QString path = prefix + sub->childText(QStringLiteral("Name"));
        if (groups)
            groups->append(path);
        walk(*sub, path + QLatin1Char('/'), entries, groups, all, skip);
    }
}

// ================================================================ container

namespace {

// A VariantDictionary: key → value of the few types KDF parameters use.
bool readVariantDictionary(const QByteArray &data, QMap<QString, QVariant> *out) {
    Cursor cursor(data);
    const quint16 version = cursor.u16();
    if (!cursor.ok() || (version >> 8) != 1)
        return false;
    while (cursor.ok()) {
        const quint8 type = cursor.u8();
        if (type == 0)
            return cursor.ok();
        const quint32 keyLength = cursor.u32();
        const QByteArray key = cursor.bytes(keyLength);
        const quint32 valueLength = cursor.u32();
        const QByteArray value = cursor.bytes(valueLength);
        if (!cursor.ok())
            return false;

        Cursor valueCursor(value);
        const QString name = QString::fromUtf8(key);
        switch (type) {
        case 0x04:
            out->insert(name, QVariant::fromValue<quint32>(quint32(valueCursor.u32())));
            break;
        case 0x05:
            out->insert(name, QVariant::fromValue<quint64>(valueCursor.u64()));
            break;
        case 0x08:
        case 0x0C:
        case 0x0D:
            out->insert(name, QVariant::fromValue<quint64>(valueCursor.number(int(value.size()))));
            break;
        case 0x18:
            out->insert(name, QString::fromUtf8(value));
            break;
        case 0x42:
            out->insert(name, value);
            break;
        default:
            return false;
        }
    }
    return false;
}

void putVariant(QByteArray *out, quint8 type, const QString &key, const QByteArray &value) {
    out->append(char(type));
    const QByteArray keyBytes = key.toUtf8();
    out->append(le32(quint32(keyBytes.size())));
    out->append(keyBytes);
    out->append(le32(quint32(value.size())));
    out->append(value);
}

void putField(QByteArray *out, quint8 id, const QByteArray &value, bool wide) {
    out->append(char(id));
    out->append(wide ? le32(quint32(value.size())) : le16(quint16(value.size())));
    out->append(value);
}

}  // namespace

KdbxDatabase::KdbxDatabase(std::unique_ptr<Impl> impl) : d(std::move(impl)) {}
KdbxDatabase::~KdbxDatabase() = default;

std::unique_ptr<KdbxDatabase> KdbxDatabase::open(const QString &path, const Secret &password,
                                                 KdbxStatus *status, QString *detail) {
    QString note;
    QString *reason = detail ? detail : &note;
    const auto fail = [&](KdbxStatus code, const QString &why = QString()) {
        *status = code;
        *reason = why;
        return std::unique_ptr<KdbxDatabase>();
    };

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return fail(KdbxStatus::Unreadable, file.errorString());
    const QByteArray data = file.readAll();
    file.close();

    Cursor cursor(data);
    if (cursor.u32() != signature1 || cursor.u32() != signature2)
        return fail(KdbxStatus::Corrupt, QStringLiteral("signature"));
    auto impl = std::make_unique<Impl>();
    impl->minor = cursor.u16();
    impl->major = cursor.u16();
    if (!cursor.ok() || (impl->major != 3 && impl->major != 4))
        return fail(KdbxStatus::Unsupported,
                    QStringLiteral("KDBX %1.%2").arg(impl->major).arg(impl->minor));
    const bool v4 = impl->major == 4;

    // -- outer header
    QByteArray masterSeed;
    QByteArray iv;
    QByteArray streamStart;
    QByteArray protectedKey;
    bool sawEnd = false;
    while (!sawEnd) {
        const quint8 id = cursor.u8();
        const quint32 size = v4 ? cursor.u32() : quint32(cursor.u16());
        const QByteArray value = cursor.bytes(size);
        if (!cursor.ok())
            return fail(KdbxStatus::Corrupt, QStringLiteral("header"));
        switch (id) {
        case 0:
            sawEnd = true;
            break;
        case 2:
            impl->cipherId = value;
            break;
        case 3:
            impl->compressed = value.size() == 4 && Cursor(value).u32() != 0;
            break;
        case 4:
            masterSeed = value;
            break;
        case 5:
            impl->kdfId = kdfAes;
            impl->kdfSalt = toBytes(value);
            break;
        case 6:
            impl->aesRounds = Cursor(value).u64();
            break;
        case 7:
            iv = value;
            break;
        case 8:
            protectedKey = value;
            break;
        case 9:
            streamStart = value;
            break;
        case 10:
            impl->innerStreamId = Cursor(value).u32();
            break;
        case 11: {
            QMap<QString, QVariant> params;
            if (!readVariantDictionary(value, &params))
                return fail(KdbxStatus::Corrupt, QStringLiteral("KDF parameters"));
            impl->kdfId = params.value(QStringLiteral("$UUID")).toByteArray();
            impl->kdfSalt = toBytes(params.value(QStringLiteral("S")).toByteArray());
            impl->aesRounds = params.value(QStringLiteral("R")).toULongLong();
            impl->argonParallelism = quint32(params.value(QStringLiteral("P")).toULongLong());
            impl->argonMemory = params.value(QStringLiteral("M")).toULongLong();
            impl->argonIterations = params.value(QStringLiteral("I")).toULongLong();
            impl->argonVersion = params.contains(QStringLiteral("V"))
                ? quint32(params.value(QStringLiteral("V")).toULongLong()) : 0x13;
            break;
        }
        case 12:
            impl->publicCustomData = value;
            break;
        default:
            break;
        }
    }
    const QByteArray headerBytes = data.left(cursor.pos());

    if (masterSeed.size() != 32 || iv.isEmpty() || impl->kdfSalt.empty())
        return fail(KdbxStatus::Corrupt, QStringLiteral("header fields"));
    if (impl->cipherId != cipherAes && impl->cipherId != cipherChaCha && impl->cipherId != cipherTwofish)
        return fail(KdbxStatus::Unsupported, QStringLiteral("cipher"));
    if (!v4 && (impl->cipherId != cipherAes || streamStart.size() != 32))
        return fail(KdbxStatus::Corrupt, QStringLiteral("KDBX 3 header"));

    // -- key
    Bytes composite;
    {
        const Bytes inner = sha256(password.bytes());
        composite = sha256(toArray(inner));
    }
    QString kdfDetail;
    try {
        if (!impl->transform(composite, &kdfDetail))
            return fail(KdbxStatus::Unsupported, kdfDetail);
    } catch (const std::exception &error) {
        return fail(KdbxStatus::Unsupported, QString::fromUtf8(error.what()));
    }

    const Bytes masterKey = sha256(masterSeed, toArray(impl->transformed));

    // -- payload
    QByteArray xmlData;
    QByteArray innerKey = QByteArray();
    if (v4) {
        const Bytes hmacKeyBase = sha512(masterSeed, toArray(impl->transformed), QByteArray(1, '\x01'));
        const QByteArray headerHash = toArray(sha256(headerBytes));
        const QByteArray storedHash = cursor.bytes(32);
        const QByteArray storedMac = cursor.bytes(32);
        if (!cursor.ok())
            return fail(KdbxStatus::Corrupt, QStringLiteral("header hash"));
        if (headerHash != storedHash)
            return fail(KdbxStatus::Corrupt, QStringLiteral("header hash"));
        const Bytes headerKey = sha512(le64(0xFFFFFFFFFFFFFFFFULL), toArray(hmacKeyBase));
        const Bytes headerMac = hmacSha256(Bytes(headerKey.begin(), headerKey.begin() + 64), headerBytes);
        if (toArray(headerMac) != storedMac)
            return fail(KdbxStatus::WrongPassword);

        Bytes cipherText;
        quint64 index = 0;
        for (;;) {
            const QByteArray blockMac = cursor.bytes(32);
            const quint32 size = cursor.u32();
            if (!cursor.ok() || size > quint32(blockSize) * 16)
                return fail(KdbxStatus::Corrupt, QStringLiteral("block"));
            const QByteArray block = cursor.bytes(size);
            if (!cursor.ok())
                return fail(KdbxStatus::Corrupt, QStringLiteral("block"));
            const Bytes blockKey = sha512(le64(index), toArray(hmacKeyBase));
            const Bytes expected = hmacSha256(Bytes(blockKey.begin(), blockKey.begin() + 64), le64(index),
                                              le32(size), block);
            if (toArray(expected) != blockMac)
                return fail(KdbxStatus::Corrupt, QStringLiteral("block mac"));
            if (size == 0)
                break;
            cipherText.insert(cipherText.end(), block.cbegin(), block.cend());
            ++index;
        }

        if (!applyCipher(impl->cipherId, masterKey, toBytes(iv), &cipherText, false))
            return fail(KdbxStatus::Corrupt, QStringLiteral("cipher"));
        QByteArray plain = toArray(cipherText);
        if (impl->compressed) {
            QByteArray inflated;
            if (!gunzip(plain, &inflated))
                return fail(KdbxStatus::Corrupt, QStringLiteral("compression"));
            plain.fill('\0');
            plain = inflated;
        }

        // Inner header: stream cipher and attachments, then the XML.
        Cursor inner(plain);
        for (;;) {
            const quint8 id = inner.u8();
            const quint32 size = inner.u32();
            const QByteArray value = inner.bytes(size);
            if (!inner.ok())
                return fail(KdbxStatus::Corrupt, QStringLiteral("inner header"));
            if (id == 0)
                break;
            if (id == 1)
                impl->innerStreamId = Cursor(value).u32();
            else if (id == 2)
                innerKey = value;
            else if (id == 3)
                impl->binaries.append(value);
        }
        xmlData = plain.mid(inner.pos());
        plain.fill('\0');
    } else {
        // KDBX 3: AES-CBC over [stream start bytes | hashed blocks], gzip inside.
        Bytes payload = toBytes(data.mid(cursor.pos()));
        if (!applyCipher(impl->cipherId, masterKey, toBytes(iv), &payload, false))
            return fail(KdbxStatus::WrongPassword);
        QByteArray plain = toArray(payload);
        if (plain.left(32) != streamStart)
            return fail(KdbxStatus::WrongPassword);

        QByteArray blocks;
        Cursor stream(plain);
        stream.bytes(32);
        quint32 expectedIndex = 0;
        for (;;) {
            const quint32 index = stream.u32();
            const QByteArray hash = stream.bytes(32);
            const quint32 size = stream.u32();
            const QByteArray block = stream.bytes(size);
            if (!stream.ok() || index != expectedIndex)
                return fail(KdbxStatus::Corrupt, QStringLiteral("hashed block"));
            if (size == 0)
                break;
            if (toArray(sha256(block)) != hash)
                return fail(KdbxStatus::Corrupt, QStringLiteral("block hash"));
            blocks.append(block);
            ++expectedIndex;
        }
        plain.fill('\0');
        if (impl->compressed) {
            if (!gunzip(blocks, &xmlData))
                return fail(KdbxStatus::Corrupt, QStringLiteral("compression"));
            blocks.fill('\0');
        } else {
            xmlData = blocks;
        }
        innerKey = protectedKey;
    }

    // -- XML
    impl->xml = parseXml(xmlData);
    xmlData.fill('\0');
    if (!impl->xml || impl->xml->name != QLatin1String("KeePassFile") || !impl->rootGroup())
        return fail(KdbxStatus::Corrupt, QStringLiteral("xml"));

    InnerStream stream;
    if (!stream.init(impl->innerStreamId, innerKey))
        return fail(KdbxStatus::Unsupported, QStringLiteral("inner stream"));
    std::vector<XNode *> protectedValues;
    collectProtected(*impl->xml, &protectedValues);
    for (XNode *value : protectedValues) {
        if (value->text.isEmpty())
            continue;
        const QByteArray raw = QByteArray::fromBase64(value->text.toLatin1());
        value->text = QString::fromUtf8(stream.apply(raw));
    }

    *status = KdbxStatus::Ok;
    return std::unique_ptr<KdbxDatabase>(new KdbxDatabase(std::move(impl)));
}

std::unique_ptr<KdbxDatabase> KdbxDatabase::create(const Secret &password, const QString &name,
                                                   bool legacy) {
    auto impl = std::make_unique<Impl>();
    impl->major = legacy ? 3 : 4;
    impl->minor = legacy ? 1 : 0;
    impl->cipherId = cipherAes;
    impl->kdfId = legacy ? kdfAes : kdfArgon2d;
    impl->aesRounds = legacy ? 60000 : 0;
    impl->kdfSalt = randomBytes(32);
    impl->innerStreamId = legacy ? 2 : 3;

    const Bytes composite = sha256(toArray(sha256(password.bytes())));
    QString detail;
    if (!impl->transform(composite, &detail))
        return nullptr;

    const QString now = timeStamp(impl->binaryTimes());
    impl->xml = std::make_unique<XNode>();
    impl->xml->name = QStringLiteral("KeePassFile");
    XNode *meta = impl->xml->add(QStringLiteral("Meta"));
    meta->add(QStringLiteral("Generator"), QStringLiteral("omapass"));
    meta->add(QStringLiteral("DatabaseName"), name);
    meta->add(QStringLiteral("DatabaseNameChanged"), now);
    meta->add(QStringLiteral("DatabaseDescription"));
    meta->add(QStringLiteral("DatabaseDescriptionChanged"), now);
    meta->add(QStringLiteral("DefaultUserName"));
    meta->add(QStringLiteral("DefaultUserNameChanged"), now);
    meta->add(QStringLiteral("MaintenanceHistoryDays"), QStringLiteral("365"));
    meta->add(QStringLiteral("Color"));
    meta->add(QStringLiteral("MasterKeyChanged"), now);
    meta->add(QStringLiteral("MasterKeyChangeRec"), QStringLiteral("-1"));
    meta->add(QStringLiteral("MasterKeyChangeForce"), QStringLiteral("-1"));
    XNode *protection = meta->add(QStringLiteral("MemoryProtection"));
    protection->add(QStringLiteral("ProtectTitle"), QStringLiteral("False"));
    protection->add(QStringLiteral("ProtectUserName"), QStringLiteral("False"));
    protection->add(QStringLiteral("ProtectPassword"), QStringLiteral("True"));
    protection->add(QStringLiteral("ProtectURL"), QStringLiteral("False"));
    protection->add(QStringLiteral("ProtectNotes"), QStringLiteral("False"));
    meta->add(QStringLiteral("RecycleBinEnabled"), QStringLiteral("True"));
    meta->add(QStringLiteral("RecycleBinUUID"), noUuid);
    meta->add(QStringLiteral("RecycleBinChanged"), now);
    meta->add(QStringLiteral("EntryTemplatesGroup"), noUuid);
    meta->add(QStringLiteral("EntryTemplatesGroupChanged"), now);
    meta->add(QStringLiteral("LastSelectedGroup"), noUuid);
    meta->add(QStringLiteral("LastTopVisibleGroup"), noUuid);
    meta->add(QStringLiteral("HistoryMaxItems"), QStringLiteral("10"));
    meta->add(QStringLiteral("HistoryMaxSize"), QStringLiteral("6291456"));
    meta->add(QStringLiteral("SettingsChanged"), now);
    meta->add(QStringLiteral("CustomData"));

    XNode *root = impl->xml->add(QStringLiteral("Root"));
    root->children.push_back(impl->makeGroup(QStringLiteral("Root")));
    root->add(QStringLiteral("DeletedObjects"));

    return std::unique_ptr<KdbxDatabase>(new KdbxDatabase(std::move(impl)));
}

QString KdbxDatabase::save(const QString &path) {
    Impl &db = *d;
    const bool v4 = db.major == 4;

    try {
        // Fresh randomness for everything that is per-file.
        const Bytes masterSeed = randomBytes(32);
        const Bytes iv = randomBytes(db.cipherId == cipherChaCha ? 12 : 16);
        const QByteArray innerKey = toArray(randomBytes(v4 ? 64 : 32));
        const Bytes streamStart = randomBytes(32);
        const quint32 innerId = v4 ? 3 : 2;

        // -- XML with the protected values encrypted
        std::unique_ptr<XNode> copy = db.xml->clone();
        if (!v4) {
            if (XNode *meta = copy->child(QStringLiteral("Meta")))
                meta->setChildText(QStringLiteral("HeaderHash"), QString());   // set below
        }
        InnerStream stream;
        if (!stream.init(innerId, innerKey))
            return I18n::t(QStringLiteral("keepass.save_error"), QStringLiteral("err"), QStringLiteral("stream"));
        std::vector<XNode *> protectedValues;
        collectProtected(*copy, &protectedValues);
        for (XNode *value : protectedValues) {
            if (value->text.isEmpty())
                continue;
            value->text = QString::fromLatin1(stream.apply(value->text.toUtf8()).toBase64());
        }

        // -- header
        QByteArray header;
        header.append(le32(signature1));
        header.append(le32(signature2));
        header.append(le16(quint16(v4 ? db.minor : 1)));
        header.append(le16(quint16(db.major)));
        putField(&header, 2, db.cipherId, v4);
        putField(&header, 3, le32(db.compressed ? 1 : 0), v4);
        putField(&header, 4, toArray(masterSeed), v4);
        if (v4) {
            QByteArray params;
            params.append(le16(0x0100));
            putVariant(&params, 0x42, QStringLiteral("$UUID"), db.kdfId);
            putVariant(&params, 0x42, QStringLiteral("S"), toArray(db.kdfSalt));
            if (db.kdfId == kdfAes) {
                putVariant(&params, 0x05, QStringLiteral("R"), le64(db.aesRounds));
            } else {
                putVariant(&params, 0x04, QStringLiteral("P"), le32(db.argonParallelism));
                putVariant(&params, 0x05, QStringLiteral("M"), le64(db.argonMemory));
                putVariant(&params, 0x05, QStringLiteral("I"), le64(db.argonIterations));
                putVariant(&params, 0x04, QStringLiteral("V"), le32(db.argonVersion));
            }
            params.append(char(0));
            putField(&header, 11, params, true);
            if (!db.publicCustomData.isEmpty())
                putField(&header, 12, db.publicCustomData, true);
            putField(&header, 7, toArray(iv), true);
        } else {
            putField(&header, 5, toArray(db.kdfSalt), false);
            putField(&header, 6, le64(db.aesRounds), false);
            putField(&header, 7, toArray(iv), false);
            putField(&header, 8, innerKey, false);
            putField(&header, 9, toArray(streamStart), false);
            putField(&header, 10, le32(innerId), false);
        }
        putField(&header, 0, QByteArray::fromHex("0d0a0d0a"), v4);

        if (!v4) {
            if (XNode *meta = copy->child(QStringLiteral("Meta"))) {
                meta->setChildText(QStringLiteral("HeaderHash"),
                                   QString::fromLatin1(toArray(sha256(header)).toBase64()));
            }
        }

        // -- XML bytes
        QByteArray xmlBytes;
        {
            QXmlStreamWriter writer(&xmlBytes);
            writer.setAutoFormatting(false);
            writer.writeStartDocument(QStringLiteral("1.0"), true);
            writeXml(writer, *copy);
            writer.writeEndDocument();
        }
        copy.reset();

        // -- payload
        const Bytes masterKey = sha256(toArray(masterSeed), toArray(db.transformed));
        QByteArray out = header;

        if (v4) {
            QByteArray plain;
            plain.append(char(1));
            plain.append(le32(4));
            plain.append(le32(innerId));
            plain.append(char(2));
            plain.append(le32(quint32(innerKey.size())));
            plain.append(innerKey);
            for (const QByteArray &binary : std::as_const(db.binaries)) {
                plain.append(char(3));
                plain.append(le32(quint32(binary.size())));
                plain.append(binary);
            }
            plain.append(char(0));
            plain.append(le32(0));
            plain.append(xmlBytes);
            xmlBytes.fill('\0');

            if (db.compressed) {
                QByteArray deflated;
                if (!gzip(plain, &deflated))
                    return I18n::t(QStringLiteral("keepass.save_error"), QStringLiteral("err"), QStringLiteral("gzip"));
                plain.fill('\0');
                plain = deflated;
            }
            Bytes cipherText = toBytes(plain);
            plain.fill('\0');
            if (!applyCipher(db.cipherId, masterKey, iv, &cipherText, true))
                return I18n::t(QStringLiteral("keepass.save_error"), QStringLiteral("err"), QStringLiteral("cipher"));

            const Bytes hmacKeyBase = sha512(toArray(masterSeed), toArray(db.transformed), QByteArray(1, '\x01'));
            out.append(toArray(sha256(header)));
            const Bytes headerKey = sha512(le64(0xFFFFFFFFFFFFFFFFULL), toArray(hmacKeyBase));
            out.append(toArray(hmacSha256(Bytes(headerKey.begin(), headerKey.begin() + 64), header)));

            const QByteArray encrypted = toArray(cipherText);
            quint64 index = 0;
            // The data in blocks, then an empty one to mark the end.
            for (qsizetype at = 0;; at += blockSize, ++index) {
                const QByteArray block = encrypted.mid(at, blockSize);
                const Bytes blockKey = sha512(le64(index), toArray(hmacKeyBase));
                out.append(toArray(hmacSha256(Bytes(blockKey.begin(), blockKey.begin() + 64), le64(index),
                                              le32(quint32(block.size())), block)));
                out.append(le32(quint32(block.size())));
                out.append(block);
                if (block.isEmpty())
                    break;
            }
        } else {
            QByteArray body = xmlBytes;
            xmlBytes.fill('\0');
            if (db.compressed) {
                QByteArray deflated;
                if (!gzip(body, &deflated))
                    return I18n::t(QStringLiteral("keepass.save_error"), QStringLiteral("err"), QStringLiteral("gzip"));
                body.fill('\0');
                body = deflated;
            }
            QByteArray plain = toArray(streamStart);
            quint32 index = 0;
            for (qsizetype at = 0; at < body.size(); at += blockSize, ++index) {
                const QByteArray block = body.mid(at, blockSize);
                plain.append(le32(index));
                plain.append(toArray(sha256(block)));
                plain.append(le32(quint32(block.size())));
                plain.append(block);
            }
            plain.append(le32(index));
            plain.append(QByteArray(32, '\0'));
            plain.append(le32(0));

            Bytes cipherText = toBytes(plain);
            plain.fill('\0');
            body.fill('\0');
            if (!applyCipher(db.cipherId, masterKey, iv, &cipherText, true))
                return I18n::t(QStringLiteral("keepass.save_error"), QStringLiteral("err"), QStringLiteral("cipher"));
            out.append(toArray(cipherText));
        }

        QSaveFile file(path);
        if (!file.open(QIODevice::WriteOnly))
            return I18n::t(QStringLiteral("keepass.save_error"), QStringLiteral("err"), file.errorString());
        if (file.write(out) != out.size() || !file.commit())
            return I18n::t(QStringLiteral("keepass.save_error"), QStringLiteral("err"), file.errorString());
        return QString();
    } catch (const std::exception &error) {
        return I18n::t(QStringLiteral("keepass.save_error"), QStringLiteral("err"), QString::fromUtf8(error.what()));
    }
}

// ---------------------------------------------------------------- operations

void KdbxDatabase::list(QStringList *entries, QStringList *groups) const {
    entries->clear();
    groups->clear();
    if (const XNode *root = d->rootGroup())
        d->walk(*root, QString(), entries, groups, nullptr);
}

bool KdbxDatabase::entry(const QString &path, KdbxEntry *out) const {
    const XNode *node = d->findEntry(path);
    if (!node)
        return false;
    *out = Impl::read(*node);
    return true;
}

QList<QPair<QString, KdbxEntry>> KdbxDatabase::allEntries(bool includeRecycled) const {
    QList<QPair<QString, KdbxEntry>> all;
    if (const XNode *root = d->rootGroup()) {
        const XNode *bin = includeRecycled ? nullptr : d->recycleBin(false);
        d->walk(*root, QString(), nullptr, nullptr, &all, bin);
    }
    return all;
}

QString KdbxDatabase::addEntry(const QString &group, const KdbxEntry &data) {
    XNode *target = d->ensureGroup(group);
    if (!target)
        return I18n::t(QStringLiteral("keepass.corrupt"));
    target->children.push_back(d->makeEntry(data));
    d->touch(*target, QStringLiteral("LastModificationTime"));
    return QString();
}

QString KdbxDatabase::editEntry(const QString &oldPath, const QString &group, const KdbxEntry &data) {
    XNode *parent = nullptr;
    XNode *entry = d->findEntry(oldPath, &parent);
    if (!entry)
        return I18n::t(QStringLiteral("keepass.entry_not_found"), QStringLiteral("entry"), oldPath);

    // The state before the edit goes to the entry's history, as KeePass does.
    const KdbxEntry before = Impl::read(*entry);
    const bool changed = before.title != data.title || before.username != data.username
        || before.password.bytes() != data.password.bytes() || before.url != data.url
        || before.notes != data.notes;
    if (changed) {
        std::unique_ptr<XNode> snapshot = entry->clone();
        snapshot->detach(snapshot->child(QStringLiteral("History")));
        XNode *history = entry->child(QStringLiteral("History"));
        if (!history)
            history = entry->add(QStringLiteral("History"));
        history->children.push_back(std::move(snapshot));

        int limit = 10;
        if (const XNode *meta = d->meta()) {
            bool ok = false;
            const int configured = meta->childText(QStringLiteral("HistoryMaxItems")).toInt(&ok);
            if (ok)
                limit = configured;
        }
        if (limit >= 0) {
            while (int(history->children.size()) > limit)
                history->children.erase(history->children.begin());
        }
    }

    d->fill(*entry, data);
    if (changed)
        d->touch(*entry, QStringLiteral("LastModificationTime"));

    XNode *destination = d->ensureGroup(group);
    if (!destination)
        return I18n::t(QStringLiteral("keepass.corrupt"));
    if (destination != parent) {
        std::unique_ptr<XNode> moved = parent->detach(entry);
        destination->children.push_back(std::move(moved));
        d->touch(*destination->children.back(), QStringLiteral("LocationChanged"));
    }
    return QString();
}

QString KdbxDatabase::removeEntry(const QString &path) {
    XNode *parent = nullptr;
    XNode *entry = d->findEntry(path, &parent);
    if (!entry)
        return I18n::t(QStringLiteral("keepass.entry_not_found"), QStringLiteral("entry"), path);

    const XNode *meta = d->meta();
    const bool binEnabled = meta
        && meta->childText(QStringLiteral("RecycleBinEnabled")).compare(QLatin1String("True"), Qt::CaseInsensitive) == 0;
    if (binEnabled && !d->insideBin(entry)) {
        XNode *bin = d->recycleBin(true);
        std::unique_ptr<XNode> moved = parent->detach(entry);
        d->touch(*moved, QStringLiteral("LocationChanged"));
        bin->children.push_back(std::move(moved));
        return QString();
    }

    const QString uuid = entry->childText(QStringLiteral("UUID"));
    parent->detach(entry);
    d->recordDeleted(uuid);
    return QString();
}

QString KdbxDatabase::renameGroup(const QString &oldPath, const QString &newName) {
    XNode *group = d->findGroup(oldPath);
    if (!group || group == d->rootGroup())
        return I18n::t(QStringLiteral("keepass.group_not_found"), QStringLiteral("group"), oldPath);

    const XNode *parent = d->parentOf(group);
    if (parent) {
        for (const XNode *sibling : parent->childrenNamed(QStringLiteral("Group"))) {
            if (sibling != group && sibling->childText(QStringLiteral("Name")) == newName)
                return I18n::t(QStringLiteral("keepass.group_exists"), QStringLiteral("group"), newName);
        }
    }
    group->setChildText(QStringLiteral("Name"), newName);
    d->touch(*group, QStringLiteral("LastModificationTime"));
    return QString();
}

QString KdbxDatabase::removeGroup(const QString &path) {
    XNode *group = d->findGroup(path);
    if (!group || group == d->rootGroup())
        return I18n::t(QStringLiteral("keepass.group_not_found"), QStringLiteral("group"), path);
    XNode *parent = d->parentOf(group);
    if (!parent)
        return I18n::t(QStringLiteral("keepass.corrupt"));

    const XNode *meta = d->meta();
    const bool binEnabled = meta
        && meta->childText(QStringLiteral("RecycleBinEnabled")).compare(QLatin1String("True"), Qt::CaseInsensitive) == 0;
    XNode *bin = binEnabled ? d->recycleBin(false) : nullptr;
    if (binEnabled && group != bin && !d->insideBin(group)) {
        bin = d->recycleBin(true);
        std::unique_ptr<XNode> moved = parent->detach(group);
        d->touch(*moved, QStringLiteral("LocationChanged"));
        bin->children.insert(bin->children.begin(), std::move(moved));
        return QString();
    }

    const QString uuid = group->childText(QStringLiteral("UUID"));
    parent->detach(group);
    d->recordDeleted(uuid);
    return QString();
}
