#include "entryrowsmodel.h"

int EntryRowsModel::rowCount(const QModelIndex &parent) const {
    return parent.isValid() ? 0 : m_rows.size();
}

QVariant EntryRowsModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() >= m_rows.size() || role != Qt::UserRole + 1)
        return QVariant();
    return m_rows.at(index.row());
}

// The delegate reads `modelData`, as it does for the plain arrays the
// database list passes.
QHash<int, QByteArray> EntryRowsModel::roleNames() const {
    return {{Qt::UserRole + 1, "modelData"}};
}

void EntryRowsModel::setRows(const QVariantList &rows) {
    beginResetModel();
    m_rows = rows;
    endResetModel();
    updateLongest();
}

void EntryRowsModel::replaceRow(int index, const QVariantMap &row) {
    if (index < 0 || index >= m_rows.size())
        return;
    m_rows[index] = row;
    const QModelIndex at = createIndex(index, 0);
    emit dataChanged(at, at);
    updateLongest();
}

void EntryRowsModel::updateLongest() {
    QVariantMap longest;
    for (const QVariant &row : std::as_const(m_rows)) {
        const QVariantMap map = row.toMap();
        for (auto it = map.cbegin(); it != map.cend(); ++it) {
            const QString text = it.value().toString();
            if (text.size() > longest.value(it.key()).toString().size())
                longest.insert(it.key(), text);
        }
    }
    if (longest == m_longest)
        return;
    m_longest = longest;
    emit longestChanged();
}

QString EntryRowsModel::pathAt(int index) const {
    if (index < 0 || index >= m_rows.size())
        return QString();
    return m_rows.at(index).toMap().value(QStringLiteral("path")).toString();
}
