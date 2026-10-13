#pragma once

#include <QAbstractListModel>
#include <QVariantList>
#include <QVariantMap>

// The rows of the entry list, as the list view reads them. A model of its own
// rather than a property that is replaced whole: when a login or URL arrives
// late (KeePassXC hands them over one entry at a time), only that row changes
// and the cursor stays where the user left it.
class EntryRowsModel : public QAbstractListModel {
    Q_OBJECT
    // For each column key, the longest value among the rows: what a column
    // sized to its content needs room for.
    Q_PROPERTY(QVariantMap longest READ longest NOTIFY longestChanged)

public:
    using QAbstractListModel::QAbstractListModel;

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    void setRows(const QVariantList &rows);
    void replaceRow(int index, const QVariantMap &row);
    QString pathAt(int index) const;
    QVariantMap longest() const { return m_longest; }

signals:
    void longestChanged();

private:
    void updateLongest();

    QVariantList m_rows;
    QVariantMap m_longest;
};
