#pragma once

#include <QList>
#include <QString>
#include <QStringList>

// Keeps the items that contain every space-separated term of `query`, in any
// order, case-insensitively — the search both the database list and the entry
// list use.
QStringList filterItems(const QStringList &items, const QString &query);

// The same match over `haystacks`, answering with the positions that hold
// every term. Lets a row be searched by more than the text it is listed by
// (its group, login, URL…) while the caller keeps its own parallel data.
QList<int> filterIndexes(const QStringList &haystacks, const QString &query);
