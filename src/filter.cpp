#include "filter.h"

#include <algorithm>

QList<int> filterIndexes(const QStringList &haystacks, const QString &query) {
    const QStringList terms = query.toLower().split(QLatin1Char(' '), Qt::SkipEmptyParts);

    QList<int> matches;
    for (int i = 0; i < haystacks.size(); ++i) {
        const QString lower = haystacks.at(i).toLower();
        const bool matchesAll = std::all_of(terms.cbegin(), terms.cend(),
                                            [&lower](const QString &term) {
            return lower.contains(term);
        });
        if (matchesAll)
            matches.append(i);
    }
    return matches;
}

QStringList filterItems(const QStringList &items, const QString &query) {
    QStringList matches;
    const QList<int> indexes = filterIndexes(items, query);
    for (int index : indexes)
        matches.append(items.at(index));
    return matches;
}
