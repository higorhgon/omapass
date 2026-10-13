#pragma once

#include <QString>
#include <QStringList>
#include <QVector>

// Imports a KeePassXC database (.kdbx) into a pass store, encrypting every
// entry to the given GPG recipients. Runs headless, from the command line.
//
// The database is read in-process and no export file is written: the
// passwords only ever live in memory, on their way to `pass insert`.
namespace Kdbx2Pass {

// Returns an empty string on success, or the error to print.
QString run(const QString &dbPath, const QStringList &recipients);

// Exposed for testing.
QString sanitizeTitle(const QString &title);

}
