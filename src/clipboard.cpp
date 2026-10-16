#include "clipboard.h"

#include "process.h"

#include <QClipboard>
#include <QGuiApplication>
#include <QMimeData>
#include <QStandardPaths>
#include <QTimer>

namespace {

// Marks the content as sensitive, so clipboard managers keep it out of
// their on-disk history — fixing the leak at the source rather than
// deleting the password after it was already written down. cliphist,
// Klipper and GPaste honour it; it is the same mime type `wl-copy`
// advertises behind `--sensitive`.
const auto sensitiveHint = QStringLiteral("x-kde-passwordManagerHint");

// Whether to hand the clipboard to `wl-copy` instead of writing it through
// Qt. Worth it on Wayland, and only there: `wl-copy --clear` drops the
// selection through wlr-data-control, which does not need the window to be
// focused — and the clear lands `clearSecs` after the copy, by which time
// the user is in the window they were pasting into. Qt writes through
// wl_data_device, which a compositor only accepts with a serial from a
// recent input event, so the clear would be the part that silently stops
// working.
//
// Everywhere else Qt's own clipboard is both available and enough: under
// X11 the application owns the selection outright and can drop it whenever
// it likes, with no helper binary in the picture.
bool useWlCopy() {
    static const bool wanted = []() {
        if (!QGuiApplication::platformName().startsWith(QStringLiteral("wayland")))
            return false;
        return !QStandardPaths::findExecutable(QStringLiteral("wl-copy")).isEmpty();
    }();
    return wanted;
}

// The password the timer is waiting to clear, so quitting can clear it too:
// the timer dies with the process, and a clipboard served by `wl-copy` does
// not.
Secret &pending() {
    static Secret secret;
    return secret;
}

void clearClipboard() {
    if (useWlCopy()) {
        // `--clear` tells the compositor to drop the selection outright.
        // Writing an empty string instead leaves some compositors holding
        // the old value, since they do not treat it as a new selection.
        runProcess(QStringLiteral("wl-copy"), {QStringLiteral("--clear")});
        return;
    }

    if (QClipboard *clipboard = QGuiApplication::clipboard())
        clipboard->clear();
}

// Fallback for wl-clipboard < 2.2.1, or a clipboard manager that ignores the
// sensitive hint: deletes the password from cliphist's persisted history.
// The entries are found by id, never by handing the password to cliphist —
// an argument would put it in every process listing, and `delete-query`
// would take along any other entry that merely contains it.
void deleteFromHistory(const Secret &password) {
    if (QStandardPaths::findExecutable(QStringLiteral("cliphist")).isEmpty())
        return;

    ProcResult listed = runProcess(QStringLiteral("cliphist"), {QStringLiteral("list")});
    if (!listed.success)
        return;

    QString secret = password.toString();
    QByteArray doomed;
    const QStringList lines = listed.out.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    for (const QString &line : lines) {
        const int tab = line.indexOf(QLatin1Char('\t'));
        if (tab <= 0 || !Clipboard::previewMayBe(line.mid(tab + 1), secret))
            continue;

        // The preview only narrows it down; the entry itself settles it.
        ProcResult decoded = runProcess(QStringLiteral("cliphist"), {QStringLiteral("decode")},
                                        line.toUtf8());
        const bool same = decoded.success && decoded.out == secret;
        decoded.out.fill(QChar(0));
        if (same)
            doomed += line.toUtf8() + '\n';
    }
    listed.out.fill(QChar(0));
    secret.fill(QChar(0));

    if (!doomed.isEmpty())
        runProcess(QStringLiteral("cliphist"), {QStringLiteral("delete")}, doomed);
    doomed.fill('\0');
}

}

namespace Clipboard {

bool previewMayBe(const QString &preview, const QString &secret) {
    // cliphist shows whitespace collapsed, and a long entry cut short with
    // an ellipsis after `-preview-width` (100) characters.
    const QString flat = secret.simplified();
    if (flat.isEmpty())
        return false;
    if (preview == flat)
        return true;

    const QString ellipsis = QStringLiteral("\u2026");
    if (!preview.endsWith(ellipsis) || preview.size() <= ellipsis.size())
        return false;
    return flat.startsWith(preview.chopped(ellipsis.size()));
}

bool copy(const QString &text) {
    if (useWlCopy()) {
        const ProcResult result = runProcess(QStringLiteral("wl-copy"),
                                             {QStringLiteral("--sensitive")}, text.toUtf8());
        return result.started && result.success;
    }

    QClipboard *clipboard = QGuiApplication::clipboard();
    if (!clipboard)
        return false;

    // setMimeData rather than setText: the hint rides along as a second
    // mime type next to the plain text, which is what --sensitive does on
    // the other path. The clipboard takes ownership of the QMimeData.
    auto *mime = new QMimeData;
    mime->setText(text);
    mime->setData(sensitiveHint, QByteArrayLiteral("secret"));
    clipboard->setMimeData(mime);

    // Qt reports no outcome here, and reading the clipboard back would
    // answer from the copy Qt keeps in this process rather than from the
    // display server, so it would say yes either way.
    return true;
}

void scheduleClear(const Secret &password) {
    pending() = password;
    const Secret copyOfPassword = password;
    QTimer::singleShot(clearSecs * 1000, [copyOfPassword]() {
        clearClipboard();
        if (useWlCopy())
            deleteFromHistory(copyOfPassword);
        pending().clear();
    });
}

void clearPending() {
    if (pending().isEmpty())
        return;
    clearClipboard();
    if (useWlCopy())
        deleteFromHistory(pending());
    pending().clear();
}

}
