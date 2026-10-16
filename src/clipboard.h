#pragma once

#include <QString>

#include "secret.h"

namespace Clipboard {

// Seconds a copied password stays on the clipboard. Drives both the timer
// and the countdown the interface shows.
const int clearSecs = 10;

bool copy(const QString &text);

// Whether a line of `cliphist list` (the part after the id) could be this
// secret. Only a pre-filter: the entry is decoded and compared before it is
// deleted.
bool previewMayBe(const QString &preview, const QString &secret);

// Wipes the clipboard once `clearSecs` have passed, on the event loop rather
// than a thread.
void scheduleClear(const Secret &password);

// Clears now what scheduleClear is still waiting on, if anything. Called on
// the way out, since the timer does not outlive the application.
void clearPending();

}
