# fd0 browser autofill preview

This directory contains the read-only Google Chrome preview for macOS and
Linux. On a top-level HTTPS login page it opens an isolated fd0 picker when a
matching username or password field receives focus. It fills only the login
selected by the user. It does not submit forms, write vault data, or store
credentials in Chrome.

The preview is not part of the fd0 installer and is not published in a browser
store.

## Build and register

```sh
cd browser
bun install --frozen-lockfile
bun run typecheck
bun test
bun run build

cd ..
go build -o .build/browser/fd0 ./cmd/fd0
go build -o .build/browser/fd0-browser-host ./cmd/fd0-browser-host
.build/browser/fd0 browser enable --host .build/browser/fd0-browser-host
```

Open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**,
and select `browser/dist`. Chrome must show extension id
`flkmmllfacmjnhjgdfliahdkhfjmdoec`. A different id cannot use this development
Native Messaging registration.

## Fill a login

Unlock fd0, reload an HTTPS login page after changing the unpacked extension,
and focus its username or password field. Choose a login with the mouse or
keyboard. The small fd0 field button reopens the picker; the toolbar action is
also available as a fallback. Chrome grants the development extension access
to HTTPS pages because password-manager behavior cannot work through
`activeTab` alone.

The content script sends only the current HTTPS origin to the local Native
Messaging host when a login field is used. Matching titles and usernames return
first. The password is requested only after the user chooses an item, and fd0
checks the origin again before filling the same browser document.

If the picker does not appear, confirm that fd0 is unlocked, the page is HTTPS,
and the extension id is the one above. Reload the page after every extension
build. The preview deliberately ignores embedded frames and signup fields
marked `new-password`.

## Remove the registration

Remove only the development Native Messaging registration with:

```sh
.build/browser/fd0 browser disable
```

Remove the unpacked extension separately in `chrome://extensions`. Neither
action removes the fd0 vault.
