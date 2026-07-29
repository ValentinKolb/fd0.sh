# Chrome Web Store privacy answers

## Single purpose

Provide origin-bound password-manager autofill, password generation, TOTP fill,
and explicit login save/update actions by connecting Chrome to the encrypted
fd0 vault on the same device.

## Permission justifications

### `nativeMessaging`

Connects Chrome to the local `fd0-browser-host`. The host exposes only
origin-bound password-manager operations and accepts requests only from the
exact fd0 extension origin.

### `activeTab`

Allows the user to open fd0 explicitly from the toolbar for the active HTTPS
login page.

### `alarms`

Expires a short-lived login candidate held after a form submission. The
candidate is deleted after at most 60 seconds.

### `scripting`

Finds the eligible frame selected by the toolbar action and reconnects the
packaged fd0 content script after an extension update. It does not fetch or
execute remote code.

### `storage`

Uses `chrome.storage.session` only for a short-lived login candidate, scoped to
one tab, frame, and HTTPS origin. Passwords, TOTP seeds, and codes are never
written to Chrome Local or Sync storage.

### `https://*/*`

Detects supported login fields and places the fd0 control beside them on HTTPS
pages. The extension does not run on unencrypted HTTP pages and does not
collect browsing history.

## Remote code

No. All executable code is contained in the submitted Manifest V3 package.

## User data declarations

The extension handles:

- Authentication information: usernames, passwords, and one-time passwords
  selected or entered by the user.
- Website content: the current HTTPS origin and visible login form fields
  required to provide autofill and explicit save/update actions.

The developer does not remotely collect this data. It is processed on the
device between Chrome and the local fd0 native host. If the user separately
enables fd0 sync, the fd0 client sends encrypted ciphertext to the configured
hosted or self-hosted sync server.

The data is not sold, used for advertising or credit decisions, or made
available for human reading. Its use complies with the Chrome Web Store User
Data Policy, including the Limited Use requirements.
