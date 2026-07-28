#!/bin/sh

if command -v update-alternatives >/dev/null 2>&1; then
    update-alternatives --remove fd0-desktop /opt/fd0/fd0-desktop >/dev/null 2>&1 || true
else
    rm -f /usr/bin/fd0-desktop
fi

profile=/etc/apparmor.d/fd0-desktop
if [ -f "$profile" ]; then
    if command -v apparmor_status >/dev/null 2>&1 \
        && apparmor_status --enabled >/dev/null 2>&1 \
        && command -v apparmor_parser >/dev/null 2>&1; then
        apparmor_parser --remove "$profile" >/dev/null 2>&1 || true
    fi
    rm -f "$profile"
fi

# FPM can leave empty directories from unpacked native modules.
find /opt/fd0 -depth -type d -empty -delete 2>/dev/null || true
