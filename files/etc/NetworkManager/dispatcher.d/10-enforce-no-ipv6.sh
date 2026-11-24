#!/bin/sh
INTERFACE="$1"
ACTION="$2"

if [ "$ACTION" = "up" ] && [ -n "$CONNECTION_UUID" ]; then
    case "$INTERFACE" in
        lo|png*) exit 0 ;;
    esac
    CURRENT_IPV6="$(/usr/bin/nmcli -g ipv6.method connection show uuid "$CONNECTION_UUID" 2>/dev/null)"
    if [ "$CURRENT_IPV6" != "disabled" ]; then
        /usr/bin/nmcli connection modify uuid "$CONNECTION_UUID" ipv6.method disabled
        /usr/bin/nmcli device reapply "$INTERFACE" >/dev/null 2>&1 || true
    fi
fi
