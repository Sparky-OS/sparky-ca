#!/bin/sh
# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Daniel Campos Ramos
#
# Add the Ed521 provider to OpenSSL's system configuration, or take it out.
#
# Debian's openssl package ships /usr/lib/ssl/openssl.cnf, the file libcrypto
# reads, as a link to its conffile /etc/ssl/openssl.cnf, and offers no drop-in
# directory.  "enable" diverts that link (dpkg-divert, so openssl upgrades
# keep updating Debian's own link under the diverted name) and points the
# path at openssl.cnf in this package, which includes /etc/ssl/openssl.cnf
# first and then adds the provider.  It does so only after the new
# configuration has been tried: the same providers as before plus ed521,
# the default provider among them, no FIPS provider, and ITI's v7 root
# verifying.  "disable" puts Debian's link back exactly as it was and keeps
# it so across upgrades; "enable" undoes that choice.  The package scripts
# use "configure" and "unconfigure", which respect it.
set -eu

PACKAGE=openssl-provider-ed521
LINK=/usr/lib/ssl/openssl.cnf
DIVERTED=/usr/lib/ssl/openssl.cnf.distrib
DEBIAN_CONF=/etc/ssl/openssl.cnf
SHARE=/usr/share/openssl-provider-ed521
WRAPPER=$SHARE/openssl.cnf
V7=$SHARE/ICP-Brasilv7.pem
# Debian's own openssl, never another one found first on PATH (conda, miniforge)
OPENSSL=/usr/bin/openssl
CHOICE=/var/lib/$PACKAGE/disabled
REFUSED=0

unset OPENSSL_CONF OPENSSL_MODULES OPENSSL_CONF_INCLUDE

say() {
	echo "$PACKAGE: $*" >&2
}

providers() {
	OPENSSL_CONF=$1 "$OPENSSL" list -providers 2>/dev/null | awk '
		/^  [^ ]/ { name = $1 }
		/^    status: active$/ { print name }' | sort | tr '\n' ' '
}

ours() {
	[ "$(dpkg-divert --listpackage "$LINK")" = "$PACKAGE" ]
}

disable() {
	if ours; then
		if [ -L "$DIVERTED" ] || [ -e "$DIVERTED" ]; then
			mv -T "$DIVERTED" "$LINK"
		else
			ln -s "$DEBIAN_CONF" "$LINK.$PACKAGE"
			mv -T "$LINK.$PACKAGE" "$LINK"
		fi
		dpkg-divert --package "$PACKAGE" --remove --no-rename --divert "$DIVERTED" "$LINK" >/dev/null
		say "OpenSSL's system configuration is Debian's again."
	elif [ "$(readlink "$LINK" 2>/dev/null)" = "$WRAPPER" ]; then
		ln -s "$DEBIAN_CONF" "$LINK.$PACKAGE"
		mv -T "$LINK.$PACKAGE" "$LINK"
	fi
}

refuse() {
	say "$*"
	say "Ed521 is not added to OpenSSL's system configuration; see /usr/share/doc/$PACKAGE/README.Debian."
	exit "$REFUSED"
}

enable() {
	if ours; then
		[ "$(readlink "$LINK" 2>/dev/null)" = "$WRAPPER" ] && return 0
		disable
	fi
	owner=$(dpkg-divert --listpackage "$LINK")
	[ -z "$owner" ] || refuse "$LINK is already diverted by $owner."
	[ -d /usr/lib/ssl ] && [ ! -L /usr/lib/ssl ] || refuse "/usr/lib/ssl is not a directory."
	[ "$(readlink "$LINK" 2>/dev/null)" = "$DEBIAN_CONF" ] || refuse "$LINK is not Debian's link to $DEBIAN_CONF."
	before=$(providers "$DEBIAN_CONF")
	after=$(providers "$WRAPPER")
	expected=$(printf '%s\n' $before ed521 | sort -u | tr '\n' ' ')
	case " $before " in
	*" fips "*) refuse "The FIPS provider is active; its configuration stays as you made it." ;;
	esac
	case " $before " in
	*" default "*) ;;
	*) refuse "The default provider is not active in $DEBIAN_CONF." ;;
	esac
	[ "$after" = "$expected" ] || refuse "The providers would change from '$before' to '$after'."
	echo | OPENSSL_CONF=$WRAPPER "$OPENSSL" dgst -sha256 >/dev/null 2>&1 || refuse "SHA-256 fails with the new configuration."
	OPENSSL_CONF=$WRAPPER "$OPENSSL" verify -check_ss_sig -CAfile "$V7" "$V7" >/dev/null 2>&1 \
		|| refuse "ITI's v7 root does not verify with the new configuration."
	dpkg-divert --package "$PACKAGE" --add --no-rename --divert "$DIVERTED" "$LINK" >/dev/null
	cp -a "$LINK" "$DIVERTED"
	ln -s "$WRAPPER" "$LINK.$PACKAGE"
	mv -T "$LINK.$PACKAGE" "$LINK"
	if [ "$(providers "$LINK")" != "$expected" ]; then
		disable
		refuse "The system configuration did not load the provider."
	fi
	say "OpenSSL verifies Ed521 (ICP-Brasil v7) system-wide."
}

status() {
	if ours && [ "$(readlink "$LINK" 2>/dev/null)" = "$WRAPPER" ]; then
		echo "enabled: $(providers "$LINK")"
	else
		echo "disabled: $(providers "$LINK")"
		return 1
	fi
}

case "${1:-}" in
enable)
	rm -f "$CHOICE"
	REFUSED=1
	enable
	;;
disable)
	mkdir -p "${CHOICE%/*}"
	: >"$CHOICE"
	disable
	;;
configure)
	if [ -e "$CHOICE" ]; then
		say "Switched off by the administrator; \"$0 enable\" switches it on."
	else
		enable
	fi
	;;
unconfigure) disable ;;
status) status ;;
*) echo "usage: $0 enable|disable|status" >&2; exit 2 ;;
esac
