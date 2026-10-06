#!/bin/sh
# Installs peerfectly on a Linux machine with systemd, from the unpacked archive this
# script came in:
#
#   sudo ./install.sh               install, or upgrade the copy that is there
#   sudo ./install.sh --uninstall   remove the programs and the service
#
# Everything the daemon needs is checked before anything is written, and every
# missing piece is named, not only the first: a person fixing one thing at a
# time, one run at a time, gives up before the third.
#
# Uninstalling keeps /var/lib/peerfectly. A network is an identity, and removing
# programs is not a decision about any of them.
#
# POSIX sh: Debian's /bin/sh is dash, and a server may have no bash.

set -eu

# Filled in by package.sh, from the programs it packed.
VERSION='@VERSION@'
GLIBC_FLOOR='@GLIBC_FLOOR@'

BIN=/usr/local/bin
UNIT=peerfectlyd.service
UNIT_DIR=/etc/systemd/system
STATE=/var/lib/peerfectly
SOCKET=/run/peerfectly/control.sock

HERE=$(cd "$(dirname "$0")" && pwd)

say() { printf '%s\n' "$*"; }

# What is wrong, one finding per line, gathered before any of it is reported.
PROBLEMS=''
problem() {
    PROBLEMS="${PROBLEMS}  - $*
"
}

# Who provides a library, on the two families this is built for. Debian 13 and
# Ubuntu 24.04 renamed most of them with `t64`; Debian 12 and Ubuntu 22.04 did
# not. The soname, which is what the loader asks for, is the same everywhere.
debian_names() {
    case "$1" in
        libtss2-esys.so.0) echo 'libtss2-esys-3.0.2-0t64 libtss2-esys-3.0.2-0' ;;
        libtss2-tctildr.so.0) echo 'libtss2-tctildr0t64 libtss2-tctildr0' ;;
        libtss2-mu.so.0) echo 'libtss2-mu-4.0.1-0t64 libtss2-mu0' ;;
        libtss2-sys.so.1) echo 'libtss2-sys1t64 libtss2-sys1' ;;
        libtss2-tcti-device.so.0) echo 'libtss2-tcti-device0t64 libtss2-tcti-device0' ;;
        libcrypto.so.3) echo 'libssl3t64 libssl3' ;;
        *) echo '' ;;
    esac
}
fedora_name() {
    case "$1" in
        libtss2-*) echo 'tpm2-tss' ;;
        libcrypto.so.3) echo 'openssl-libs' ;;
        *) echo '' ;;
    esac
}

# Whether this is a release from before the `t64` rename: Debian 12 or older,
# Ubuntu 22.04 or older.
before_t64() {
    [ -r /etc/os-release ] || return 1
    # shellcheck disable=SC1091
    release_id=$(. /etc/os-release && echo "${ID:-}")
    # shellcheck disable=SC1091
    release=$(. /etc/os-release && echo "${VERSION_ID:-}")
    major=${release%%.*}
    case "$release_id" in
        debian) [ -n "$major" ] && [ "$major" -le 12 ] 2>/dev/null ;;
        ubuntu) [ -n "$major" ] && [ "$major" -le 22 ] 2>/dev/null ;;
        *) return 1 ;;
    esac
}

# The packages to ask for, gathered as libraries are found missing.
DEBIAN_WANTED=''
FEDORA_WANTED=''
wants() {
    debian=$(debian_names "$1")
    fedora=$(fedora_name "$1")
    if [ -z "$debian" ]; then
        problem "$1 is missing"
        return
    fi
    # On Debian or Ubuntu, the name this release actually has.
    chosen=''
    if command -v apt-cache >/dev/null 2>&1; then
        for name in $debian; do
            if apt-cache show "$name" >/dev/null 2>&1; then
                chosen=$name
                break
            fi
        done
    fi
    first=${debian%% *}
    second=${debian#* }
    # With no package lists to ask, the release says which spelling it uses.
    if [ -z "$chosen" ]; then
        if before_t64; then chosen=$second; else chosen=$first; fi
    fi
    problem "$1 is missing: on Debian/Ubuntu it is in $first ($second on Debian 12 and Ubuntu 22.04), on Fedora in $fedora"
    case " $DEBIAN_WANTED " in *" $chosen "*) ;; *) DEBIAN_WANTED="$DEBIAN_WANTED $chosen" ;; esac
    case " $FEDORA_WANTED " in *" $fedora "*) ;; *) FEDORA_WANTED="$FEDORA_WANTED $fedora" ;; esac
}

# The libraries `ldd` cannot find for one program, and whether its C library is
# too old. `ldd` rather than a list of packages: package names change between
# releases, and the soname is what the loader actually wants.
OLD_LIBC=''
look_at() {
    if ! found=$(ldd "$HERE/$1" 2>&1); then
        case "$found" in
            *'not a dynamic executable'*)
                problem "$1 cannot be loaded here: this machine's C library is not glibc"
                return
                ;;
        esac
    fi
    case "$found" in
        *"version \`GLIBC_"*'not found'*) OLD_LIBC=yes ;;
    esac
    for missing in $(printf '%s\n' "$found" | awk '/=> not found/ { print $1 }'); do
        case " $MISSING " in *" $missing "*) ;; *) MISSING="$MISSING $missing" ;; esac
    done
}

# Every check, before anything is written.
check() {
    if [ "$(id -u)" -ne 0 ]; then
        problem "this needs root: run it again with sudo"
    fi

    for file in peerfectlyd peerfectly "$UNIT"; do
        [ -f "$HERE/$file" ] || problem "$file is not beside this script: run it from the unpacked archive"
    done
    if [ -f "$HERE/SHA256SUMS" ]; then
        if ! (cd "$HERE" && sha256sum --quiet -c SHA256SUMS >/dev/null 2>&1); then
            problem "the files beside this script do not match SHA256SUMS: unpack the archive again"
        fi
    else
        problem "SHA256SUMS is not beside this script: run it from the unpacked archive"
    fi

    if [ ! -d /run/systemd/system ]; then
        problem "this machine is not running systemd, and the daemon is installed as a systemd service; the programs can still be run by hand"
    fi

    machine=$(uname -m)
    if [ "$machine" != x86_64 ]; then
        problem "these programs are built for x86_64, and this machine is $machine"
    fi

    MISSING=''
    if [ -f "$HERE/peerfectlyd" ] && [ -f "$HERE/peerfectly" ] && [ "$machine" = x86_64 ]; then
        if command -v ldd >/dev/null 2>&1; then
            look_at peerfectlyd
            look_at peerfectly
        else
            problem "ldd is not here, so the libraries the programs need cannot be checked"
        fi
    fi

    # The TPM is reached through a plugin the TSS loads only when it is asked,
    # so `ldd` never lists it. Without it a machine that has a TPM is answered as
    # if it had none, and signing keys become passphrase-sealed files: weaker,
    # and silently so.
    if [ -e /dev/tpmrm0 ] && ! tpm_plugin_present; then
        case " $MISSING " in *' libtss2-tcti-device.so.0 '*) ;; *) MISSING="$MISSING libtss2-tcti-device.so.0" ;; esac
    fi
    for library in $MISSING; do
        wants "$library"
    done

    if [ -n "$OLD_LIBC" ]; then
        problem "this machine's C library is older than glibc $GLIBC_FLOOR, which the programs were built against: Debian 12, Ubuntu 22.04, RHEL 9 and Fedora 35, and later releases, are new enough"
    fi

    if [ ! -x /usr/sbin/nft ] && [ ! -x /sbin/nft ]; then
        problem "nft is missing, and without it no network comes up: it is in nftables, on Debian/Ubuntu and on Fedora"
        DEBIAN_WANTED="$DEBIAN_WANTED nftables"
        FEDORA_WANTED="$FEDORA_WANTED nftables"
    fi

    if [ ! -c /dev/net/tun ]; then
        problem "/dev/net/tun is not here, and it is the device every network's packets go through: load the kernel module with 'modprobe tun'"
    fi
}

tpm_plugin_present() {
    if command -v ldconfig >/dev/null 2>&1; then
        ldconfig -p 2>/dev/null | grep -q 'libtss2-tcti-device\.so\.0 '
    elif [ -x /sbin/ldconfig ]; then
        /sbin/ldconfig -p 2>/dev/null | grep -q 'libtss2-tcti-device\.so\.0 '
    else
        for directory in /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu /lib64 /usr/lib64; do
            [ -e "$directory/libtss2-tcti-device.so.0" ] && return 0
        done
        return 1
    fi
}

refuse_if_anything_is_wrong() {
    if [ -z "$PROBLEMS" ]; then
        return
    fi
    say "peerfectly $VERSION was not installed, and nothing was written:"
    say ''
    printf '%s' "$PROBLEMS"
    if [ -n "$DEBIAN_WANTED$FEDORA_WANTED" ]; then
        say ''
        if command -v apt-get >/dev/null 2>&1; then
            say "To install what is missing:  sudo apt-get install$DEBIAN_WANTED"
        elif command -v dnf >/dev/null 2>&1; then
            say "To install what is missing:  sudo dnf install$FEDORA_WANTED"
        else
            say "On Debian/Ubuntu:  sudo apt-get install$DEBIAN_WANTED"
            say "On Fedora:         sudo dnf install$FEDORA_WANTED"
        fi
    fi
    exit 1
}

install_it() {
    check
    refuse_if_anything_is_wrong

    upgrading=no
    if systemctl is-active --quiet "$UNIT"; then
        upgrading=yes
    fi

    # Each program goes in under a temporary name and is renamed over the old
    # one. A running daemon keeps its old file until it stops; the next start
    # runs the new one, and there is never a moment with half a program.
    for program in peerfectlyd peerfectly; do
        install -o root -g root -m 0755 "$HERE/$program" "$BIN/.$program.new"
        mv -f "$BIN/.$program.new" "$BIN/$program"
    done
    install -o root -g root -m 0644 "$HERE/$UNIT" "$UNIT_DIR/$UNIT"

    systemctl daemon-reload
    systemctl enable --quiet "$UNIT"
    if [ "$upgrading" = yes ]; then
        say "Upgrading: the service is restarted, and the networks that were up come back up."
        systemctl restart "$UNIT"
    else
        systemctl start "$UNIT"
    fi

    # The daemon answers once its control socket exists; a few seconds at most.
    waited=0
    while [ ! -S "$SOCKET" ] && [ "$waited" -lt 15 ]; do
        sleep 1
        waited=$((waited + 1))
    done
    if ! systemctl is-active --quiet "$UNIT"; then
        say ''
        say "The programs are installed, and the service did not stay up. What it said:"
        journalctl -u "$UNIT" -n 20 --no-pager || true
        exit 1
    fi

    say ''
    say "peerfectly $VERSION is installed: $BIN/peerfectlyd and $BIN/peerfectly, and the service starts at boot."
    say ''
    "$BIN/peerfectly" status || true
}

uninstall_it() {
    if [ "$(id -u)" -ne 0 ]; then
        say "this needs root: run it again with sudo"
        exit 1
    fi

    if [ -d /run/systemd/system ]; then
        # The daemon takes every network down before it exits.
        systemctl disable --now --quiet "$UNIT" 2>/dev/null || true
    fi
    rm -f "$UNIT_DIR/$UNIT" "$BIN/peerfectlyd" "$BIN/peerfectly"
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload
    fi

    say "peerfectly is uninstalled: the service and the programs are gone."
    if [ -d "$STATE" ]; then
        say ''
        say "$STATE is kept, with the networks this machine holds and their keys:"
        found=no
        if [ -d "$STATE/networks" ]; then
            for network in "$STATE/networks"/*; do
                [ -d "$network" ] || continue
                say "  ${network##*/}"
                found=yes
            done
        fi
        [ "$found" = yes ] || say "  (none)"
        say ''
        say "To remove a network and its key, run 'peerfectly forget <network>' while peerfectly is"
        say "installed: install it again, forget the network, then uninstall. Deleting"
        say "$STATE by hand removes every network at once, with no question about"
        say "whether this machine is a network's only admin."
    fi
}

case "${1:-}" in
    '') install_it ;;
    --uninstall) uninstall_it ;;
    -h | --help)
        sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
        ;;
    *)
        say "unknown option '$1': run it with no option to install, or with --uninstall"
        exit 2
        ;;
esac
