#!/bin/bash
#
# gmp-relay.sh -- the privileged half of the GMP helper. Reads one GMP request on STDIN, sends it to
#                 a Dockerised Greenbone, writes ONLY the response XML to STDOUT.
#
# This is the script that actually needs root (for docker). It is never invoked directly by the
# remote caller: gmp.sh is the world-readable stub that runs it via a narrowly-scoped sudo rule.
#
# WHY THE SPLIT
#   The alternative is putting the SSH account in the docker group, which on any Docker host is
#   root-equivalent -- that account could mount the host filesystem into a container and read
#   anything. Instead this script is root-owned 0700, and sudoers permits exactly one command:
#       gvm-relay ALL=(root) NOPASSWD: /opt/greenbone/gmp-relay.sh
#   The SSH account therefore gains the ability to relay GMP requests and nothing else.
#
# HOW SECRETS ARE KEPT OFF argv AND OFF DISK
#   gvm-cli can take credentials as --gmp-password (argv, visible in `ps` to every local user, and
#   container argv IS visible from the host) or from a config file. It can take the request as
#   -X/--xml (argv again) or as a positional file. Both are therefore passed as FILES:
#     * written into a mktemp dir under /dev/shm, which is tmpfs -- so not written to the
#       filesystem. "Off disk" is only true to the extent that swap is disabled or encrypted,
#       since tmpfs pages can be swapped; see the README threat model.
#     * left root-owned, mode 0444, inside a 0700 root-owned directory
#     * mounted read-only, and the whole directory removed on exit via trap
#
#   DO NOT chown these to the container's uid. A bind mount does NOT translate uids: chowning to
#   "the container user" hands ownership to whatever HOST account holds that number, which on a normal
#   Linux box is a real login. The original version of this script also chowned the DIRECTORY and left
#   it 0750, which made both secrets readable by that account and -- since it then owned req.xml --
#   let it substitute an arbitrary GMP request. Keeping the directory 0700 root blunts a file-only
#   chown, because the path is not traversable, but there is no reason to chown at all: root-owned
#   0444 inside a 0700 root directory is both safer and sufficient. The kernel checks the file inode
#   for the container process, which sees the file through the mount rather than by traversing the host
#   directory. VERIFIED working.
#
#   VERIFIED, do not "simplify" this: gvm-cli does NOT read the request from stdin. Omitting the
#   positional file gives `TypeError: object of type 'NoneType' has no len()` from gvmtools/cli.py.
#   The request must be a file path argument.
#
set -euo pipefail
umask 077

# This script runs as root via sudo from a less-privileged account. env_reset IS sudo's own default,
# so the caller's environment is normally stripped -- but secure_path is a distro packaging choice
# rather than an upstream default, and without it env_reset preserves the caller's PATH. Hardcode
# PATH so a caller-supplied one cannot substitute bash, stat, chmod, timeout or docker, regardless of
# how the host's sudoers is configured.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

GMP_ENV="${GMP_ENV:-/opt/greenbone/.gmp.env}"

# Cleared rather than read from the environment: only the root-owned .gmp.env checked below may
# set these. A caller-supplied COMPOSE_DIR would point `docker compose` at a compose file of their
# choosing, which is root on this host -- a bigger hole than the one the owner check closes.
# Defaults are applied after that file is sourced.
unset COMPOSE_DIR GVM_TOOLS_SERVICE GMP_TIMEOUT

die() { printf '%s\n' "gmp-relay.sh: $*" >&2; exit 1; }

[ -r "$GMP_ENV" ] || die "cannot read $GMP_ENV"

# Refuse a loosely-permissioned credentials file rather than quietly using it.
perms="$(stat -c '%a' "$GMP_ENV")"
case "$perms" in
    600|400) ;;
    *) die "$GMP_ENV has mode $perms; expected 600. Run: chmod 600 $GMP_ENV" ;;
esac

# OWNER check as well as mode, because the next line EXECUTES this file as root. A mode check alone
# proves only that nobody else can read it; it says nothing about who wrote it, so any 0600 file the
# caller happens to own would satisfy the test and then run with full privilege. Unreachable as
# installed -- the sudoers fragment sets env_reset and the SSH forced command passes no environment,
# so GMP_ENV cannot be steered from outside -- but present for the same reason PATH is hardcoded
# below: this script should not depend on the invoking sudoers being exactly what install.sh wrote.
owner="$(stat -c '%u' "$GMP_ENV")" || die "cannot stat $GMP_ENV"
[ "$owner" -eq 0 ] || die "$GMP_ENV is owned by uid $owner, not root; refusing to source it as root"

# Sourcing errors are SUPPRESSED, not forwarded. This file is shell code, so a value that needed
# quoting makes the shell name the offending word: an unquoted multi-line password yields
# "line2: command not found", which echoes part of that password -- and this script's stderr reaches
# the caller's exception message and event log. The redaction further down covers gvm-cli's output,
# not the shell's. An operator debugging this file is root here and can run `sh -n` on it directly.
# shellcheck disable=SC1090
if ! . "$GMP_ENV" 2>/dev/null; then
    die "failed to source $GMP_ENV -- check it with: sh -n $GMP_ENV. Quote any value containing a space, %, # or other shell metacharacter. Its contents are deliberately not echoed."
fi

# Defaults applied only now, so they come from .gmp.env or from here -- never from the caller.
COMPOSE_DIR="${COMPOSE_DIR:-/opt/greenbone-community-edition}"
GVM_TOOLS_SERVICE="${GVM_TOOLS_SERVICE:-gvm-tools}"
GMP_TIMEOUT="${GMP_TIMEOUT:-300}"

# Accept either naming: GMP_USER/GMP_PASS or GMP_USERNAME/GMP_PASSWORD.
user="${GMP_USER:-${GMP_USERNAME:-}}"
pass="${GMP_PASS:-${GMP_PASSWORD:-}}"
[ -n "$user" ] || die "GMP_USER (or GMP_USERNAME) is not set in $GMP_ENV"
[ -n "$pass" ] || die "GMP_PASS (or GMP_PASSWORD) is not set in $GMP_ENV"

[ -d "$COMPOSE_DIR" ] || die "compose directory $COMPOSE_DIR not found"

# tmpfs, so neither the request nor the credentials are ever written to persistent storage.
d="$(mktemp -d /dev/shm/gmprelay.XXXXXX)"
trap 'rm -rf "$d"' EXIT

# Bounded read: the caller is remote, and an unbounded write into tmpfs is RAM exhaustion on the
# scanner host. 1 MiB is far more than any GMP request needs.
head -c 1048576 > "$d/req.xml"
[ -s "$d/req.xml" ] || die "no GMP request on stdin"

# gvm-tools reads this with configparser BasicInterpolation, where a lone % is a syntax error
# whose message QUOTES the value. Doubling makes % passwords work AND keeps them out of the error
# path. A newline cannot be represented in this format at all, so refuse it rather than emit a
# ParsingError naming the second line. CR counts too: gvm-tools opens the file in text mode, where a
# lone \r is a line break, so it splits the value exactly as \n would.
# $'\n' and $'\r', NOT "$(printf '\n')": command substitution strips trailing newlines, so the printf
# form yields an empty string and the pattern then matches every value. This script is bash, so
# ANSI-C quoting is available and literal.
case "$pass$user" in
    *$'\n'* | *$'\r'*)
        die 'GMP_USER or GMP_PASS contains a line break, which this config format cannot hold' ;;
esac
user_ini=$(printf '%s' "$user" | sed 's/%/%%/g')
pass_ini=$(printf '%s' "$pass" | sed 's/%/%%/g')
printf '[gmp]\nusername=%s\npassword=%s\n' "$user_ini" "$pass_ini" > "$d/gvm-tools.conf"

# No chown -- see the note in the header. Root-owned and world-readable BY INODE, inside a
# directory only root can traverse.
chmod 700 "$d"
chmod 444 "$d/req.xml" "$d/gvm-tools.conf"

cd "$COMPOSE_DIR"

# --progress quiet keeps STDOUT strictly the GMP response: compose otherwise emits "No services to
# build" and pull progress, which would corrupt the XML the caller parses.
# --no-deps avoids starting dependent services just to run a CLI.
#
# stderr goes to a FILE, not /dev/null. Discarding it meant a wrong GMP username or password in
# .gmp.env reached the Windows side as "no response from the GMP helper, ssh exit 1, nothing on
# stderr" -- which points at SSH or the sudo rule, the two things that were working, and says nothing
# about the credentials that were not. Never onto stdout, which must stay pure XML.
set +e
timeout "$GMP_TIMEOUT" docker compose --progress quiet run --rm --no-deps -T \
    -v "$d/req.xml":/tmp/req.xml:ro \
    -v "$d/gvm-tools.conf":/tmp/gvm-tools.conf:ro \
    "$GVM_TOOLS_SERVICE" \
    gvm-cli -c /tmp/gvm-tools.conf socket /tmp/req.xml 2>"$d/err"
rc=$?
set -e

if [ "$rc" -eq 124 ]; then
    die "GMP request timed out after ${GMP_TIMEOUT}s (set GMP_TIMEOUT to change)"
fi

# On failure, pass the reason up -- REDACTED. gvm-tools validates the request BEFORE sending and,
# on a parse error, prints "Invalid XML '<the whole request>'" -- which for a credential push
# contains the plaintext. That stderr becomes the caller's exception message and reaches its event
# log and task log, so password elements are stripped here, where they are produced. Bounded and
# flattened to one line; the remainder is a Python traceback.
if [ "$rc" -ne 0 ] && [ -s "$d/err" ]; then
    printf 'gmp-relay.sh: gvm-cli exit %s: ' "$rc" >&2
    # Greedy and attribute-tolerant on purpose: <password xml:space="preserve"> and a raw '<' inside
    # the value both defeat a narrow pattern, and over-redacting an error line costs nothing while
    # under-redacting it leaks. Redaction runs BEFORE the truncation, so a kept fragment cannot
    # contain an unredacted value.
    sed -e 's#<password[^>]*>.*</password>#<password>[redacted]</password>#g' "$d/err" \
        | tail -c 1024 | tr '\n' ' ' >&2
    printf '\n' >&2
fi
exit "$rc"
