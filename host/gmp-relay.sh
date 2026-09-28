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
#     * written into a mktemp dir under /dev/shm, which is tmpfs -- they never touch disk
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

# This script runs as root via sudo from a less-privileged account. Do not rely on the invoking
# sudoers configuration for hygiene: distro defaults (env_reset, secure_path) close the environment
# and PATH injection paths, but they are packaging choices, not sudo's compiled-in behaviour.
# Hardcode PATH so a caller-supplied one cannot substitute bash, stat, chmod, timeout or docker.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

COMPOSE_DIR="${COMPOSE_DIR:-/opt/greenbone-community-edition}"
GMP_ENV="${GMP_ENV:-/opt/greenbone/.gmp.env}"
GVM_TOOLS_SERVICE="${GVM_TOOLS_SERVICE:-gvm-tools}"
GMP_TIMEOUT="${GMP_TIMEOUT:-300}"

die() { printf '%s\n' "gmp-relay.sh: $*" >&2; exit 1; }

[ -r "$GMP_ENV" ] || die "cannot read $GMP_ENV"

# Refuse a loosely-permissioned credentials file rather than quietly using it.
perms="$(stat -c '%a' "$GMP_ENV")"
case "$perms" in
    600|400) ;;
    *) die "$GMP_ENV has mode $perms; expected 600. Run: chmod 600 $GMP_ENV" ;;
esac

# shellcheck disable=SC1090
. "$GMP_ENV"

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

printf '[gmp]\nusername=%s\npassword=%s\n' "$user" "$pass" > "$d/gvm-tools.conf"

# No chown -- see the note in the header. Root-owned and world-readable BY INODE, inside a
# directory only root can traverse.
chmod 700 "$d"
chmod 444 "$d/req.xml" "$d/gvm-tools.conf"

cd "$COMPOSE_DIR"

# --progress quiet plus 2>/dev/null keeps STDOUT strictly the GMP response: compose otherwise emits
# "No services to build" and pull progress, which would corrupt the XML the caller parses.
# --no-deps avoids starting dependent services just to run a CLI.
set +e
timeout "$GMP_TIMEOUT" docker compose --progress quiet run --rm --no-deps -T \
    -v "$d/req.xml":/tmp/req.xml:ro \
    -v "$d/gvm-tools.conf":/tmp/gvm-tools.conf:ro \
    "$GVM_TOOLS_SERVICE" \
    gvm-cli -c /tmp/gvm-tools.conf socket /tmp/req.xml 2>/dev/null
rc=$?
set -e

if [ "$rc" -eq 124 ]; then
    die "GMP request timed out after ${GMP_TIMEOUT}s (set GMP_TIMEOUT to change)"
fi
exit "$rc"
