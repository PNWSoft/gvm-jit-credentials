#!/usr/bin/env bash
#
# gmp.sh -- read one GMP request on STDIN, send it to a Dockerised Greenbone, write the response
#           to STDOUT.
#
# WHY THIS EXISTS
#   The obvious approach is `gvm-cli --gmp-username U --gmp-password P socket --xml '<...>'`.
#   That puts BOTH the GMP password and the scan credential being set onto the command line, where
#   they are visible in `ps` output to every local user for the life of the call, and land in shell
#   history. This wrapper takes the request on stdin and the GMP credentials from a 0600 env file,
#   so neither ever appears in argv -- see the detailed note above the docker invocation,
#   which is where the two easy-to-get-wrong leaks are.
#
#   Pair it with SSH: the Windows side pipes the request over an SSH channel, so the password is
#   never on a command line at either end.
#
# SETUP
#   1. cp gmp.env.example /opt/greenbone/.gmp.env   (or wherever GMP_ENV points)
#   2. edit it: a DEDICATED low-privilege GMP user, never the Greenbone 'admin' account
#   3. chmod 600 and chown it to the account that will run this script
#   4. ./install.sh   -- or place this file yourself and make it executable
#
# HARDENING (recommended): the account running this needs docker access, which is root-equivalent
#   on this host. Constrain the runner's SSH key in ~/.ssh/authorized_keys so it can do nothing
#   else, which sshd enforces regardless of what command the client requests:
#     command="/opt/greenbone/gmp.sh",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA...
#
# USAGE
#   echo '<get_version/>' | ./gmp.sh
#   ssh scanner@host /opt/greenbone/gmp.sh < request.xml
#
set -euo pipefail

GMP_ENV="${GMP_ENV:-/opt/greenbone/.gmp.env}"
COMPOSE_DIR="${COMPOSE_DIR:-/opt/greenbone-community-edition}"
GVM_TOOLS_SERVICE="${GVM_TOOLS_SERVICE:-gvm-tools}"

die() { printf '%s\n' "gmp.sh: $*" >&2; exit 1; }

[ -r "$GMP_ENV" ] || die "cannot read $GMP_ENV (set GMP_ENV to override)"

# Refuse a world- or group-readable credentials file rather than quietly using it. A silent
# weakening of the one file holding the GMP password is worth being noisy about.
perms="$(stat -c '%a' "$GMP_ENV")"
case "$perms" in
    600|400) ;;
    *) die "$GMP_ENV has mode $perms; expected 600. Run: chmod 600 $GMP_ENV" ;;
esac

# shellcheck disable=SC1090
. "$GMP_ENV"

[ -n "${GMP_USERNAME:-}" ] || die "GMP_USERNAME is not set in $GMP_ENV"
[ -n "${GMP_PASSWORD:-}" ] || die "GMP_PASSWORD is not set in $GMP_ENV"

[ -d "$COMPOSE_DIR" ] || die "compose directory $COMPOSE_DIR not found (set COMPOSE_DIR to override)"

request="$(cat)"
[ -n "$request" ] || die "no GMP request on stdin"

# KEEPING SECRETS OFF argv -- the entire reason this script exists. Two separate leaks to avoid:
#
#  1. `-e "GMPPASS=$GMP_PASSWORD"` would make the GMP password an argv element of the docker
#     compose process ON THE HOST, readable via ps/proc by every local user for the life of the
#     call. Exporting the variable and passing `-e GMPPASS` with NO value makes compose inherit it
#     from the environment instead.
#
#  2. `gvm-cli --gmp-password "$GMPPASS" ... --xml "$(cat)"` would put BOTH the GMP password and
#     the request -- which carries the freshly rotated scan-account password -- onto gvm-cli's argv
#     INSIDE the container. Container argv is visible in the host's `ps aux`, so that is not a
#     boundary. Instead the credentials are written to a 0600 config inside the ephemeral container
#     and the request is fed to gvm-cli on stdin.
#
# NOTE: gvm-cli reads the request from stdin when --xml is omitted. Verify against your installed
# gvm-tools version once with:  echo '<get_version/>' | ./gmp.sh
export GMP_USERNAME GMP_PASSWORD

cd "$COMPOSE_DIR"

# The request is PIPED rather than fed through a heredoc. Both are correct -- bash expands a
# heredoc body ONCE, so a '$' inside the expanded value of $request is not re-scanned -- but a pipe
# removes the question entirely, which is worth something in the one file whose job is handling a
# plaintext password.
#
# `set +e` around the call is load-bearing: a non-zero exit (including timeout's 124) must be
# captured, and under `set -e` it would abort the script before `rc=$?` ever ran, so the timeout
# message could never be reached.
set +e
printf '%s' "$request" | timeout "${GMP_TIMEOUT:-300}" docker compose run --rm -T \
    -e GMP_USERNAME \
    -e GMP_PASSWORD \
    "$GVM_TOOLS_SERVICE" \
    sh -c '
        set -eu
        umask 077
        conf="$(mktemp)"
        trap "rm -f \"$conf\"" EXIT
        printf "[gmp]\nusername=%s\npassword=%s\n" "$GMP_USERNAME" "$GMP_PASSWORD" > "$conf"
        exec gvm-cli --config "$conf" socket
    '
rc=$?
set -e

if [ "$rc" -eq 124 ]; then
    die "GMP request timed out after ${GMP_TIMEOUT:-300}s (set GMP_TIMEOUT to change)"
fi
exit "$rc"
