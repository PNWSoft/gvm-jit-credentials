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
#   so neither ever appears in argv.
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

# The credentials go in as environment variables, and gvm-cli reads them from there -- still not
# argv. --xml takes the request on its own stdin via the here-string below.
#
# `docker compose run --rm -T` writes progress to stderr on a cold start; callers must judge
# success from the returned XML status attribute, not from stderr being empty.
cd "$COMPOSE_DIR"
printf '%s' "$request" | docker compose run --rm -T \
    -e "GMPUSER=$GMP_USERNAME" \
    -e "GMPPASS=$GMP_PASSWORD" \
    "$GVM_TOOLS_SERVICE" \
    sh -c 'gvm-cli --gmp-username "$GMPUSER" --gmp-password "$GMPPASS" socket --xml "$(cat)"'
