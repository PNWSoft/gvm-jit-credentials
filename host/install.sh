#!/usr/bin/env bash
#
# Installs the GMP helper pair on the Greenbone Docker host:
#
#   gmp.sh        world-readable stub, invoked over SSH; execs the relay via scoped sudo
#   gmp-relay.sh  root-owned 0700, does the docker work
#   .gmp.env      0600, holds the GMP username and password
#   sudoers rule  lets ONE account run ONE script as root -- no docker group membership
#
# Run as root on the Docker host. Idempotent.
#
set -euo pipefail

PREFIX="${PREFIX:-/opt/greenbone}"
# The LINUX account the Windows runner SSHes in as -- NOT the AD scan account, which never logs in
# here. Override to match whatever you created: RELAY_ACCOUNT=gvm-relay ./install.sh
# SCAN_ACCOUNT is accepted as a deprecated alias.
RELAY_ACCOUNT="${RELAY_ACCOUNT:-${SCAN_ACCOUNT:-gvm-relay}}"
SCAN_ACCOUNT="$RELAY_ACCOUNT"
SUDOERS_FILE="${SUDOERS_FILE:-/etc/sudoers.d/gvm-jit-gmp-relay}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "install.sh must run as root" >&2; exit 1; }

echo "Installing to $PREFIX"
mkdir -p "$PREFIX"

install -m 0755 -o root -g root "$SRC_DIR/gmp.sh"       "$PREFIX/gmp.sh"
install -m 0700 -o root -g root "$SRC_DIR/gmp-relay.sh" "$PREFIX/gmp-relay.sh"
echo "  installed $PREFIX/gmp.sh (0755) and $PREFIX/gmp-relay.sh (0700 root)"

# The stub has the relay path baked in; keep them consistent if PREFIX was overridden.
# Both the stub's hardcoded relay path AND the relay's own default GMP_ENV point at /opt/greenbone.
# Rewriting only the first left a relay that could not read its own credentials file and failed every
# request with "cannot read /opt/greenbone/.gmp.env".
if [ "$PREFIX" != "/opt/greenbone" ]; then
    sed -i "s|/opt/greenbone/gmp-relay.sh|$PREFIX/gmp-relay.sh|g" "$PREFIX/gmp.sh"
    sed -i "s|/opt/greenbone/gmp.sh|$PREFIX/gmp.sh|g" "$PREFIX/gmp.sh"
    sed -i "s|GMP_ENV=\"\${GMP_ENV:-/opt/greenbone/.gmp.env}\"|GMP_ENV=\"\${GMP_ENV:-$PREFIX/.gmp.env}\"|" "$PREFIX/gmp-relay.sh"
    echo "  rewrote paths in gmp.sh and GMP_ENV in gmp-relay.sh for PREFIX=$PREFIX"
    # Verify BOTH rewrites. Checking only one leaves the other free to fail at runtime, where the
    # symptom is sudo refusing an unlisted command or the relay not finding its credentials.
    grep -q "exec sudo -n $PREFIX/gmp-relay.sh" "$PREFIX/gmp.sh" || {
        echo "  ERROR: failed to rewrite the relay path in gmp.sh; sudo would refuse the command" >&2
        exit 1
    }
    grep -q "GMP_ENV:-$PREFIX/.gmp.env" "$PREFIX/gmp-relay.sh" || {
        echo "  ERROR: failed to rewrite GMP_ENV in gmp-relay.sh; the relay would not find its credentials" >&2
        exit 1
    }
fi

if [ -e "$PREFIX/.gmp.env" ]; then
    echo "  $PREFIX/.gmp.env exists; leaving it alone"
else
    install -m 0600 -o root -g root "$SRC_DIR/gmp.env.example" "$PREFIX/.gmp.env"
    echo "  created $PREFIX/.gmp.env (0600) -- EDIT IT NOW, it holds a placeholder password"
fi

# Scoped sudo: one account, one command, no password. requiretty is disabled because the caller
# arrives over SSH with no TTY.
tmp="$(mktemp)"
# env_reset is sudo's own default, but secure_path is a distro packaging choice, and this rule grants
# root. State both explicitly so the fragment does not depend on what /etc/sudoers happens to contain.
# The trailing "" on the Cmnd is not decoration: sudoers(5) treats a bare command path as "this
# command with ANY arguments", while an empty double-quoted string after it means "with NO arguments".
# The relay ignores $@ today, so this changes nothing now -- it stops a future version that reads an
# argument from silently becoming caller-controlled.
cat > "$tmp" <<SUDOERS
Defaults:$SCAN_ACCOUNT !requiretty
Defaults:$SCAN_ACCOUNT env_reset, secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
$SCAN_ACCOUNT ALL=(root) NOPASSWD: $PREFIX/gmp-relay.sh ""
SUDOERS

# Validate BEFORE installing: a malformed sudoers file can lock out sudo entirely.
if visudo -cf "$tmp" >/dev/null 2>&1; then
    install -m 0440 -o root -g root "$tmp" "$SUDOERS_FILE"
    rm -f "$tmp"
    echo "  installed $SUDOERS_FILE ($SCAN_ACCOUNT may run only $PREFIX/gmp-relay.sh)"
else
    rm -f "$tmp"
    echo "  ERROR: generated sudoers rule failed validation; nothing installed" >&2
    exit 1
fi
visudo -c >/dev/null || { echo "  ERROR: sudoers validation failed after install" >&2; exit 1; }

cat <<NEXT

Next:
  1. Edit $PREFIX/.gmp.env -- a DEDICATED low-privilege GMP user, never Greenbone's 'admin'.
     Either GMP_USER/GMP_PASS or GMP_USERNAME/GMP_PASSWORD is accepted.
  2. Verify as root:
       echo '<get_version/>' | $PREFIX/gmp-relay.sh
  3. Verify as the relay account (this is the path the Windows side uses):
       sudo -u $SCAN_ACCOUNT sh -c "echo '<get_version/>' | $PREFIX/gmp.sh"
     Expect: <get_version_response status="200">...
  4. Restrict the runner's key in ~$SCAN_ACCOUNT/.ssh/authorized_keys so a stolen key cannot get a
     shell (sshd enforces this whatever the client requests):
       command="$PREFIX/gmp.sh",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA...
     A forced command OVERRIDES the requested one -- if you ever move gmp.sh, update the key too, or
     callers will keep hitting the old path while still appearing to succeed.

  5. From the Windows runner, confirm over SSH:
       echo '<get_version/>' | ssh -o BatchMode=yes $SCAN_ACCOUNT@THIS_HOST $PREFIX/gmp.sh

If step 2 works but step 3 does not, the sudoers rule or the relay's permissions are wrong.

If step 3 works but step 5 does not, check in this order:
  - "This account is currently not available." means $SCAN_ACCOUNT has a nologin shell. sshd runs
    even a forced command through the login shell, and nologin ignores -c. Give it /bin/sh; the
    forced command and no-pty are what prevent an interactive session.
  - exit 255 with no prompt is the SSH key or known_hosts of the CALLING account, not this host.
    Remember both belong to the account the scheduled task runs as, not to you.
Note that step 3 uses sudo, which does NOT go through the login shell, so it passes even when a
nologin shell would break step 5.
NEXT
