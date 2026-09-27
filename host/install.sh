#!/usr/bin/env bash
#
# Installs gmp.sh on the Greenbone host and creates .gmp.env from the example if absent.
#
# Run on the Docker host, as a user who can write $PREFIX. Idempotent.
#
set -euo pipefail

PREFIX="${PREFIX:-/opt/greenbone}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Installing to $PREFIX"
mkdir -p "$PREFIX"
install -m 0755 "$SRC_DIR/gmp.sh" "$PREFIX/gmp.sh"
echo "  installed $PREFIX/gmp.sh"

if [ -e "$PREFIX/.gmp.env" ]; then
    echo "  $PREFIX/.gmp.env exists; leaving it alone"
else
    install -m 0600 "$SRC_DIR/gmp.env.example" "$PREFIX/.gmp.env"
    echo "  created $PREFIX/.gmp.env (mode 600) -- EDIT IT NOW, it contains a placeholder password"
fi

# Nudge rather than fix: tightening someone else's file without saying so is worse than telling them.
perms="$(stat -c '%a' "$PREFIX/.gmp.env")"
if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
    echo "  WARNING: $PREFIX/.gmp.env is mode $perms. Run: chmod 600 $PREFIX/.gmp.env"
fi

cat <<NEXT

Next:
  1. Edit $PREFIX/.gmp.env with a dedicated low-privilege GMP user.
  2. Verify:  echo '<get_version/>' | $PREFIX/gmp.sh
     Expect a <get_version_response status="200"> element.
  3. Give the Windows runner account an SSH key to this host, then confirm from there:
     echo '<get_version/>' | ssh -o BatchMode=yes USER@THIS_HOST $PREFIX/gmp.sh

If step 2 works but step 3 does not, it is almost always one of:
  - the host key is not in the CALLING account's known_hosts (BatchMode makes ssh fail silently), or
  - the key is in a different account's profile than the one the scheduled task runs as.
NEXT
