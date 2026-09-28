#!/bin/sh
#
# gmp.sh -- world-readable stub. Reads one GMP request on STDIN, writes the response to STDOUT.
#
# This is the only thing the remote caller invokes. It holds no credentials and does no work: it
# hands off to gmp-relay.sh via a sudo rule scoped to exactly that one command, so the SSH account
# never needs docker-group membership (which would be root-equivalent on this host).
#
# Deliberately a stub and not the real script, so that the part needing root can be 0700 root-owned
# while this remains readable and executable by the relay account (the Linux account the Windows
# runner SSHes in as, which is not the AD scan account).
#
# RESTRICT THE KEY. This account can run the relay as root, so a stolen SSH key must not yield an
# interactive shell. Such a shell could not read the relay's tmpfs files directly -- that directory is
# 0700 root -- but it could enumerate the host, probe the sudo rule, and run the relay by hand as often
# as it liked. Pin the key to this one command in ~/.ssh/authorized_keys; sshd enforces it regardless
# of what the client asks to run:
#
#   command="/opt/greenbone/gmp.sh",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA...
#
# NOTE: a forced command OVERRIDES the requested one. If you move this script, update the key too,
# or callers will silently keep invoking the old path while appearing to succeed.
#
exec sudo -n /opt/greenbone/gmp-relay.sh
