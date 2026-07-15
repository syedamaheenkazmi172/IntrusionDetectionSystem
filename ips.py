import subprocess
import sys
import argparse
import socket
from alert import alert

# to make the ips module work following command should be run
# sudo python ids.py --enforce
# without enforce flag it would not block the suspicious IP

# IPs that must never be blocked, no matter what
ALLOWLIST = {
    # add IPs here that you would use for testing purposes they won't get blocked even with enforce flag
    "127.0.0.1" # added localhost if testing is being done through same machine
}

blocked_ips = set()  # tracks what we've blocked this run, for cleanup


def block_ip(ip, enforce=False, reason=None, os_guess=None):
    if ip in ALLOWLIST:
        print(f"[IPS] Refusing to block allowlisted IP: {ip}")
        return
    if ip in blocked_ips:
        return  # already blocked (or already logged as dry-run), don't re-issue

    detail_bits = [f"triggered by {reason}" if reason else "auto-blocked"]
    if os_guess:
        detail_bits.append(f"suspected OS: {os_guess}")

    if not enforce:
        print(f"[IPS] (dry-run) Would block {ip}")
        blocked_ips.add(ip)
        alert('IP_BLOCKED', ip, f"(dry-run) {', '.join(detail_bits)}", severity=3)
        return

    # this only blocks traffic destined FOR the machine running this script (host-based firewall).
    already_present = subprocess.run(
        ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True
    ).returncode == 0
    if already_present:
        # rule's already live in the kernel (e.g. from a previous run whose in-memory blocked_ips set we lost) -- just resync our bookkeeping
        blocked_ips.add(ip)
        print(f"[IPS] {ip} already has an active DROP rule, nothing to add")
        return

    try:
        # -I (insert at position 1) instead of -A (append): appending puts the rule at the END of the chain, so any earlier ACCEPT rule (default policy, an established/related rule, etc.) matches first and this DROP is never reached. 
        # Inserting at the top guarantees it's evaluated before anything else.
        subprocess.run(
            ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
            check=True
        )
        blocked_ips.add(ip)
        print(f"[IPS] Blocked {ip}")
        alert('IP_BLOCKED', ip, ", ".join(detail_bits), severity=3)
    except subprocess.CalledProcessError as e:
        print(f"[IPS] Failed to block {ip}: {e}")


def unblock_ip(ip, enforce=True, notify=True):
    try:
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        print(f"[IPS] Unblocked {ip}")
    except subprocess.CalledProcessError as e:
        print(f"[IPS] No matching rule to remove for {ip} (or error): {e}")
    blocked_ips.discard(ip)
    # notify=False on shutdown cleanup so ctrl+c doesn't spam the dashboard
    # with an UNBLOCKED alert for every rule we're tearing down
    if notify:
        alert('IP_UNBLOCKED', ip, 'Manually unblocked via ips.py --unblock', severity=1)


def unblock_all(enforce=False):
    """Called on shutdown to remove all rules we added this run."""
    for ip in list(blocked_ips):
        if not enforce:
            continue
        unblock_ip(ip, notify=False)
    blocked_ips.clear()


if __name__ == "__main__":
    # Standalone emergency CLI: python3 ips.py --unblock <ip>
    parser = argparse.ArgumentParser(description="IPS manual control")
    parser.add_argument("--unblock", metavar="IP", help="Remove a DROP rule for this IP")
    parser.add_argument("--list", action="store_true", help="List current INPUT DROP rules")
    args = parser.parse_args()

    if args.unblock:
        unblock_ip(args.unblock)
    elif args.list:
        subprocess.run(["sudo", "iptables", "-L", "INPUT", "-n", "--line-numbers"])
    else:
        parser.print_help()
