import subprocess
import sys
import argparse
import socket
from alert import alert

# IPs that must never be blocked, no matter what
ALLOWLIST = {
    "192.168.56.102",   # Kali's own IP -- update if it changes
    "192.168.56.1",     # host-only gateway/host adapter
    "127.0.0.1",
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

    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        blocked_ips.add(ip)
        print(f"[IPS] Blocked {ip}")
        alert('IP_BLOCKED', ip, ", ".join(detail_bits), severity=3)
    except subprocess.CalledProcessError as e:
        print(f"[IPS] Failed to block {ip}: {e}")


def unblock_ip(ip, enforce=True, notify=True):
    """Remove a single DROP rule for ip, regardless of whether this
    process tracked it. Safe to call even if no rule exists (ignored)."""
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
        alert('IP_UNBLOCKED', ip, 'Manually unblocked via dashboard', severity=1)


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
