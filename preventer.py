import subprocess
import platform

blocked_ips = set()

def is_linux():
    return platform.system() == "Linux"

def block_ip(ip):
    """Block an IP address using iptables (Linux only)."""
    if not is_linux():
        print(f"[!] IP blocking is only supported on Linux. Cannot block {ip}.")
        return

    if ip not in blocked_ips:
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            blocked_ips.add(ip)
            print(f"[🔥] Blocked IP: {ip}")
        except subprocess.CalledProcessError:
            print(f"[!] Failed to block IP: {ip}")
    else:
        print(f"[i] IP {ip} is already blocked.")

def unblock_ip(ip):
    """Unblock an IP address (manual unblock)."""
    if not is_linux():
        return

    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        blocked_ips.discard(ip)
        print(f"[✔] Unblocked IP: {ip}")
    except subprocess.CalledProcessError:
        print(f"[!] Failed to unblock IP: {ip}")
