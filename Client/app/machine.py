import hashlib
import uuid
import socket
import os
import platform

def _get_cpu_info() -> str:
    "Just static fields in CPU info"
    system = platform.system()

    if system == "Linux":
        try:
            with open("/proc/cpuinfo") as f:
                lines = f.readlines()
                "Just static fields, not bogomips or cpu MHz"
                stable_fields = {"model name", "vendor_id", "cpu family", "model", "stepping"}
                parts = []
                for line in lines:
                    if ":" in line:
                        key, _, val = line.partition(":")
                        if key.strip().lower() in stable_fields:
                            parts.append(val.strip())
                            break
                return "|".join(parts)
        except Exception:
            return ""
        
    elif system == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            name = winreg.QueryValueEx(key, "ProcessorNameString")[0]
            identifire = winreg.QueryValueEx(key, "Identifire")[0]
            return f"{name} | {identifire}"
        except Exception:
            return ""
        
    return platform.processor()

def _get_mac_address() -> str:
    """The most stable MAc address"""
    try:
        import psutil
        addrs = psutil.net_if_addrs()
        macs = []
        for iface, snics in sorted(addrs.items()):
            # skip loopback
            if iface.lower().startswith("lo"):
                continue
            for snic in snics:
                if snic.family.name in ("AF_LINK", "AF_PACKET") or snic.family == -1:
                    mac = snic.address
                    if mac and mac != "00:00:00:00:00:00":
                        macs.append(mac)
        if macs:
            return macs[0]
    except Exception:
        pass

    # fallback
    node = uuid.getnode()
    # If the eighth bit is set, it means the MAC address is locally administered (randomized)
    if (node >> 40) % 2 == 0:
        return str(node)
    return ""

def _get_disk_serial() -> str:
    """Disk serial number — very stable even on virtual machines (VMs)"""
    system = platform.system()

    if system == "Linux":
        try:
            # Accessing this requires root privileges, so we try it safely
            result = os.popen("lsblk -o SERIAL -n 2>/dev/null | head -1").read().strip()
            if result:
                return result
        except Exception:
            pass

    elif system == "Windows":
        try:
            result = os.popen(
                "wmic diskdrive get SerialNumber /value 2>nul"
            ).read().strip()
            for line in result.splitlines():
                if "SerialNumber=" in line:
                    serial = line.split("=", 1)[1].strip()
                    if serial:
                        return serial
        except Exception:
            pass

    return ""

def get_machine_hash() -> str:
    components = {
        "hostname": socket.gethostname(),
        "mac": _get_mac_address(),
        "cpu": _get_cpu_info(),
        "disk_serial": _get_disk_serial(),
        "os": f"{platform.system()}-{platform.release()}",
        "arch": platform.machine()
    }

    raw = "\n".join(f"{k}={v}" for k, v in components.items() if v)

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
