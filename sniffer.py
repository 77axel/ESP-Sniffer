import sys
import platform
import argparse
import struct
import time
from collections import Counter, deque

try:
    import serial
    from serial.tools import list_ports
except ImportError:
    print("[!] Missing dependency: pip install pyserial --break-system-packages")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("[!] Missing dependency: pip install colorama --break-system-packages")
    sys.exit(1)

try:
    from manuf import manuf
    _parser = manuf.MacParser(manuf_name="manuf.txt", update=False)
except:
    print("[!] Missing dependency: pip install manuf --break-system-packages")
    sys.exit(1)

def classify_mac(mac_addr: str) -> str:
    octets = mac_addr.replace("-", ":").split(":")
    first = int(octets[0], 16)

    if mac_addr.lower() in ("ff:ff:ff:ff:ff:ff",):
        return "Broadcast"
    if first & 0x01:
        return "Multicast"
    if first & 0x02:
        return "Randomized"
    return None

def maclookup(mac_addr: str) -> str:
    special = classify_mac(mac_addr)
    if special:
        return special
    vendor = _parser.get_manuf(mac_addr)
    return vendor if vendor else "Unknown"

def update_manuf():
    print("Updating Manuf database ...")
    import requests

    with open("manuf.txt", "w", encoding="utf-8") as db_file:
        try:
            res = requests.get("https://www.wireshark.org/download/automated/data/manuf")
        except requests.ConnectionError:
            print("Connection Error !")
            return
        if res.status_code == 200:
            db_file.write(res.text)
            print("Manuf database updated successfully")
        else:
            print("Issue happened while updating the database")
        db_file.close()

ESP32_USB_IDS = {
    (0x10C4, 0xEA60),
    (0x1A86, 0x7523),
    (0x1A86, 0x55D4),
    (0x0403, 0x6001),
    (0x303A, 0x1001),
}

DESC_KEYWORDS = ("cp210", "ch340", "ch341", "ch9102", "silicon labs", "usb-serial", "usb serial", "uart")

def find_esp32_port() -> str:
    ports = list(list_ports.comports())
    if not ports:
        return None

    candidates = []
    for p in ports:
        score = 0
        if p.vid is not None and p.pid is not None and (p.vid, p.pid) in ESP32_USB_IDS:
            score += 10
        desc = (p.description or "").lower()
        manufacturer = (p.manufacturer or "").lower()
        if any(k in desc or k in manufacturer for k in DESC_KEYWORDS):
            score += 5
        if score > 0:
            candidates.append((score, p.device))

    if not candidates:
        return None

    candidates.sort(reverse=True)
    return candidates[0][1]


def list_available_ports():
    ports = list(list_ports.comports())
    if not ports:
        print(f"{Fore.RED}[!] No serial ports found on this system.{Style.RESET_ALL}")
        return
    print(f"{Fore.YELLOW}[*] Available serial ports:{Style.RESET_ALL}")
    for p in ports:
        vidpid = f"VID:PID={p.vid:04X}:{p.pid:04X}" if p.vid and p.pid else ""
        print(f"    {p.device:<20} {p.description or ''} {vidpid}")


def resolve_port(requested: str) -> str:
    if requested is not None:
        return requested

    detected = find_esp32_port()
    if detected:
        print(f"{Fore.GREEN}[+] Auto-detected ESP32 on {detected} ({platform.system()}){Style.RESET_ALL}")
        return detected

    print(f"{Fore.RED}[!] Could not auto-detect an ESP32 serial port.{Style.RESET_ALL}")
    list_available_ports()
    print(f"{Fore.YELLOW}[*] Specify the port manually with --port <PORT>{Style.RESET_ALL}")
    if platform.system() == "Windows":
        print("    Example: --port COM5")
    else:
        print("    Example: --port /dev/ttyUSB0  (Linux)  or  --port /dev/cu.usbserial-0001  (macOS)")
    sys.exit(1)


MAGIC = bytes([0xd4, 0xc3, 0xb2, 0xa1])
GLOBAL_HEADER_LEN = 24
PKT_HEADER_LEN = 16

FRAME_TYPES = {
    0x00: ("Management", "Assoc Request"),
    0x01: ("Management", "Assoc Response"),
    0x02: ("Management", "Reassoc Request"),
    0x03: ("Management", "Reassoc Response"),
    0x04: ("Management", "Probe Request"),
    0x05: ("Management", "Probe Response"),
    0x08: ("Management", "Beacon"),
    0x09: ("Management", "ATIM"),
    0x0A: ("Management", "Disassoc"),
    0x0B: ("Management", "Authentication"),
    0x0C: ("Management", "Deauth"),
    0x0D: ("Management", "Action"),
    0x18: ("Control", "BAR"),
    0x19: ("Control", "BA"),
    0x1B: ("Control", "PS-Poll"),
    0x1C: ("Control", "RTS"),
    0x1D: ("Control", "CTS"),
    0x1E: ("Control", "ACK"),
    0x1F: ("Control", "CF-End"),
    0x20: ("Data", "Data"),
    0x24: ("Data", "Null"),
    0x28: ("Data", "QoS Data"),
    0x2C: ("Data", "QoS Null"),
}

TYPE_COLOR = {
    "Management": Fore.CYAN,
    "Control": Fore.YELLOW,
    "Data": Fore.GREEN,
}

def mac_str(b):
    return ":".join(f"{x:02x}" for x in b)

def parse_dot11(frame):
    if len(frame) < 24:
        return None
    fc = struct.unpack("<H", frame[0:2])[0]
    version = fc & 0x3
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    key = (ftype << 4) | subtype
    kind, name = FRAME_TYPES.get(key, ("Unknown", f"0x{key:02x}"))

    addr1 = frame[4:10]
    addr2 = frame[10:16] if len(frame) >= 16 else b"\x00" * 6
    addr3 = frame[16:22] if len(frame) >= 22 else b"\x00" * 6

    return {
        "kind": kind,
        "name": name,
        "dst": mac_str(addr1),
        "src": mac_str(addr2),
        "bssid": mac_str(addr3),
    }


def sync_to_magic(ser):
    buf = bytearray()
    print(f"{Fore.YELLOW}[*] Waiting for pcap magic bytes (syncing)...{Style.RESET_ALL}")
    last_heartbeat = time.time()
    while True:
        b = ser.read(1)
        if not b:
            if time.time() - last_heartbeat > 5:
                print(f"{Fore.YELLOW}[*] Still waiting... try pressing EN/RESET on the ESP32.{Style.RESET_ALL}")
                last_heartbeat = time.time()
            continue
        buf += b
        if len(buf) > 4:
            del buf[0]
        if bytes(buf) == MAGIC:
            rest = ser.read(GLOBAL_HEADER_LEN - 4)
            if len(rest) < GLOBAL_HEADER_LEN - 4:
                return False
            print(f"{Fore.GREEN}[+] Synced. Global pcap header received.{Style.RESET_ALL}\n")
            return True


def read_exact(ser, n):
    data = bytearray()
    while len(data) < n:
        chunk = ser.read(n - len(data))
        if not chunk:
            continue
        data += chunk
    return bytes(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=None, help="Serial port (e.g. COM5, /dev/ttyUSB0, /dev/cu.usbserial-0001). If omitted, auto-detects an ESP32 on Windows/Linux/macOS.")
    ap.add_argument("--baud", type=int, default=921600)
    ap.add_argument("--update", type=int, default=None)
    ap.add_argument("--list-ports", action="store_true", help="List available serial ports and exit.")
    args = ap.parse_args()

    if args.list_ports:
        list_available_ports()
        sys.exit(0)

    if args.update:
        update_manuf()

    port = resolve_port(args.port)

    try:
        ser = serial.Serial(port, args.baud, timeout=1)
    except serial.SerialException as e:
        print(f"{Fore.RED}[!] Failed to open {port}: {e}{Style.RESET_ALL}")
        if platform.system() != "Windows":
            print(f"{Fore.YELLOW}[*] On Linux, you may need permission: sudo usermod -a -G dialout $USER (then log out/in){Style.RESET_ALL}")
        sys.exit(1)
    ser.dtr = False
    ser.rts = False
    time.sleep(0.1)

    print(f"{Fore.YELLOW}[*] If nothing happens for a few seconds, press the EN/RESET button on the ESP32 now.{Style.RESET_ALL}")
    if not sync_to_magic(ser):
        print(f"{Fore.RED}[!] Failed to sync to pcap stream.{Style.RESET_ALL}")
        sys.exit(1)

    stats = Counter()
    start_time = time.time()
    recent_macs = deque(maxlen=8)
    pkt_num = 0

    try:
        while True:
            hdr = read_exact(ser, PKT_HEADER_LEN)
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", hdr)

            if incl_len == 0 or incl_len > 4000:
                print(f"{Fore.RED}[!] Bad packet length ({incl_len}), resyncing...{Style.RESET_ALL}")
                if not sync_to_magic(ser):
                    break
                continue

            frame = read_exact(ser, incl_len)
            pkt_num += 1

            info = parse_dot11(frame)
            elapsed = time.time() - start_time

            if info is None:
                print(f"{Fore.RED}[{pkt_num:06d}] {elapsed:8.2f}s  RUNT FRAME len={incl_len}{Style.RESET_ALL}")
                continue

            stats[info["name"]] += 1
            color = TYPE_COLOR.get(info["kind"], Fore.WHITE)

            line = (
                f"{Fore.WHITE}[{pkt_num:06d}]{Style.RESET_ALL} "
                f"{Fore.WHITE}{elapsed:8.2f}s{Style.RESET_ALL}  "
                f"{color}{info['kind']:<10}{Style.RESET_ALL} "
                f"{color}{info['name']:<15}{Style.RESET_ALL} "
                f"len={incl_len:<4} "
                f"src={Fore.BLUE}{info['src']} ({maclookup(info['src'])}) {Style.RESET_ALL} "
                f"dst={Fore.BLUE}{info['dst']} ({maclookup(info['dst'])}) {Style.RESET_ALL} "
                f"bssid={Fore.MAGENTA}{info['bssid']}{Style.RESET_ALL}"
            )
            print(line)

            if info["src"] not in recent_macs:
                recent_macs.append(info["src"])

            if pkt_num % 50 == 0:
                top = stats.most_common(3)
                summary = "  ".join(f"{k}:{v}" for k, v in top)
                pps = pkt_num / elapsed if elapsed > 0 else 0
                print(f"{Fore.YELLOW}{Style.DIM}--- {pkt_num} pkts | {pps:.1f} pkt/s | top: {summary} ---{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Stopped. Total packets: {pkt_num}{Style.RESET_ALL}")
        for name, count in stats.most_common():
            print(f"    {name:<15} {count}")
        sys.exit(0)


if __name__ == "__main__":
    main()