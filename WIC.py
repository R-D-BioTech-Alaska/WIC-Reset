import asyncio
import hashlib
import ipaddress
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine,
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        get_cmd,
        UdpTransportTarget,
    )
except Exception as e:
    raise RuntimeError(
        "PySNMP is required for SNMP functionality. Please install pysnmp to use this tool."
    ) from e

try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
except Exception:
    Zeroconf = None

try:
    import orjson as _json

    def _dumps(obj):
        return _json.dumps(obj, option=_json.OPT_INDENT_2).decode()
except Exception:
    import json as _json

    def _dumps(obj):
        return _json.dumps(obj, indent=2)


EPCTRL_HEAD = [1, 3, 6, 1, 4, 1, 1248, 1, 2, 2, 44, 1, 1, 2, 1]
PRT_SERIAL_OID = "1.3.6.1.2.1.43.5.1.1.17.1"
READ_TAG = [124, 124, 7, 0]
WRITE_TAG = [124, 124, 16, 0]
READ_A = [65, 190, 160]
WRITE_B = [66, 189, 33]
ST2_STATUS_OID = "1.3.6.1.4.1.1248.1.2.2.1.1.1.4.1"
COMMON_WRITE_KEY = [88, 98, 108, 98, 117, 112, 99, 106]
COMMON_PASSWORDS: List[Tuple[int, int]] = [
    (25, 7),
    (101, 0),
    (121, 4),
]
DEFAULT_DIVIDER_GUESS = 62.06
COMMON_PAIRS = [(24, 25), (28, 29), (20, 21), (22, 23)]
THRESH_ADDRS = [46, 47, 60, 61]
THRESH_DEFAULT_VALUE = 94


@dataclass
class SnmpConf:
    community: str = "public"
    port: int = 161
    timeout: float = 3.0
    retries: int = 1


@dataclass
class ModelPreset:
    match: List[str]
    password: Optional[Tuple[int, int]]
    write_key: Optional[List[int]]
    divider: Optional[float]
    perm_writes: Dict[int, int] = field(default_factory=dict)
    addr_pairs: List[Tuple[int, int]] = field(default_factory=list)


WF_7525_PERM = {
    20: 0,
    21: 0,
    22: 0,
    23: 0,
    24: 0,
    25: 0,
    26: 0,
    27: 0,
    28: 0,
    29: 0,
    30: 0,
    34: 0,
    46: 94,
    47: 94,
    60: 94,
    61: 94,
    49: 0,
    59: 0,
}

PRESETS: List[ModelPreset] = [
    ModelPreset(
        match=["wf-7525", "wf-7520", "wf-7510", "px-047a"],
        password=(101, 0),
        write_key=COMMON_WRITE_KEY[:],
        divider=19650.0 / 100,
        perm_writes=WF_7525_PERM,
        addr_pairs=[(24, 25), (28, 29), (20, 21), (22, 23), (30, 30), (34, 34)],
    ),
    ModelPreset(
        match=["et-4700"],
        password=(151, 7),
        write_key=[78, 98, 115, 106, 99, 98, 122, 98],
        divider=6345.0 / 100,
        perm_writes={
            48: 0,
            49: 0,
            50: 0,
            51: 0,
            52: 0,
            53: 0,
            54: 94,
            55: 94,
        },
        addr_pairs=[(48, 49), (50, 51), (52, 53)],
    ),
    ModelPreset(
        match=["et-", "l31", "l36", "l38", "xp-", "wf-"],
        password=None,
        write_key=None,
        divider=DEFAULT_DIVIDER_GUESS,
        perm_writes={
            20: 0,
            21: 0,
            22: 0,
            23: 0,
            24: 0,
            25: 0,
            28: 0,
            29: 0,
            30: 0,
            34: 0,
            46: 94,
            47: 94,
            60: 94,
            61: 94,
        },
        addr_pairs=COMMON_PAIRS[:],
    ),
]


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def printable(b: bytes) -> str:
    return "".join(chr(x) if 32 <= x <= 126 else "." for x in b)


def epctrl_oid(cmd: str, payload: bytes) -> str:
    if len(cmd) != 2:
        raise ValueError("EPSON-CTRL command must be two ASCII chars")
    body = bytearray()
    body += cmd.encode("ascii")
    body += len(payload).to_bytes(2, "little")
    body += payload
    parts = EPCTRL_HEAD + list(body)
    return ".".join(str(x) for x in parts)


def eeprom_read_oid(pw_hi: int, pw_lo: int, addr_lo: int, addr_hi: int) -> str:
    tail = READ_TAG + [pw_hi, pw_lo] + READ_A + [addr_lo, addr_hi, 0]
    return ".".join(str(x) for x in (EPCTRL_HEAD + tail))


def eeprom_write_oid(
    pw_hi: int,
    pw_lo: int,
    addr_lo: int,
    addr_hi: int,
    value: int,
    write_key: List[int],
) -> str:
    tail = WRITE_TAG + [pw_hi, pw_lo] + WRITE_B + [addr_lo, addr_hi, value] + list(write_key)
    return ".".join(str(x) for x in (EPCTRL_HEAD + tail))


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


async def snmp_get_octets(ip: str, oid: str, conf: SnmpConf) -> Optional[bytes]:
    eng = SnmpEngine()
    try:
        it = get_cmd(
            eng,
            CommunityData(conf.community, mpModel=0),
            await UdpTransportTarget.create((ip, conf.port), timeout=conf.timeout, retries=conf.retries),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        errInd, errStat, errIdx, varBinds = await it
        if errInd or errStat or not varBinds:
            return None
        _, val = varBinds[0]
        try:
            return bytes(val.asOctets())
        except Exception:
            return str(val).encode("utf-8", errors="ignore")
    finally:
        try:
            eng.close_dispatcher()
        except Exception:
            pass


async def get_serial(ip: str, conf: SnmpConf) -> Optional[str]:
    b = await snmp_get_octets(ip, PRT_SERIAL_OID, conf)
    if b:
        s = b.decode("utf-8", errors="ignore").strip()
        if s:
            return s
    b = await snmp_get_octets(ip, epctrl_oid("rp", b"\x00"), conf)
    if not b:
        return None
    txt = printable(b)
    m = re.search(r"[A-Z0-9]{8,20}", txt)
    return m.group(0) if m else txt.strip() or None


async def reset_rw(ip: str, conf: SnmpConf, serial_text: str) -> bool:
    digest = hashlib.sha1(serial_text.encode("utf-8")).digest()
    payload = b"\x01\x00" + digest
    data = await snmp_get_octets(ip, epctrl_oid("rw", payload), conf)
    return data is not None


async def eeprom_read_byte(ip: str, conf: SnmpConf, pw: Tuple[int, int], addr_lo: int, addr_hi: int) -> Optional[int]:
    oid = eeprom_read_oid(pw[0], pw[1], addr_lo, addr_hi)
    data = await snmp_get_octets(ip, oid, conf)
    if not data:
        return None
    return data[-1]


async def eeprom_write_byte(
    ip: str,
    conf: SnmpConf,
    pw: Tuple[int, int],
    addr_lo: int,
    addr_hi: int,
    value: int,
    key: List[int],
) -> bool:
    oid = eeprom_write_oid(pw[0], pw[1], addr_lo, addr_hi, value & 0xFF, key)
    data = await snmp_get_octets(ip, oid, conf)
    return data is not None


async def fetch_st2(ip: str, conf: SnmpConf) -> Optional[bytes]:
    return await snmp_get_octets(ip, ST2_STATUS_OID, conf)


WIC_PATHS = [
    Path(os.getenv("APPDATA", "")) / "wicreset" / "application.log",
    Path.home() / ".wicreset" / "application.log",
    Path.home() / "Library" / "Application Support" / "wicreset" / "application.log",
]

WIC_READ_RE = re.compile(
    r"1\.3\.6\.1\.4\.1\.1248\.1\.2\.2\.44\.1\.1\.2\.1\.124\.124\.7\.0\.(\d+)\.(\d+)\.65\.190\.160\.(\d+)\.0"
)
WIC_WRITE_RE = re.compile(
    r"1\.3\.6\.1\.4\.1\.1248\.1\.2\.2\.44\.1\.1\.2\.1\.124\.124\.16\.0\.(\d+)\.(\d+)\.66\.189\.33\.(\d+)\.0\.(\d+)\.((?:\d+\.)+\d+)"
)


@dataclass
class ParsedWic:
    password: Optional[Tuple[int, int]] = None
    write_key: Optional[List[int]] = None
    oids_seen: List[int] = field(default_factory=list)


def parse_wic(path: Path) -> Optional[ParsedWic]:
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="ignore")
    pw: Optional[Tuple[int, int]] = None
    wkey: Optional[List[int]] = None
    oids: set[int] = set()

    for m in WIC_READ_RE.finditer(text):
        pw = pw or (int(m.group(1)), int(m.group(2)))
        oids.add(int(m.group(3)))

    for m in WIC_WRITE_RE.finditer(text):
        pw = pw or (int(m.group(1)), int(m.group(2)))
        oids.add(int(m.group(3)))
        key_bytes = [int(x) for x in m.group(5).split(".") if x]
        if len(key_bytes) >= 6:
            wkey = key_bytes

    if not pw and not wkey and not oids:
        return None
    return ParsedWic(password=pw, write_key=wkey, oids_seen=sorted(oids))


ST2_CODES = {
    0x01: "status_code",
    0x02: "error_code",
    0x03: "self_print",
    0x04: "warning_code",
    0x06: "paper_path",
    0x07: "paper_mismatch",
    0x0C: "cleaning_time",
    0x0D: "maintenance_tanks",
    0x0E: "replace_cartridge",
    0x0F: "ink_info",
    0x10: "loading_path",
    0x13: "cancel_code",
    0x14: "cutter_info",
    0x18: "stacker_open",
    0x19: "job_name",
    0x1C: "temperature",
    0x1F: "serial",
    0x35: "paper_jam",
    0x36: "paper_count",
}


def parse_st2_frame(data: bytes) -> Dict[str, object]:
    out: Dict[str, object] = {"raw_hex": data.hex().upper()}
    if not data.startswith(b"@BDC ST2\r\n"):
        out["note"] = "Unexpected header"
        return out
    i = len(b"@BDC ST2\r\n")
    while i + 2 <= len(data):
        t = data[i]
        ln = data[i + 1]
        i += 2
        if i + ln > len(data):
            break
        payload = data[i : i + ln]
        i += ln
        key = ST2_CODES.get(t, f"tag_{t:02X}")
        if key in ("job_name", "serial"):
            out[key] = payload.decode("utf-8", errors="ignore").strip("\x00")
        elif key in ("status_code", "error_code", "warning_code", "cancel_code"):
            out[key] = payload.hex().upper()
        elif key == "ink_info":
            out[key] = [x for x in payload]
        elif key == "maintenance_tanks":
            out[key] = [x for x in payload]
        else:
            out[key] = payload.hex().upper()
    return out


class App(tk.Tk):
    """Main application window for the Epson waste counter reset tool."""

    def __init__(self):
        super().__init__()
        self.title("Open WIC Reset — Epson Waste Ink (SNMP)")
        self.geometry("1040x780")

        self.snmp = SnmpConf()
        self.devices: List[Tuple[str, str]] = []  
        self.password: Optional[Tuple[int, int]] = None
        self.write_password: Optional[Tuple[int, int]] = None
        self.write_key: Optional[List[int]] = None
        self.addr_pairs: List[Tuple[int, int]] = []
        self.divider: Optional[float] = None  
        self.model_label: str = "Unknown"

        self.target_pct_var = tk.DoubleVar(value=0.0)
        self.thresh_enable_var = tk.BooleanVar(value=True)
        self.divider_var = tk.DoubleVar(value=DEFAULT_DIVIDER_GUESS)

        self.log_lines: List[str] = []
        self._build_ui()
        self.log(
            "Ready. Scan or enter the printer IP (e.g., 192.168.1.6)."
        )

    def _build_ui(self):
        root = ttk.Frame(self, padding=12)
        root.pack(fill="both", expand=True)

        ttk.Button(root, text="Scan", command=self.scan_mdns).grid(
            row=0, column=0, sticky="w"
        )
        self.dev_var = tk.StringVar()
        self.dev_combo = ttk.Combobox(
            root, textvariable=self.dev_var, width=80
        )
        self.dev_combo.grid(row=0, column=1, columnspan=4, sticky="ew", padx=(8, 0))

        ttk.Label(root, text="Community").grid(
            row=1, column=0, sticky="w", pady=(8, 0)
        )
        self.community_var = tk.StringVar(value="public")
        ttk.Entry(root, textvariable=self.community_var, width=16).grid(
            row=1, column=1, sticky="w", pady=(8, 0)
        )

        ttk.Button(root, text="Identify", command=self.on_identify).grid(
            row=1, column=2, sticky="w", padx=(8, 0)
        )
        ttk.Button(root, text="Reset (rw quick)", command=self.on_reset_rw).grid(
            row=1, column=3, sticky="w", padx=(8, 0)
        )

        box = ttk.Frame(root)
        box.grid(row=2, column=0, columnspan=5, sticky="ew", pady=(8, 0))
        ttk.Label(
            box,
            text="Waste usage left after reset (%):",
        ).pack(side="left")
        self.pct_spin = ttk.Spinbox(
            box,
            from_=0.0,
            to=90.0,
            increment=0.5,
            width=8,
            textvariable=self.target_pct_var,
        )
        self.pct_spin.pack(side="left", padx=(6, 14))
        ttk.Checkbutton(
            box,
            text="Refresh maintenance thresholds to 94",
            variable=self.thresh_enable_var,
        ).pack(side="left")

        ttk.Label(
            box,
            text="Divider:",
        ).pack(side="left", padx=(14, 0))
        self.div_spin = ttk.Spinbox(
            box,
            from_=10.0,
            to=1000.0,
            increment=1.0,
            width=8,
            textvariable=self.divider_var,
        )
        self.div_spin.pack(side="left", padx=(4, 0))
        ttk.Label(box, text="units per %").pack(side="left", padx=(2, 0))

        ttk.Label(root, text="Progress").grid(
            row=3, column=0, sticky="w", pady=(12, 0)
        )
        self.prog = ttk.Progressbar(root, maximum=100)
        self.prog.grid(
            row=3, column=1, columnspan=4, sticky="ew", pady=(12, 0)
        )

        bar = ttk.Frame(root)
        bar.grid(row=4, column=0, columnspan=5, sticky="ew", pady=(10, 6))
        ttk.Button(bar, text="Read waste counters", command=self.on_read_counters).pack(
            side="left"
        )
        ttk.Button(
            bar, text="Permanent EEPROM reset", command=self.on_perm_reset
        ).pack(side="left", padx=8)
        ttk.Button(bar, text="Detect keys (quick)", command=self.on_detect_keys).pack(
            side="left", padx=8
        )
        ttk.Button(bar, text="Load WIC log", command=self.on_load_wic).pack(
            side="left", padx=8
        )
        ttk.Button(bar, text="Printer Status (ST2)", command=self.on_status).pack(
            side="left", padx=8
        )
        ttk.Button(bar, text="Save Log", command=self.on_save).pack(side="right")

        info = ttk.Frame(root)
        info.grid(row=5, column=0, columnspan=5, sticky="ew", pady=(6, 8))
        self.lbl_model = ttk.Label(info, text="Model: Unknown")
        self.lbl_model.pack(side="left")
        self.lbl_keys = ttk.Label(
            info, text=" Keys: pw=n/a write=n/a divider=n/a"
        )
        self.lbl_keys.pack(side="left", padx=(16, 0))

        ttk.Label(root, text="Log").grid(row=6, column=0, sticky="w")
        self.logbox = scrolledtext.ScrolledText(root, height=20, state="disabled")
        self.logbox.grid(row=7, column=0, columnspan=5, sticky="nsew")

        root.columnconfigure(1, weight=1)
        root.rowconfigure(7, weight=1)

    def set_progress(self, v: int):
        self.prog["value"] = v
        self.update_idletasks()

    def log(self, msg: str):
        """Append a line to the log display and internal log buffer."""
        line = msg.rstrip()
        self.log_lines.append(line)
        self.logbox.config(state="normal")
        self.logbox.insert("end", line + "\n")
        self.logbox.config(state="disabled")
        self.logbox.see("end")

    def _selected_ip(self) -> Optional[str]:
        text = self.dev_var.get().strip()
        if is_ip(text):
            return text
        if "@" in text:
            ip = text.split("@")[ -1 ].strip()
            if is_ip(ip):
                return ip
        idx = self.dev_combo.current()
        if 0 <= idx < len(self.devices):
            return self.devices[idx][0]
        return None

    def _update_labels(self):
        rpw = f"{self.password[0]}.{self.password[1]}" if self.password else "n/a"
        wpw = (
            f"{self.write_password[0]}.{self.write_password[1]}"
            if self.write_password
            else "n/a"
        )
        wk = "yes" if self.write_key else "n/a"
        div_value = self.divider if self.divider else self.divider_var.get()
        div = f"{div_value:.2f}" if div_value else "n/a"
        self.lbl_model.config(text=f"Model: {self.model_label}")
        self.lbl_keys.config(
            text=f" Keys: pw‑r={rpw} pw‑w={wpw} write={wk} divider={div}"
        )


    def _apply_presets(self, label_lower: str):
        for p in PRESETS:
            if any(tok in label_lower for tok in p.match):
                if not self.password and p.password:
                    self.password = p.password
                if p.password:
                    self.write_password = p.password
                if p.write_key:
                    self.write_key = p.write_key[:]
                if p.divider:
                    self.divider = p.divider
                    self.divider_var.set(p.divider)
                if p.addr_pairs:
                    self.addr_pairs = p.addr_pairs[:]
                self.log(f"[Preset] Applied: {p.match[0]}")
                break

    def scan_mdns(self):
        if Zeroconf is None:
            self.log("Zeroconf not installed; enter IP manually.")
            return
        self.log("Scanning network via mDNS for IPP printers…")
        zc = Zeroconf()
        self.devices.clear()

        def add(ip: str, label: str):
            self.devices.append((ip, label))
            self.dev_combo["values"] = [f"{ip} — {label}" for ip, label in self.devices]
            self.dev_combo.current(0)
            self.log(f"Found: {label}")

        class Listener(ServiceListener):
            def add_service(self, z, t, name):
                info = z.get_service_info(t, name)
                if not info:
                    return
                addrs = info.parsed_addresses()
                if not addrs:
                    return
                ip = addrs[0]
                label = f"{name} @ {ip}"
                if any(x in name.lower() for x in ("epson", "et-", "wf-", "xp-")):
                    add(ip, label)

        browsers = [
            ServiceBrowser(zc, "_ipp._tcp.local.", Listener()),
            ServiceBrowser(zc, "_printer._tcp.local.", Listener()),
        ]

        def stop():
            time.sleep(3)
            for b in browsers:
                try:
                    b.cancel()
                except Exception:
                    pass
            try:
                zc.close()
            except Exception:
                pass
            if not self.devices:
                self.log("No printers discovered. Type the IP and continue.")

        threading.Thread(target=stop, daemon=True).start()

    def on_identify(self):
        ip = self._selected_ip()
        if not ip:
            messagebox.showerror("No printer", "Select or type the printer IP.")
            return
        self.snmp.community = self.community_var.get().strip() or "public"
        self.set_progress(0)
        self.log(f"Connecting to printer {ip}…")
        threading.Thread(
            target=self._identify_thread, args=(ip,), daemon=True
        ).start()

    def _identify_thread(self, ip: str):
        try:
            if sys.platform.startswith("win"):
                try:
                    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                except Exception:
                    pass
            self.set_progress(20)
            serial = asyncio.run(get_serial(ip, self.snmp))
            if serial:
                self.log(f"[OK] Serial: {serial}")
            else:
                self.log("[!] Serial not available.")
            label = (self.dev_var.get() or "").strip()
            self.model_label = label or "Epson (detected)"
            self._apply_presets(label.lower())
            self._update_labels()
            self.set_progress(100)
        except Exception as e:
            self.set_progress(0)
            self.log(f"[!] Identify error: {e!r}")
            messagebox.showerror("Error", str(e))

    def on_reset_rw(self):
        ip = self._selected_ip()
        if not ip:
            messagebox.showerror("No printer", "Select or type the printer IP.")
            return
        self.snmp.community = self.community_var.get().strip() or "public"
        self.set_progress(0)
        self.log(f"Connecting to {ip}…")
        threading.Thread(
            target=self._reset_rw_thread, args=(ip,), daemon=True
        ).start()

    def _reset_rw_thread(self, ip: str):
        try:
            if sys.platform.startswith("win"):
                try:
                    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                except Exception:
                    pass
            self.set_progress(35)
            serial = asyncio.run(get_serial(ip, self.snmp)) or ""
            if serial:
                self.log(f"Serial: {serial}")
            else:
                self.log("Serial not found; attempting anyway.")
            self.set_progress(65)
            self.log("Sending EPSON‑CTRL 'rw'…")
            ok = asyncio.run(reset_rw(ip, self.snmp, serial))
            if ok:
                self.set_progress(100)
                self.log("[+] Printer replied to reset command.")
                messagebox.showinfo(
                    "Reset Complete",
                    "Reset Complete - Please Turn Power to Printer Off and Back On",
                )
                self.log("=== Reset Complete. Power OFF 10s, then ON. ===")
            else:
                self.set_progress(0)
                self.log("[!] No confirmation from printer for 'rw'.")
                messagebox.showerror(
                    "Not confirmed",
                    "Printer did not confirm the reset. Try power-cycling.\n"
                    "If the error persists, use Permanent EEPROM reset with keys.",
                )
        except Exception as e:
            self.set_progress(0)
            self.log(f"[!] Reset error: {e!r}")
            messagebox.showerror("Error", str(e))

    def on_detect_keys(self):
        ip = self._selected_ip()
        if not ip:
            messagebox.showerror("No printer", "Select or type the printer IP.")
            return
        self.snmp.community = self.community_var.get().strip() or "public"
        self.set_progress(0)
        self.log("Trying common EEPROM passwords…")
        threading.Thread(
            target=self._detect_keys_thread, args=(ip,), daemon=True
        ).start()

    def _detect_keys_thread(self, ip: str):
        try:
            if sys.platform.startswith("win"):
                try:
                    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                except Exception:
                    pass
            found = None
            for pw in COMMON_PASSWORDS:
                val = asyncio.run(eeprom_read_byte(ip, self.snmp, pw, 24, 0))
                if val is not None:
                    found = pw
                    self.log(f"[OK] Read with password {pw[0]}.{pw[1]} → {val}")
                    break
                else:
                    self.log(f"[ ] Password {pw[0]}.{pw[1]} failed.")
            if found:
                self.password = found
                if not self.write_key:
                    self.write_key = COMMON_WRITE_KEY[:]
                if not self.divider:
                    self.divider_var.set(DEFAULT_DIVIDER_GUESS)
                if not self.addr_pairs:
                    self.addr_pairs = COMMON_PAIRS[:]
                self._update_labels()
                self.set_progress(100)
                messagebox.showinfo(
                    "Keys detected",
                    f"Read password: {found[0]}.{found[1]}\n"
                    f"Write key length: {len(self.write_key)}",
                )
            else:
                self.set_progress(0)
                messagebox.showwarning(
                    "Not found",
                    "Common passwords failed. Load a WIC log or try another preset.",
                )
        except Exception as e:
            self.set_progress(0)
            self.log(f"[!] Detect error: {e!r}")
            messagebox.showerror("Error", str(e))

    def on_load_wic(self):
        path = filedialog.askopenfilename(
            title="Select WIC application.log",
            filetypes=[("Log", "*.log;*.txt;*.*")],
            initialdir=str(
                WIC_PATHS[0].parent if WIC_PATHS[0].parent.exists() else Path.home()
            ),
        )
        if not path:
            for p in WIC_PATHS:
                if p.exists():
                    path = str(p)
                    break
        if not path:
            messagebox.showwarning(
                "Not found", "No WIC log selected/found."
            )
            return

        parsed = parse_wic(Path(path))
        if not parsed:
            messagebox.showwarning(
                "No data", "Could not extract keys from the log."
            )
            return

        if parsed.password:
            self.password = parsed.password
        if parsed.write_key:
            self.write_key = parsed.write_key
        if parsed.oids_seen and not self.addr_pairs:
            self.addr_pairs = [(oid, oid + 1) for oid in parsed.oids_seen]
        if not self.divider:
            self.divider_var.set(DEFAULT_DIVIDER_GUESS)
        self._update_labels()
        self.log(
            f"[OK] Loaded WIC log. pw={self.password} write_key_len={len(self.write_key or [])} "
            f"addr_candidates={len(self.addr_pairs)}"
        )

    def on_read_counters(self):
        ip = self._selected_ip()
        if not ip:
            messagebox.showerror("No printer", "Select or type the printer IP.")
            return
        if not self.password:
            messagebox.showwarning(
                "Keys required",
                "Reading EEPROM needs the read password.\n"
                "Use Detect keys or load a WIC log.",
            )
            return
        self.snmp.community = self.community_var.get().strip() or "public"
        self.set_progress(0)
        self.log("Reading waste counter bytes…")
        threading.Thread(
            target=self._read_counters_thread, args=(ip,), daemon=True
        ).start()

    def _read_counters_thread(self, ip: str):
        try:
            if sys.platform.startswith("win"):
                try:
                    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                except Exception:
                    pass

            pairs = self.addr_pairs or COMMON_PAIRS
            results: Dict[str, Dict[str, int]] = {}
            ok_count = 0
            for a, b in pairs:
                b1 = asyncio.run(eeprom_read_byte(ip, self.snmp, self.password, a, 0))
                b2 = asyncio.run(eeprom_read_byte(ip, self.snmp, self.password, b, 0))
                label = f"{a}.0 + {b}.0"
                if b1 is None or b2 is None:
                    results[label] = {"ok": 0}
                    continue
                val = (b2 << 8) | b1
                results[label] = {"ok": 1, "lo": b1, "hi": b2, "value": val}
                ok_count += 1

            self.log("EEPROM pairs:")
            for k, v in results.items():
                if v.get("ok"):
                    self.log(f"  {k} -> 0x{v['value']:04X} ({v['value']})")
                else:
                    self.log(f"  {k} -> (no response)")

            if ok_count:
                div = self.divider if self.divider else self.divider_var.get()
                self.log(f"Estimated % using divider {div}:")
                for k, v in results.items():
                    if v.get("ok"):
                        pct = round(v["value"] / div, 2)
                        self.log(f"  {k}: ~{pct}%")
            else:
                self.log(
                    "No readable pairs found; need correct keys/addresses."
                )

            self.set_progress(100)
            messagebox.showinfo(
                "Done", "Read complete. See Log for details."
            )
        except Exception as e:
            self.set_progress(0)
            self.log(f"[!] Read error: {e!r}")
            messagebox.showerror("Error", str(e))

    def on_perm_reset(self):
        ip = self._selected_ip()
        if not ip:
            messagebox.showerror("No printer", "Select or type the printer IP.")
            return
        if not self.password or not self.write_key:
            messagebox.showwarning(
                "Keys required",
                "Permanent EEPROM reset needs the read password and write key.\n"
                "Load WIC log or Detect keys first.",
            )
            return
        self.snmp.community = self.community_var.get().strip() or "public"
        self.set_progress(0)

        label_lower = self.model_label.lower()
        preset_writes: Dict[int, int] = {}
        for p in PRESETS:
            if any(tok in label_lower for tok in p.match) and p.perm_writes:
                preset_writes = p.perm_writes.copy()
                break
        if not preset_writes:
            preset_writes = {
                20: 0,
                21: 0,
                22: 0,
                23: 0,
                24: 0,
                25: 0,
                28: 0,
                29: 0,
                30: 0,
                34: 0,
                46: 94,
                47: 94,
                60: 94,
                61: 94,
            }

        tgt_pct = clamp(float(self.target_pct_var.get()), 0.0, 90.0)
        div = self.divider if self.divider else float(self.divider_var.get())
        raw_val = int(round(tgt_pct * div))
        lo = raw_val & 0xFF
        hi = (raw_val >> 8) & 0xFF
        writes: Dict[int, int] = preset_writes.copy()

        def set_pair(a: int, b: int):
            writes[a] = lo
            writes[b] = hi
        pairs = self.addr_pairs or COMMON_PAIRS
        for (a, b) in pairs:
            set_pair(a, b)
        threshold_candidates = [addr for addr in writes if (
            addr in THRESH_ADDRS) or (preset_writes.get(addr) == THRESH_DEFAULT_VALUE)
        ]
        if not self.thresh_enable_var.get():
            for t in threshold_candidates:
                writes.pop(t, None)
        else:
            for t in threshold_candidates:
                writes[t] = THRESH_DEFAULT_VALUE

        if not messagebox.askyesno(
            "Confirm permanent reset",
            f"This will write {len(writes)} EEPROM bytes.\n"
            f"Waste usage left after reset: {tgt_pct:.2f}% (raw {raw_val}).\n\n"
            "Make sure the waste pads or external kit have been serviced/emptied. Continue?",
        ):
            return

        threading.Thread(
            target=self._perm_reset_thread, args=(ip, writes), daemon=True
        ).start()

    def _perm_reset_thread(self, ip: str, writes: Dict[int, int]):
        try:
            if sys.platform.startswith("win"):
                try:
                    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                except Exception:
                    pass

            total = len(writes)
            done = 0
            errors = 0
            for addr, value in writes.items():
                ok = asyncio.run(
                    eeprom_write_byte(
                        ip,
                        self.snmp,
                        self.write_password if self.write_password else self.password,
                        addr,
                        0,
                        value & 0xFF,
                        self.write_key,
                    )
                )
                done += 1
                self.set_progress(int(done * 100 / max(1, total)))
                if ok:
                    self.log(f"[WRITE] {addr}.0 = {value}")
                else:
                    errors += 1
                    self.log(f"[!] Write failed at {addr}.0")

            if errors == 0:
                messagebox.showinfo(
                    "Permanent reset complete",
                    "Reset Complete - Please Turn Power to Printer Off and Back On",
                )
                self.log(
                    "=== Permanent reset complete. Power‑cycle the printer. ==="
                )
            else:
                messagebox.showwarning(
                    "Completed with errors",
                    f"Writes attempted: {total}, failed: {errors}.\n"
                    "See Log. You may need exact model keys/addresses.",
                )
        except Exception as e:
            self.set_progress(0)
            self.log(f"[!] EEPROM reset error: {e!r}")
            messagebox.showerror("Error", str(e))

    def on_status(self):
        ip = self._selected_ip()
        if not ip:
            messagebox.showerror("No printer", "Select or type the printer IP.")
            return
        self.snmp.community = self.community_var.get().strip() or "public"
        self.set_progress(0)
        self.log("Reading @BDC ST2 status…")
        threading.Thread(
            target=self._status_thread, args=(ip,), daemon=True
        ).start()

    def _status_thread(self, ip: str):
        try:
            if sys.platform.startswith("win"):
                try:
                    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                except Exception:
                    pass

            self.set_progress(40)
            data = asyncio.run(fetch_st2(ip, self.snmp))
            if not data:
                self.set_progress(0)
                self.log("[!] No ST2 data.")
                messagebox.showwarning(
                    "No data", "Printer did not return ST2 status."
                )
                return

            parsed = parse_st2_frame(data)
            self.log("ST2 parsed summary:")
            for k, v in parsed.items():
                if k == "raw_hex":
                    continue
                self.log(f"  {k}: {v}")

            top = tk.Toplevel(self)
            top.title("Printer Status (ST2)")
            txt = scrolledtext.ScrolledText(top, width=100, height=30)
            txt.pack(fill="both", expand=True)
            txt.insert("end", _dumps(parsed))
            txt.config(state="disabled")

            self.set_progress(100)
        except Exception as e:
            self.set_progress(0)
            self.log(f"[!] ST2 error: {e!r}")
            messagebox.showerror("Error", str(e))

    def on_save(self):
        out = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text/JSON", "*.txt;*.json;*.*")],
            title="Save session log",
        )
        if not out:
            return
        meta = {
            "model_label": self.model_label,
            "password": self.password,
            "write_key_len": len(self.write_key or []),
            "divider": self.divider if self.divider else self.divider_var.get(),
            "addr_pairs": self.addr_pairs,
            "snmp": self.snmp.__dict__,
            "target_pct": self.target_pct_var.get(),
            "thresholds_enabled": self.thresh_enable_var.get(),
            "log": self.log_lines,
        }
        Path(out).write_text(_dumps(meta), encoding="utf-8")
        messagebox.showinfo("Saved", f"Saved to: {out}")

if __name__ == "__main__":
    try:
        App().mainloop()
    except tk.TclError as e:
        print(
            "Unable to launch the GUI. This program must be run in an environment with a display."
        )
        print(f"Error: {e}")
