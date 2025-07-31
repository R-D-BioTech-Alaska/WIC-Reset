<div align="center">

# **WIC - Waste Ink Counter Reset**

**A free, research‑driven waste‑ink counter tool over SNMP**  
*No credits. No paywall. Your printer*  
**Cause No-one should have to continue to pay for something they bought once.**

</div>
<p align="center">
  <a href="#license"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-lightgrey" /></a>
</p>

---

## Overview

**WIC Reset** communicates with Epson printers that expose the **EPSON‑CTRL** interface via **SNMP**, allowing you to:

* Perform a **quick reset** using the EPSON‑CTRL `rw` command.
* Perform a **permanent EEPROM reset** to a **target used %** you choose (e.g., 10%).
* **Read** common EEPROM counter pairs and compute estimated **usage %**.
* **Refresh maintenance thresholds** to typical values.
* **Auto‑discover** printers via **mDNS/Bonjour** (optional).
* **Parse WIC logs** to extract working read passwords, write keys, and observed OIDs.
* **Decode @BDC ST2** printer status frames into readable fields.

The app is a single‑window **Tkinter** GUI designed for clarity, logging, and repeatable maintenance.

> ⚠️ **Responsibility:** Writing EEPROM is powerful. Always service or route waste ink before lowering counters. You accept all risk.

---

## Download

<a id="download"></a>

* **Windows one‑file executable:** see **[Releases](../../releases)**.
* **Source:** this repository. Run with Python 3.11+ and required dependencies.

### Verify download (recommended)

```powershell
# PowerShell
Get-FileHash .\WIC.exe -Algorithm SHA256
```

Compare the hash with the value published in the release notes.

---

## Features

* **Quick Reset (`rw`)** — Sends a reset using the printer serial’s SHA‑1 hash.
* **Permanent EEPROM Reset to Target %** — Writes the EEPROM counters so the printer reports your chosen post‑reset usage percentage.
* **Waste Counter Read‑back** — Reads typical 16‑bit pairs and prints raw + % using a configurable divider.
* **Threshold Refresh** — Bytes 46, 47, 60, 61 → value **94** (configurable toggle).
* **Key Detection** — Tries common read passwords and a widely‑observed write key.
* **WIC Log Import** — Pulls passwords, write keys, and OID addresses from `application.log`.
* **Zeroconf Scan** — Finds Epson printers advertising `_ipp._tcp` / `_printer._tcp` (requires `zeroconf`).
* **ST2 Status Decode** — Fetch and parse `@BDC ST2` to show status, errors, serial, and ink info.
* **Verbose Log + Save** — Export a JSON‑structured session log for audits or sharing.

---

## How it works

Open WIC Reset builds EPSON‑CTRL OIDs and talks over SNMP using **PySNMP v3 asyncio HLAPI**.

### Core OIDs

* **EPSON‑CTRL base:** `1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1`
* **Printer serial (Printer‑MIB):** `1.3.6.1.2.1.43.5.1.1.17.1`
* **`@BDC ST2` status:** `1.3.6.1.4.1.1248.1.2.2.1.1.1.4.1`

### EEPROM sub‑blocks

| Tag            | Meaning       |   |             |
| -------------- | ------------- | - | ----------- |
| `124.124.7.0`  | Read tag (\`  |   | \`, len 7)  |
| `124.124.16.0` | Write tag (\` |   | \`, len 16) |
| `65.190.160`   | Read block A  |   |             |
| `66.189.33`    | Write block B |   |             |

### Common counter pairs

| Pair          | Notes     |
| ------------- | --------- |
| `24.0 + 25.0` | 16‑bit LE |
| `28.0 + 29.0` | 16‑bit LE |
| `20.0 + 21.0` | 16‑bit LE |
| `22.0 + 23.0` | 16‑bit LE |

### Typical thresholds

| Address | Value |
| ------: | ----: |
|      46 |    94 |
|      47 |    94 |
|      60 |    94 |
|      61 |    94 |

A **divider** converts raw counter values to approximate percent:
`percent ≈ raw / divider`. A sensible default is **62.06** when a model‑specific value is unknown.

---

## Supported models / presets

The app includes a few presets and a generic fallback. If your model isn’t listed, import a WIC log or try **Detect keys**.

| Family / Model                      | Preset fields                                                                         |
| ----------------------------------- | ------------------------------------------------------------------------------------- |
| **WF‑7525 / 7520 / 7510 / PX‑047A** | Known password, common write key, divider ≈ 196.5, mapped writes (20–34, thresholds). |
| **EcoTank / WF / XP (generic)**     | Common pairs and thresholds, default divider, key detection or WIC log import.        |

> Contributions with verified address maps are welcome.

---

## Quick start (Windows)

1. **Download** `WIC.exe` from **Releases**.
2. Ensure the **printer and PC are on the same LAN**. SNMP must be reachable on port **161**.
3. **Run** the app. If Windows asks, allow network access on **Private** networks.
4. Click **Scan** to discover printers, or **enter the IP** manually.
5. Click **Identify** to verify communication and apply a preset.
6. Use **Read waste counters** to confirm current values.
7. Choose **Reset (rw quick)** or **Permanent EEPROM reset to %**.
8. **Power‑cycle** the printer after a successful reset (OFF 10 s → ON).

### mDNS / Zeroconf (Scan)

If **Scan** logs *“Zeroconf not installed; enter IP manually”*, rebuild with `zeroconf` bundled (see **Build**). Also ensure UDP **5353** is allowed by your firewall and that the printer advertises `_ipp._tcp` or `_printer._tcp`.

---

## Build from source

### Python environment

```bash
pip install pysnmp zeroconf orjson
```

`orjson` is optional; the app falls back to stdlib `json`.

Run the GUI:

```bash
python WIC.py
```

### PyInstaller (recommended)

Simple one‑file GUI build:

```bash
pyinstaller --onefile --windowed --icon WIC.ico WIC.py
```

Include discovery and SNMP stacks explicitly (more robust):

```bash
pyinstaller ^
  --onefile --windowed ^
  --name WIC ^
  --icon WIC.ico ^
  --hidden-import=zeroconf --hidden-import=ifaddr ^
  --collect-submodules zeroconf ^
  --collect-submodules ifaddr ^
  --collect-submodules pysnmp ^
  --collect-submodules pyasn1 ^
  --collect-submodules pysnmp.hlapi.v3arch.asyncio ^
  WIC.py
```

#### `.spec` template

A curated `.spec` is provided below. Save as `WIC.spec` and build with `pyinstaller WIC.spec`.

```python
# WIC.spec
from PyInstaller.utils.hooks import collect_submodules
pkgs = [
    'zeroconf', 'ifaddr',
    'pysnmp', 'pyasn1', 'pysnmp.hlapi.v3arch.asyncio',
]
hidden = []
for p in pkgs:
    hidden += collect_submodules(p)

a = Analysis(
    ['WIC.py'],
    pathex=[],
    binaries=[],
    datas=[('WIC.ico', 'WIC.ico', 'DATA')],
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    excludes=['orjson'],  # optional
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data)
exe = EXE(
    pyz, a.scripts, a.binaries, a.zipfiles, a.datas,
    [], name='WIC', icon='WIC.ico', console=False,
)
```

---

## Troubleshooting

### Scan says Zeroconf not installed

* Rebuild with `zeroconf` and `ifaddr` bundled (see PyInstaller command above).
* Allow UDP **5353** inbound/outbound. Private network profile recommended.
* mDNS typically does **not** cross subnets/VLANs without a reflector.

### No response to `rw`

* Some firmware ignores soft resets. Use **Permanent EEPROM reset** with proper keys.

### Reads return no data

* Wrong EEPROM read password or wrong OIDs. Load a **WIC log** or try **Detect keys**.

### Writes fail

* Wrong write key, wrong address map, or blocked firmware. Verify community string; try a model‑specific preset. Power‑cycle and retry.

### ST2 empty or odd

* Not all models expose every tag. Still useful for serial and basic state.

---

## Safety, Warranty, and Ethics

* **Service first.** Ensure pads are replaced or a waste tank is installed before lowering counters.
* **At your own risk.** EEPROM writes can brick printers if misused.
* **Compliance is yours.** Know your local regulations and warranty terms.

---

## Contributing

Pull requests with **verified model maps**, **dividers**, and **decoded ST2 tags** are welcome. Please include logs and brief justification.

---

## Acknowledgements

* The open‑source Python ecosystem: **PySNMP**, **zeroconf**, **pyasn1**, **Tkinter**.
* Community research into EPSON‑CTRL OIDs and public log analysis that informed presets and address pairs.

---

## License

This project is released under the **MIT License**. See `LICENSE`.
