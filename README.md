# Honor MagicBook X (2024) Fingerprint Sensor (`10a5:a900`) Linux Driver & Port

Linux driver, reverse-engineering findings, automated build toolchain, and standalone test utility for the **Fingerprint Cards AB (FPC)** sensor controller found on the **Honor MagicBook X 14 & X 16 (2024)** laptops.

### Hardware Identification:
| Property | Value |
| :--- | :--- |
| **Target Device** | Honor MagicBook X 14 & X 16 (2024) |
| **USB VID:PID** | `10a5:a900` (Hardware Rev `0229`) |
| **Sensor Controller** | Fingerprint Cards AB (FPC) Disum / Galileo Matrix |
| **Original Windows Driver** | `FPCFingerprint_22.26.2.29` / `22.26.2.25` (`fpc_disum.dll`) |
| **PDB Debug Symbol Path** | `C:\Jenkins\workspace\PC\DISUM\_Customer\Honor\Galileo\Honor-Galileo-DPL_driver\...` |
| **Biometric Architecture** | Match-on-Host (MoH) |

---

## 📑 Table of Contents
- [1. Quickstart: Automated Build (`build.sh`)](#1-quickstart-automated-build-buildsh)
- [2. Manual Compilation Instructions](#2-manual-compilation-instructions)
  - [Prerequisites](#prerequisites)
  - [Building with GNU Make](#building-with-gnu-make)
  - [Installing Udev Rules](#installing-udev-rules)
  - [Testing Fingerprint Capture](#testing-fingerprint-capture)
- [3. REA MCP Reverse-Engineering Findings](#3-rea-mcp-reverse-engineering-findings)
  - [Match-on-Host Architecture](#match-on-host-architecture)
  - [Decompiled Command Dispatcher (`FUN_180018c38`)](#decompiled-command-dispatcher-fun_180018c38)
  - [Decompiled Event Parser (`FUN_180018ea8`)](#decompiled-event-parser-fun_180018ea8)
  - [Decompiled DFU Protocol (`FUN_18000f4b0`)](#decompiled-dfu-protocol-fun_18000f4b0)
  - [Image Capture Workflow & Framing](#image-capture-workflow--framing)
- [4. Integrating into libfprint & System Authentication](#4-integrating-into-libfprint--system-authentication)
- [5. Repository Structure](#5-repository-structure)
- [6. License & Credits](#6-license--credits)

---

## 1. Quickstart: Automated Build (`build.sh`)

The repository includes a self-contained automated build and setup script [`build.sh`](file:///home/shaanair/Projects/FingerPrintSensors/Honor%20Magicbook%20X%202024/build.sh):

```bash
# 1. Compile the driver utility (automatically checks toolchain & headers)
./build.sh

# 2. Install udev permissions for non-root hardware access
sudo ./build.sh --install-udev

# 3. Test fingerprint capture
./fpc_disum_tool
```

### Available `build.sh` Options:
| Flag | Description |
| :--- | :--- |
| *(default)* | Validates dependencies and compiles `fpc_disum_tool`. |
| `--deps` | Automatically installs missing build packages using the system package manager (`dnf`, `apt`, `pacman`, `zypper`). |
| `--install-udev` | Copies the udev rule to `/etc/udev/rules.d/` and reloads `udevadm`. |
| `--all` | Runs dependency validation, compilation, and udev rule installation in one step. |
| `--clean` | Removes compiled binaries and captured test image frames. |
| `--help` | Displays script usage and instructions. |

---

## 2. Manual Compilation Instructions

### Prerequisites
Install development tools and `libusb-1.0` headers:

- **Fedora / RHEL / CentOS:**
  ```bash
  sudo dnf install gcc make libusb1-devel pkgconf-pkg-config
  ```
- **Ubuntu / Debian / Linux Mint:**
  ```bash
  sudo apt update && sudo apt install build-essential libusb-1.0-0-dev pkg-config
  ```
- **Arch Linux / Manjaro:**
  ```bash
  sudo pacman -S base-devel libusb pkgconf
  ```
- **openSUSE:**
  ```bash
  sudo zypper install gcc make libusb-1_0-devel pkg-config
  ```

### Building with GNU Make
```bash
cd linux-driver
make
```

### Installing Udev Rules
To communicate with the device without root (`sudo`):
```bash
sudo make install-udev
```

### Testing Fingerprint Capture
```bash
./fpc_disum_tool
```

Example session output:
```
=== FPC Disum sensor utility ===
[+] opened 10a5:a900
[+] bulk IN endpoint 0x82 (mps=64)
[+] sensor firmware 29.2.26.22
[+] init result: EVT_INIT_RESULT, 38 bytes
[+] TLS key signature verified
[+] PSK derived (32 bytes)
[*] TLS-PSK handshake (host is TLS server)...
[+] TLS handshake complete (TLSv1.2)
[*] sensor armed. Touch the sensor (Ctrl+C to stop).

[<] inner event EVT_FINGER_DWN (0x06), 0 bytes
>>> FINGER DETECTED <<<
[<] inner event EVT_IMG (0x08), 11276 bytes
[+] Saved honor_fingerprint_001.pgm (11264 bytes, 128x88)
```
The captured image is saved as a standard grayscale PGM: 11264 pixel bytes,
forming a 128×88 capacitive image (128 bytes per scan row), delivered
verbatim on the wire — no unpacking or de-interleaving required.

---

## 3. REA MCP Reverse-Engineering Findings

Using **REA MCP** backed by **Ghidra 12.1.4**, the Windows 11 driver (`fpc_disum.dll`) from `FPCFingerprint_22.26.2.29.exe` was analyzed:

### Match-on-Host Architecture
Unlike Match-on-Chip (MoC) hardware where biometric matching occurs within firmware flash, the Honor MagicBook X sensor operates in Match-on-Host mode:
- The controller streams raw capacitive image frames to the host OS.
- Frames are **not** sent in the clear: the session is wrapped in TLS-PSK. The host derives a 32-byte PSK from the sealed blob returned by `CMD_GET_TLS_KEY` (HMAC-SHA256 over `AAD‖sealed_key` with `sha256("FPC_HMAC_KEY")`, then AES-256-CBC unseal with `sha256("FPC_SEALING_KEY")`, zero IV, no padding).
- The roles are reversed compared with the Acer `e340`: on `a900` the **host is the TLS server** and the device is the client, so the host calls `SSL_set_accept_state()` and supplies the PSK from a server callback.
- On Linux, **libfprint** natively incorporates the NIST Biometric Image Software (NBIS) minutiae extraction and matching engine (`fpi_image_device`), removing the need for proprietary closed-source matching blobs.

### Decompiled Command Dispatcher (`FUN_180018c38`)
Decompiled from `fpc_disum.dll` via REA `procedure_pseudo_code`:

```c
char * FUN_180018c38(int param_1) {
  if (param_1 < 0x21) {
    if (param_1 == 0x20) return "CMD_REFRESH_SENSOR";
    if (param_1 < 10) {
      if (param_1 == 9) return "CMD_GET_IMG";
      if (param_1 == 1) return "CMD_INIT";
      if (param_1 == 2) return "CMD_ARM";
      if (param_1 == 3) return "CMD_ABORT";
      if (param_1 == 4) return "CMD_BOOT0_REQ";
      if (param_1 == 5) return "CMD_TLS_INIT";
      if (param_1 == 6) return "CMD_TLS_DATA";
      if (param_1 == 8) return "CMD_INDICATE_S_STATE";
    } else {
      if (param_1 == 10) return "CMD_GET_DEAD_PIXELS";
      if (param_1 == 0xb) return "CMD_GET_TLS_KEY";
      if (param_1 == 0xc) return "CMD_GET_KPI";
      if (param_1 == 0xd) return "CMD_SET_TLS_KEY";
      if (param_1 == 0xe) return "CMD_FINISH_ENROLL";
      if (param_1 == 0x10) return "CMD_FUSE_DEVICE";
      if (param_1 == 0x12) return "CMD_FINGERPRINT_SESSION_OFF";
    }
  } else if (param_1 < 0x43) {
    if (param_1 == 0x42) return "CMD_PASSTHRU_INT_VALUE_OUT";
    if (param_1 == 0x30) return "CMD_GET_FW_VERSION";
    if (param_1 == 0x31) return "CMD_GET_HW_UNIQUE_ID";
    if (param_1 == 0x32) return "CMD_FLUSH_KEYS";
    if (param_1 == 0x40) return "CMD_PASSTHRU_INT_CONTROL";
    if (param_1 == 0x41) return "CMD_PASSTHRU_CS_CONTROL";
  } else {
    if (param_1 == 0x43) return "CMD_PASSTHRU_TO_SPI";
    if (param_1 == 0x44) return "CMD_PASSTHRU_FROM_SPI";
    if (param_1 == 0x45) return "CMD_PASSTHRU_INT_VALUE_IN";
    if (param_1 == 0x50) return "GET_STATE";
    if (param_1 == 0xaa) return "CMD_GET_MSOS";
  }
  return "Unknown USB CMD.";
}
```

### Decompiled Event Parser (`FUN_180018ea8`)
Decompiled from the vendor driver's event-dispatch loop via REA `procedure_pseudo_code`
(the Windows driver polls endpoint `0x81`, but the device as enumerated on Linux
delivers the same events on bulk `0x82`):

```c
char * FUN_180018ea8(int param_1) {
  if (param_1 < 7) {
    if (param_1 == 6) return "EVT_FINGER_DWN";
    if (param_1 == 1) return "EVT_HELLO";
    if (param_1 == 2) return "EVT_INIT_RESULT";
    if (param_1 == 3) return "EVT_ARM_RESULT";
    if (param_1 == 4) return "EVT_DEAD_PIXEL_REPORT";
    if (param_1 == 5) return "EVT_TLS";
  } else {
    if (param_1 == 7) return "EVT_FINGER_UP";
    if (param_1 == 8) return "EVT_IMG";
    if (param_1 == 9) return "EVT_USB_LOGS";
    if (param_1 == 10) return "EVT_TLS_KEY";
    if (param_1 == 0x20) return "EVT_REFRESH_SENSOR";
  }
  return "Unknown USB EVT.";
}
```

### Decompiled DFU Protocol (`FUN_18000f4b0`)
```c
char * FUN_18000f4b0(int param_1) {
  if (param_1 < 6) {
    if (param_1 == 5) return "DFU_GETSTATE";
    if (param_1 == 0) return "DFU_DETACH";
    if (param_1 == 1) return "DFU_DNLOAD";
    if (param_1 == 2) return "DFU_UPLOAD";
    if (param_1 == 3) return "DFU_GETSTATUS";
    if (param_1 == 4) return "DFU_CLRSTATUS";
  } else {
    if (param_1 == 6) return "DFU_ABORT";
    if (param_1 == 7) return "DFU_FPC_SETTINGS";
    if (param_1 == 8) return "DFU_FPC_KEYS";
    if (param_1 == 9) return "DFU_FPC_GET_FW_STATUS";
    if (param_1 == 10) return "DFU_FPC_BOOT0";
  }
  return "UNKNOWN";
}
```

### Image Capture Workflow & Framing
```
Host (TLS server)                Sensor (10a5:a900)
 |-- CMD_INDICATE_S_STATE (0x08), val 0x0010 -->|
 |-- GET_STATE (0x50) ------------------------>|
 |<-- 72-byte state block ---------------------|
 |-- CMD_INIT (0x01) + 10 2f 11 17 ---------->|
 |<-- EVT_INIT_RESULT (0x02), 38 bytes --------|
 |-- CMD_GET_TLS_KEY (0x0B) ------------------>|
 |<-- sealed PSK blob -------------------------|
 |-- CMD_TLS_INIT (0x05) --------------------->|
 |<-- EVT_TLS: ClientHello --------------------|
 |--- TLS-PSK handshake (host accepts) ------->|
 |-- CMD_ARM (0x02) + 11 2f 11 17 ----------->|
 |<-- EVT_ARM_RESULT (0x03) -------------------|
 |                               |  [User touches sensor]
 |<-- EVT_FINGER_DWN (0x06) -------------------|
 |-- CMD_GET_IMG (0x09) ---------------------->|
 |<-- EVT_IMG (0x08) --------------------------|  [12-byte image header + 11264 px]
```

The `EVT_IMG` payload begins with a **12-byte image header**, followed by 11264
8-bit grayscale pixels that form a **128×88** capacitive ridge image, copied
verbatim (no unpacking required).

**Sensor resolution and NBIS scaling:** the sensor runs at ~250 dpi, but
libfprint's NBIS/LFS minutiae detector is tuned for ~500 dpi.  At native
resolution only 7–18 minutiae are found per press (bozorth3 genuine-match
scores 5–7 — too marginal to match reliably).  The driver therefore 2×
bilinear-upscales each frame to 256×176 (ppmm = 19.685) before handing it to
libfprint, which yields 41–71 minutiae per press and genuine-match scores of
15–30 (`bz3_threshold = 15`).  Verified live: enroll 5/5 stages, then 4/4
consecutive `verify-match`.

All event headers are **big-endian** `{u32 code, u32 total_len, u32 status}`,
where `total_len` includes the 12-byte header. Note that firmware 22.26.2.29
does **not** emit `EVT_FINGER_UP`; the driver treats the image as the end of the
press (and debounces the duplicate `EVT_FINGER_DWN` the firmware re-sends).

---

## 4. Integrating into libfprint & System Authentication

The driver [`linux-driver/src/fpc2040.c`](file:///home/shaanair/Projects/FingerPrintSensors/Honor%20Magicbook%20X%202024/linux-driver/src/fpc2040.c) contains native `id_table` support for `10a5:a900`:

1. **Clone `libfprint`:**
   ```bash
   git clone https://gitlab.freedesktop.org/libfprint/libfprint.git
   cd libfprint
   ```

2. **Copy the Driver Source:**
   ```bash
   cp /path/to/linux-driver/src/fpc2040.c libfprint/drivers/
   cp /path/to/linux-driver/include/fpc_protocol.h libfprint/drivers/
   ```

3. **Register the driver in `meson.build`** (both files, plus the OpenSSL helper):
   ```meson
   # top-level meson.build, in drivers_info:
   'fpc2040': { 'helper': ['openssl'] },

   # libfprint/meson.build, in driver_sources:
   'fpc2040' : files('drivers/fpc2040.c'),
   ```

4. **Build and Install:**
   ```bash
   meson setup builddir -Ddrivers=all
   ninja -C builddir
   sudo ninja -C builddir install
   sudo ldconfig
   ```

   Verify the ID table was picked up:
   ```bash
   ./builddir/libfprint/fprint-list-supported-devices | grep 10a5
   # 10a5:a900 | Fingerprint Cards Disum (Honor MagicBook X)
   ```

5. **Restart `fprintd` and Enroll:**
   ```bash
   sudo systemctl restart fprintd
   fprintd-enroll
   ```

6. **Enable PAM Authentication:**
   - On Fedora / RHEL:
     ```bash
     sudo authselect enable-feature with-fingerprint
     ```
   - On Ubuntu / Debian:
     ```bash
     sudo pam-auth-update
     ```

---

## 5. Repository Structure

```
├── build.sh                                # Automated build & dependency installer
├── README.md                               # Complete findings & setup guide
├── Readme.txt                              # Original driver notes
├── linux-driver/
│   ├── build.sh                            # Local build script
│   ├── Makefile                            # GNU Makefile
│   ├── include/
│   │   └── fpc_protocol.h                  # Protocol constants, opcodes, structures
│   ├── src/
│   │   ├── fpc_disum_tool.c                # Standalone test CLI application
│   │   └── fpc2040.c                       # Native libfprint driver
│   └── udev/
│       └── 70-libfprint-2-fpc2040.rules    # Hardware udev permissions
└── FPCFingerprint_Driver_22.26.2.29/       # Extracted vendor Windows driver package
```

---

## 6. License & Credits

- Reverse-engineered using **REA** and **Ghidra 12.1.4**.
- Standalone test tool & protocol definitions: MIT License.
- `libfprint` driver implementation: LGPL-2.1-or-later.
