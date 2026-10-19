# FPC `10a5:a900` — Cross-Distro Compilation & Install Guide (Debian · Fedora · Arch)

How to build the Honor MagicBook X (2024) fingerprint driver and wire it into
system authentication on **Debian/Ubuntu**, **Fedora**, and **Arch Linux** —
including the login screen, the KDE lock screen, and the KWallet consequences
of biometric login.

> **Reverse engineering lives elsewhere.** Why the protocol looks the way it
> does, how the geometry and dpi were proven, and what each constant means is
> in the companion document **[`RE_GUIDE.md`](./RE_GUIDE.md)**. Read that one to
> understand the stack; read this one to build and run it.

---

## 0. TL;DR

```bash
# 1. standalone capture tool (no fprintd, no libfprint)
cd linux-driver && make && sudo make install-udev && ./fpc_disum_tool

# 2. libfprint with the driver
git clone https://gitlab.freedesktop.org/libfprint/libfprint.git ~/src/libfprint
cp src/fpc2040.c include/fpc_protocol.h ~/src/libfprint/libfprint/drivers/
#    register it in BOTH meson.build files (section 4), then:
meson setup ~/src/libfprint/build ~/src/libfprint -Ddrivers=all
ninja -C ~/src/libfprint/build && sudo ninja -C ~/src/libfprint/build install
sudo ldconfig && sudo systemctl restart fprintd

# 3. enrol from a LOCAL session (not SSH)
fprintd-enroll -f right-index-finger
```

Then integrate with the display manager (section 7) and deal with KWallet
(section 8) — that last one is not optional if you log in with a finger.

---

## 1. What you are building

Three independent pieces, in dependency order:

| # | Component | Depends on | Purpose |
|---|---|---|---|
| 1 | `fpc_disum_tool` | libusb only | Capture a PGM straight off the sensor. Proves the transport works before libfprint is involved. |
| 2 | `fpc2040` driver | libfprint + OpenSSL | The actual `FpImageDevice`. |
| 3 | PAM/fprintd wiring | `fprintd` | Makes login, sudo and the lock screen use the sensor. |

Do them in that order. If step 1 fails, nothing above it can work, and
debugging is far easier without fprintd in the picture.

---

## 2. Prerequisites (per distro)

### Debian 13 / Ubuntu 24.04+

```bash
sudo apt update
sudo apt install -y build-essential meson ninja-build pkg-config git \
    libusb-1.0-0-dev libglib2.0-dev libgusb-dev libssl-dev \
    fprintd libpam-fprintd
```

For the full libfprint dependency set (pixman, nss, gudev, …) the reliable
route is:

```bash
sudo apt build-dep libfprint-2-2     # needs deb-src lines in sources.list
```

### Fedora 40+

```bash
sudo dnf install -y gcc gcc-c++ make meson ninja-build pkgconf-pkg-config git \
    libusb1-devel glib2-devel libgusb-devel openssl-devel \
    fprintd fprintd-pam
sudo dnf builddep libfprint        # pulls the rest
```

### Arch Linux

```bash
sudo pacman -S --needed base-devel meson ninja pkgconf git \
    libusb glib2 libgusb openssl fprintd
```

Arch ships libfprint's dependencies as part of the `libfprint` package; if you
prefer to build against the packaged version's exact deps:

```bash
sudo pacman -S --needed --asdeps $(pacman -Si libfprint | awk -F': ' '/^Depends On/{print $2}' | tr ' ' '\n')
```

---

## 3. Standalone capture tool

This links only against libusb and talks the protocol directly. Use it to
confirm the sensor, the TLS handshake and the image geometry before touching
libfprint.

```bash
cd linux-driver
make
sudo make install-udev          # udev rule, so no root needed afterwards
./fpc_disum_tool
```

Expected output:

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

If you get here, the hard part is done. A 11264-byte 128×88 PGM is the proof.

The repository root also has `build.sh`, which wraps the above and can install
dependencies itself:

```bash
./build.sh              # check deps + build
./build.sh --deps       # install deps via dnf/apt/pacman/zypper, then build
sudo ./build.sh --all   # build + install udev rule
```

---

## 4. Building libfprint with the driver

The driver is not upstream, so libfprint must be built from source with
`fpc2040` registered. Any 1.94.x tree works.

```bash
git clone https://gitlab.freedesktop.org/libfprint/libfprint.git ~/src/libfprint
cd ~/src/libfprint

cp "/path/to/Honor Magicbook X 2024/linux-driver/src/fpc2040.c"        libfprint/drivers/
cp "/path/to/Honor Magicbook X 2024/linux-driver/include/fpc_protocol.h" libfprint/drivers/
```

### 4.1 Register the OpenSSL helper

In the **top-level** `meson.build`, inside `drivers_info`:

```meson
drivers_info = {
  ...
  'fpc2040': { 'helper': ['openssl'] },
}
```

This is what makes Meson add `-lssl -lcrypto` and run the OpenSSL dependency
check for this driver only.

### 4.2 Register the driver source

In `libfprint/meson.build`, inside `driver_sources`:

```meson
driver_sources = {
  ...
  'fpc2040' : files('drivers/fpc2040.c'),
}
```

### 4.3 Configure and build

```bash
meson setup build -Ddrivers=all --prefix=/usr --libdir=lib/x86_64-linux-gnu
ninja -C build
sudo ninja -C build install
sudo ldconfig
```

Use `--libdir=lib64` on Fedora and `--libdir=lib` on Arch (see the matrix in
section 5.1). On Debian the multiarch path is `lib/x86_64-linux-gnu`.

Verify the ID table was compiled in:

```bash
./build/libfprint/fprint-list-supported-devices | grep 10a5
# 10a5:a900 | Fingerprint Cards Disum (Honor MagicBook X)
```

If that line is missing, the driver was not registered in `driver_sources` —
`-Ddrivers=all` only builds what the map contains.

---

## 5. System install

### 5.1 Library install path matrix

| Distro | `--libdir` | Resulting library |
|---|---|---|
| Debian / Ubuntu | `lib/x86_64-linux-gnu` | `/usr/lib/x86_64-linux-gnu/libfprint-2.so.2` |
| Fedora | `lib64` | `/usr/lib64/libfprint-2.so.2` |
| Arch | `lib` | `/usr/lib/libfprint-2.so.2` |

Installing over the distribution's copy is intentional: `fprintd` links against
the system library, and a copy in `/usr/local` will not be picked up without
`LD_LIBRARY_PATH`, which systemd services do not inherit.

Confirm which library is actually loaded:

```bash
ldd /usr/libexec/fprintd | grep fprint    # Debian, Fedora
ldd /usr/lib/fprintd     | grep fprint    # Arch
```

### 5.2 udev rule

```bash
sudo cp linux-driver/udev/70-libfprint-2-fpc2040.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

The rule uses `TAG+="uaccess"`, which is what grants the logged-in seat access
on all three distros. `GROUP="plugdev"` in the same line is Debian-specific and
harmless elsewhere (the group simply does not exist on Fedora/Arch).

### 5.3 Disable USB autosuspend

Without this the device can fail to re-open after a suspend or an idle period,
producing "device not found" on the next `fprintd-enroll`.

```bash
# /etc/udev/rules.d/71-fpc2040-no-autosuspend.rules
ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="10a5", ATTR{idProduct}=="a900", \
    ATTR{power/control}="on"
```

```bash
sudo udevadm control --reload-rules && sudo udevadm trigger
```

---

## 6. fprintd and enrollment

```bash
sudo systemctl enable --now fprintd
sudo systemctl restart fprintd

fprintd-list "$USER"                 # should list the device
fprintd-enroll -f right-index-finger
fprintd-verify -f right-index-finger
```

Two rules that are easy to trip over:

* **Enrol from a local session, never over SSH.** The fprintd polkit policy for
  `net.reactivated.fprint.device.verify` is `allow_active=yes`,
  `allow_inactive=no`, `allow_any=no`. An SSH session is *inactive*, so every
  call fails with `PermissionDenied`. This is not a driver problem.
* **Kill stale enrolls before retrying.** A hung `fprintd-enroll` keeps the
  device claimed and the next attempt fails with `AlreadyInUse`:

  ```bash
  pkill -x fprintd-enroll      # NOT pkill -f; -f matches your own ssh command
  sudo systemctl restart fprintd
  ```

Enrollment takes about 45 s for 5 stages. If it stalls at stage 4, the sensor's
overheat guard tripped — see `RE_GUIDE.md` §4 (the driver's post-capture
cooldown must be 3 s).

---

## 7. Login screen and lock screen

`fprintd` alone only makes the sensor available to *applications*. The display
manager needs `pam_fprintd` in its own PAM stack.

### 7.1 KDE lock screen — nothing to do

Plasma 6 ships `/usr/lib/pam.d/kde-fingerprint` containing
`auth required pam_fprintd.so`, and `kde` includes it. If unlock-with-finger
works in a terminal, it works on the lock screen.

### 7.2 GDM — nothing to do

GDM ships a **dedicated** fingerprint service:

```
$ cat /etc/pam.d/gdm-fingerprint
auth    requisite  pam_nologin.so
auth    required   pam_succeed_if.so user != root quiet_success
auth    required   pam_fprintd.so
...
```

No `common-auth`, no password step. gnome-shell also talks to fprintd over
D-Bus directly (it ships `net.reactivated.Fprint.Manager.xml`), so the scan
starts as soon as you select your user — **no Enter required**. Enable/disable
with:

```bash
gsettings get  org.gnome.login-screen enable-fingerprint-authentication   # default true
```

If you switch a KDE machine to GDM, also add `pam_kwallet5` to
`/etc/pam.d/gdm-password`, otherwise even *password* logins stop unlocking the
wallet:

```
auth    optional        pam_gnome_keyring.so
-auth   optional        pam_kwallet5.so
...
session optional        pam_gnome_keyring.so auto_start
-session optional       pam_kwallet5.so auto_start
```

### 7.3 SDDM — the `pam_deny` trap

The obvious edit does **not** work:

```
@include common-auth
auth sufficient pam_fprintd.so        # ← never reached
```

Debian's `common-auth` ends with `auth requisite pam_deny.so`, and a requisite
failure aborts the whole stack. `pam_fprintd` is never executed. The stack has
to be inlined, with the fingerprint between `pam_unix` and `pam_deny`:

```
# /etc/pam.d/sddm
auth    requisite       pam_nologin.so
auth    required        pam_succeed_if.so user != root quiet_success

# inlined common-auth + pam_fprintd
auth    [success=2 default=ignore]      pam_unix.so nullok
auth    [success=1 default=ignore]      pam_fprintd.so max-tries=3 timeout=10
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
```

Jump offsets: `pam_unix` success skips **2** (the fingerprint module *and*
`pam_deny`); `pam_fprintd` success skips **1** (just `pam_deny`). A correct
password therefore logs in instantly, and an empty submit falls through to the
sensor.

Because SDDM has no native fingerprint integration, the user has to submit the
form once — click the user tile, then press Enter with the password field
empty. Add a visible prompt to the theme so this is discoverable; in
`/usr/share/sddm/themes/<theme>/Main.qml`, inside the existing
`Connections { target: sddm }` block:

```qml
function onInformationMessage(message) {
    if (message) {
        notificationResetTimer.interval = 12000   // matches pam_fprintd timeout
        notificationMessage = message
    }
}
function onLoginFailed() {
    notificationResetTimer.interval = 3000
    ...
}
```

`sddm` is the `GreeterProxy`, which emits `informationMessage` when
`sddm-helper` forwards a `PAM_TEXT_INFO` — that is how
"Place your right index finger on the fingerprint reader" reaches the screen.

### 7.4 Fedora (any DM)

Fedora centralises this in `system-auth`:

```bash
sudo authselect enable-feature with-fingerprint
sudo authselect apply-changes
```

This adds `pam_fprintd` to `system-auth`, which every service includes — so it
affects `sudo`, `su` and TTY logins as well. If you only want it for the
display manager, edit `/etc/pam.d/<dm>` directly instead, following §7.3.

### 7.5 Arch

Arch has no `pam-auth-update`; edit the stack by hand:

```
# /etc/pam.d/system-auth
auth      [success=3 default=ignore]  pam_unix.so nullok try_first_pass
auth      [success=2 default=ignore]  pam_fprintd.so
auth      [success=1 default=ignore]  pam_sss.so use_first_pass   # if present
auth      requisite                   pam_deny.so
auth      required                    pam_permit.so
```

Recount the jump offsets for your actual file — they depend on how many lines
follow `pam_unix`. Same rule as §7.3: fingerprint goes *before* `pam_deny`.

---

## 8. KWallet, Wi-Fi, and what fingerprint login cannot do

**This section matters as soon as you actually log in with a finger.**

### 8.1 Why the wallet asks

`pam_kwallet5` works by capturing your password during PAM authentication
(`pam_sm_authenticate` stashes `PAM_AUTHTOK`) and replaying it at session open
to unlock the wallet. Fingerprint authentication produces **no password at
all** — `pam_fprintd` never sets `PAM_AUTHTOK` — so the wallet stays closed and
KWallet prompts the first time anything needs a secret.

With password login the wallet unlocks silently, so nothing asks. With
fingerprint login it asks. This is not a driver bug and not fixable by
configuration: a KWallet key is derived from a password, and there is no
password.

Typical first victim is Wi-Fi:

```bash
nmcli -f connection.id,802-11-wireless-security.psk-flags connection show "MyWiFi"
# 802-11-wireless-security.psk-flags:     1 (agent-owned)
```

`1 (agent-owned)` means the WPA passphrase is stored **in KWallet**, so
NetworkManager has to ask the wallet — which is locked.

### 8.2 Fix the Wi-Fi prompt (recommended)

Move the PSK into the system connection file, which is root-owned and mode
0600, so NetworkManager never consults the wallet:

```bash
sudo nmcli connection modify "MyWiFi" wifi-sec.psk 'YOUR_WIFI_PASSWORD'
sudo nmcli connection modify "MyWiFi" wifi-sec.psk-flags 0
sudo nmcli connection up "MyWiFi"
```

Or in Plasma: connection editor → **Wi-Fi Security** → tick
**"Store password for all users (not encrypted)"**.

Repeat for every SSID you use. `psk-flags 0` is system-owned; `1` is
agent-owned (wallet); `2` is not-saved; `4` is not-required.

### 8.3 Everything else in the wallet

After moving Wi-Fi out, any remaining secret (browser logins, app passwords)
still triggers **one** KWallet prompt per fingerprint session. Options:

| Option | Trade-off |
|---|---|
| Type the wallet password once per session | Safe; one prompt |
| Give the wallet an empty password | Auto-unlocks for anyone with the file — not recommended |
| Use password login when you need the wallet | Defeats the point |

KWallet cannot be unlocked biometrically, on any distro. Plan around it rather
than trying to fix it.

### 8.4 If your DM is GDM

GDM's `gdm-password` stack contains `pam_gnome_keyring` but **not**
`pam_kwallet5`. Without the addition shown in §7.2, even password logins stop
auto-unlocking the wallet — a regression compared to SDDM. The fingerprint path
(`gdm-fingerprint`) has no password to pass on, so §8.1 applies unchanged.

---

## 9. Verify end-to-end

```bash
# 1. device visible to fprintd
fprintd-list "$USER"

# 2. capture works at all (bypasses libfprint entirely)
./linux-driver/fpc_disum_tool

# 3. driver picked up by libfprint
fprint-list-supported-devices | grep 10a5

# 4. enroll + verify
fprintd-enroll -f right-index-finger
fprintd-verify -f right-index-finger          # expect verify-match

# 5. impostor check — a different finger must fail
fprintd-verify -f left-index-finger           # expect verify-no-match

# 6. desktop paths
#    lock screen  : touch the sensor, no click needed
#    login screen : SDDM -> Enter on empty field; GDM -> just touch
```

Expected bozorth3 scores for a genuine press: **15–30**. Scores in the single
digits mean the frame is not being upscaled or `ppmm` is unset — see
`RE_GUIDE.md` §3.8.

---

## 10. Surviving distribution updates

A distro `libfprint` upgrade replaces `/usr/lib*/libfprint-2.so.2` and the
driver disappears.

```bash
# Debian: re-install after any libfprint upgrade
sudo apt-mark hold libfprint-2-2            # optional: stop the upgrade entirely
sudo ninja -C ~/src/libfprint/build install && sudo ldconfig

# Fedora
sudo dnf versionlock add libfprint          # optional
sudo ninja -C ~/src/libfprint/build install && sudo ldconfig

# Arch: same, and add IgnorePkg if you prefer
sudo ninja -C ~/src/libfprint/build install && sudo ldconfig
```

A post-upgrade hook keeps it automatic:

```
# /etc/pacman.d/hooks/99-libfprint-fpc2040.hook   (Arch)
[Trigger]
Operation = Upgrade
Type = Package
Target = libfprint

[Action]
Description = Reinstalling fpc2040-enabled libfprint
When = PostTransaction
Exec = /usr/bin/ninja -C /home/USER/src/libfprint/build install
```

Debian/Fedora equivalents are `DPkg::Post-Invoke` and a `%post` file trigger;
both are more fragile than simply re-running `ninja install`.

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `fprint-list-supported-devices` has no `10a5:a900` | driver not in `driver_sources` | §4.2, rebuild |
| `fprintd-list` → `PermissionDenied` | SSH session is inactive for polkit | run locally |
| `AlreadyInUse` | stale enroll holds the claim | `pkill -x fprintd-enroll`, restart fprintd |
| `verify-no-match` always | upscale/ppmm missing | §3.8 of `RE_GUIDE.md` |
| Enrollment stalls at stage 4/5 | 1 s cooldown instead of 3 s | raise the `g_usleep` before re-arm |
| `FP_DEVICE_ERROR_TOO_HOT` | libfprint software thermal guard | `temp_hot_seconds = -1` |
| Device vanishes after suspend | USB autosuspend | §5.3 |
| Login screen accepts password but no scan | `pam_fprintd` after `pam_deny` | §7.3 |
| Login screen waits 10 s then asks for password | `pam_fprintd` **before** `pam_unix` | reorder, §7.3 |
| Wallet prompt after fingerprint login | no `PAM_AUTHTOK` | §8 |
| `bad record mac` at handshake | PKCS#7 padding enabled | disable padding in PSK unseal |

---

## 12. File map

```
Honor Magicbook X 2024/
├── RE_GUIDE.md                     ← protocol/RE deep dive
├── CROSS_DISTRO_BUILD_GUIDE.md     ← this document
├── README.md                       ← findings summary + quickstart
├── build.sh                        ← dependency install + build + udev
├── deploy_honor.sh                 ← rsync driver into a libfprint tree, rebuild
└── linux-driver/
    ├── Makefile
    ├── build.sh
    ├── include/fpc_protocol.h
    ├── src/fpc_disum_tool.c        ← standalone capture (libusb only)
    ├── src/fpc2040.c               ← libfprint driver
    └── udev/70-libfprint-2-fpc2040.rules
```

---

## 13. References

- libfprint: <https://gitlab.freedesktop.org/libfprint/libfprint>
- fprintd: <https://gitlab.freedesktop.org/libfprint/fprintd>
- NBIS / bozorth3 (via libfprint's `nbis/`): minutiae + matching
- GNOME fingerprint login setting:
  `org.gnome.login-screen enable-fingerprint-authentication`
- fprintd polkit policy: `/usr/share/polkit-1/actions/net.reactivated.fprint.device.policy`
