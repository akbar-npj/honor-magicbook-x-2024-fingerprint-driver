# FPC `10a5:a900` — Reverse-Engineering Guide (deep)

This is the **deep reverse-engineering write-up** for the Fingerprint Cards AB
(FPC) "Disum" sensor shipped in the **Honor MagicBook X 14 / X 16 (2024)**:
how the vendor Windows stack was taken apart, what the wire protocol actually
is, how the Linux driver is structured, and how each claim below was validated
against real hardware.

Everything here was verified live against USB `10a5:a900`, vendor package
`FPCFingerprint_Driver_22.26.2.29`, on Debian 13 (trixie) with libfprint
1.94.x.

> **Compilation & install live elsewhere.** How to *build* the capture tool and
> the libfprint driver, and how to *install* them (udev, fprintd, PAM, SDDM /
> GDM login-screen integration, KWallet) on Debian, Fedora and Arch is in the
> companion document **[`CROSS_DISTRO_BUILD_GUIDE.md`](./CROSS_DISTRO_BUILD_GUIDE.md)**.
> Read that one to build/run; read this one to understand the stack.

---

## 0. TL;DR

| Area | Result |
|---|---|
| USB transport | Vendor control transfers + bulk IN `0x82` |
| Event framing | Big-endian `{u32 code, u32 total_len, u32 status}`, `total_len` **includes** the 12-byte header |
| Session crypto | TLS 1.2 **PSK**, and the **host is the TLS server** |
| PSK derivation | HMAC-SHA256 verify + AES-256-CBC unseal, keys derived from ASCII literals |
| Image path | `EVT_IMG` = 12-byte image header + **11 264 bytes = 128×88**, verbatim |
| Matching | Match-on-**host**; libfprint `FpImageDevice` + NBIS/bozorth3 |
| Resolution trap | Sensor ≈250 dpi vs NBIS ≈500 dpi → **2× upscale** required |
| Live result | Enrol 5/5 stages (~45 s), then 4/4 consecutive `verify-match` |

The single most important finding: **there is no proprietary matcher and no
enclave in the loop on Linux.** The decrypted `EVT_IMG` payload already *is* a
usable ridge image. The entire difficulty is (a) getting through TLS with the
roles reversed, and (b) noticing that the image needs upscaling before NBIS can
find enough minutiae.

---

## 1. Hardware & software inventory

| Item | Value |
|---|---|
| USB VID:PID | `0x10a5:0xa900` (Hardware Revision `0229`) |
| Product | Fingerprint Cards Disum / Galileo Matrix |
| Hosts | Honor MagicBook X 14 & X 16 (2024) |
| Bulk IN endpoint | `0x82`, 64-byte MPS (auto-discovered from descriptors) |
| Raw contact frame | 128 × 88, 8-bit, 11 264 bytes |
| Frame handed to NBIS | 256 × 176 (2× bilinear), 11 264 → 45 056 bytes |
| Sensor pitch | ≈250 dpi (250 dpi ≈ 9.84 px/mm) |
| Vendor package | `FPCFingerprint_Driver_22.26.2.29` (`fpc_disum.dll`) |
| Windows PDB path | `C:\Jenkins\workspace\PC\DISUM\_Customer\Honor\Galileo\Honor-Galileo-DPL_driver\…` |
| Biometric architecture | Match-on-Host (MoH) |

Two sibling parts share the `10a5` vendor ID and are **not** interchangeable
with this driver's assumptions:

| Part | Differences |
|---|---|
| `10a5:e340` (Acer Swift) | Little-endian event header, interrupt IN `0x81`, host is TLS **client**, ridge-free payload needing an enclave reconstruction step |
| `10a5:a900` (this) | Big-endian header, bulk IN `0x82`, host is TLS **server**, payload is the image |

Do not port constants across without re-verifying. The endianness and TLS role
flip are the two that bite hardest.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ Applications / PAM / display manager                             │
│   fprintd  ←  pam_fprintd   (login, sudo, lock screen)           │
└───────────────────────────┬──────────────────────────────────────┘
                            │ D-Bus  net.reactivated.Fprint
┌───────────────────────────▼──────────────────────────────────────┐
│ libfprint 1.94.x                                                 │
│   driver: fpc2040  (generic FP_TYPE_IMAGE_DEVICE)                │
│     • USB control + bulk (GUsb)                                  │
│     • TLS 1.2 PSK **server**                                     │
│     • inner-event reassembly                                     │
│     • 2× upscale + ppmm                                         │
│     • NBIS/LFS minutiae + bozorth3 (in libfprint)                │
└───────────┬───────────────────────────────┬──────────────────────┘
            │ 11 264-byte 128×88 payload    │ FpPrint (minutiae)
            │ (after TLS decrypt)           │
┌───────────▼───────────────────────────────▼──────────────────────┐
│ USB 10a5:a900 — firmware 22.26.2.29                              │
│   streams raw capacitive frames; no on-chip templates            │
└──────────────────────────────────────────────────────────────────┘
```

Because the sensor is match-on-host, `fprintd` stores templates on disk and
libfprint does the matching. The driver therefore advertises
`CAPTURE | VERIFY | IDENTIFY` and deliberately **not** `FP_DEVICE_FEATURE_STORAGE`
— claiming device storage makes fprintd reject enrollments.

---

## 3. Reverse engineering

### 3.1 Target artifacts

The vendor package is a Windows driver bundle. The useful parts:

```
FPCFingerprint_Driver_22.26.2.29/
├── x64/fpc_disum.dll        ← the whole protocol lives here
├── x64/fpc_disum.sys        ← thin USB wrapper, little logic
├── …/fpc_disum.pdb          ← symbols (names only; private symbols stripped)
└── Firmware/                ← DFU images (not needed for capture)
```

`fpc_disum.dll` is the only artifact worth analysing: it contains the command
dispatcher, the event parser, the TLS glue, and the PSK unsealing. The `.sys`
file just moves bytes.

### 3.2 Tooling and workflow

The analysis was done with **REA MCP** driving **Ghidra 12.1.4**:

1. Import `fpc_disum.dll` (x86-64 PE, no packing, no anti-debug).
2. Let auto-analysis finish; the PDB path string in `.rdata` confirms the build.
3. Use `search_strings` for the protocol vocabulary — `"CMD_INIT"`,
   `"EVT_IMG"`, `"FPC_HMAC_KEY"`, `"FPC_SEALING_KEY"`, `"FPC TLS Keys"` — then
   `xrefs` to find the string→code tables. Those tables are how the numeric
   opcodes were recovered without guessing.
4. `procedure_pseudo_code` on the dispatcher and the event parser.
5. `build_call_path` from the TLS entry point to find the OpenSSL calls
   (`SSL_CTX_new`, `SSL_set_accept_state`, `SSL_CTX_set_psk_server_callback`),
   which is what revealed the reversed TLS roles.

The three tables recovered this way are reproduced verbatim in
`linux-driver/include/fpc_protocol.h` (`fpc_cmd_to_str`, `fpc_event_to_str`,
and the DFU table).

### 3.3 USB transport and command set

All commands are **vendor control transfers** on the device (not the interface):

| Direction | `bmRequestType` | Notes |
|---|---|---|
| Host → device | `0x40` | `wValue`/`wIndex` carry flags, data stage optional |
| Device → host | `0xc0` | data stage is the reply |

DFU (`0x21`/`0xa1`, class requests) is only used for firmware update and is
irrelevant to capture.

The commands the driver actually uses:

| Code | Name | Used for |
|---|---|---|
| `0x01` | `CMD_INIT` | open a session, 4-byte magic `10 2f 11 17` |
| `0x02` | `CMD_ARM` | enable finger detection, magic `11 2f 11 17` |
| `0x03` | `CMD_ABORT` | abandon a capture |
| `0x05` | `CMD_TLS_INIT` | tell the device to start the handshake |
| `0x08` | `CMD_INDICATE_S_STATE` | `wValue=0x0010`, put the sensor in "session" state |
| `0x09` | `CMD_GET_IMG` | request the frame after `EVT_FINGER_DWN` |
| `0x0B` | `CMD_GET_TLS_KEY` | fetch the sealed PSK blob |
| `0x50` | `GET_STATE` | 72-byte state block (best effort, failure not fatal) |

The full enum (including DFU, passthrough and fusing commands) is in
`fpc_protocol.h`; the unused ones are documented for completeness, not
implemented.

### 3.4 Event framing

Everything the device sends is one or more **12-byte-header** packets:

```c
struct fpc_packet_header {   /* big-endian on the wire for a900 */
    uint32_t event_id;       /* enum fpc_event */
    uint32_t length;         /* TOTAL length, including this 12-byte header */
    uint32_t status;
};
```

Two traps, both of which cost debugging time:

* **`length` includes the header.** A frame with `length == 11276` carries
  `11276 - 12 = 11264` payload bytes.
* **The device is big-endian here** even though the TLS-key blob (below) is
  little-endian. The driver reads the header with an explicit `fpc_be32()`
  rather than casting, precisely because the rest of the structure is LE.

Events observed on this firmware:

| Code | Name | Notes |
|---|---|---|
| `0x01` | `EVT_HELLO` | at enumeration |
| `0x02` | `EVT_INIT_RESULT` | 38 bytes after `CMD_INIT` |
| `0x03` | `EVT_ARM_RESULT` | after `CMD_ARM` |
| `0x05` | `EVT_TLS` | TLS record bytes (see 3.5) |
| `0x06` | `EVT_FINGER_DWN` | touch detected; driver then sends `CMD_GET_IMG` |
| `0x08` | `EVT_IMG` | 12-byte image header + 11 264 pixels |
| `0x0A` | `EVT_TLS_KEY` | key blob in some firmware paths |

**`EVT_FINGER_UP` (0x07) is never emitted by firmware 22.26.2.29.** The driver
treats the image as the end of the press and synthesises the "finger off"
transition itself. The firmware *also* re-sends `EVT_FINGER_DWN` roughly 250 ms
after the image of the same press, so the handler debounces anything inside a
700 ms window and ignores unsolicited images (`img_pending == FALSE`).

### 3.5 TLS-PSK, with the roles reversed

This is the part that differs most from the Acer sibling. On `a900` the
**device is the TLS client** and the **host is the TLS server**:

```c
SSL_CTX_set_min_proto_version (ctx, TLS1_2_VERSION);
SSL_CTX_set_max_proto_version (ctx, TLS1_2_VERSION);
SSL_CTX_set_psk_server_callback (ctx, fpc_psk_server_cb);
SSL_CTX_set_cipher_list (ctx,
    "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:"
    "PSK-AES128-CBC-SHA256:PSK-AES256-CBC-SHA384");
...
SSL_set_accept_state (ssl);          /* server, not client */
```

Because the host is the server, the host must **already know** the PSK before
the handshake starts — hence `CMD_GET_TLS_KEY` comes first, and the key blob is
read over a vendor control transfer, not over TLS.

The blob is a little-endian descriptor into itself:

```c
struct fpc_tls_key {
    uint32_t magic;        /* 0x0dec0ded */
    uint32_t key_offset;   /* sealed key   */
    uint32_t key_len;
    uint32_t aad_offset;   /* starts with "FPC TLS Keys" */
    uint32_t aad_len;
    uint32_t sig_offset;   /* HMAC-SHA256, 32 bytes */
    uint32_t sig_len;
};
```

Derivation, in order:

1. `hmac_key = SHA256("FPC_HMAC_KEY")` — the literal, **including** the NUL,
   hence `FPC_HMAC_KEY_LEN == 13`.
2. `mac = HMAC-SHA256(hmac_key, AAD ‖ sealed_key)`.
3. Reject unless `mac == sig[0..31]`. This is an integrity check, not a
   security boundary: the key material is on the host either way.
4. `sealing_key = SHA256("FPC_SEALING_KEY")` (literal length 16).
5. `psk = AES-256-CBC-decrypt(sealing_key, IV = all-zero, sealed_key)` with
   **padding disabled**.

The zero IV and the disabled padding are both deliberate; enabling PKCS#7
padding makes the last block fail to decrypt and the handshake abort with
`bad record mac` rather than anything informative.

`psk_len` lands at 32 bytes on this firmware.

### 3.6 Session state machine

```
Host (TLS server)                         Sensor (10a5:a900)
 |-- CMD_INDICATE_S_STATE, wValue 0x0010 -->|
 |-- GET_STATE (0x50) --------------------->|   72 bytes, best effort
 |<-----------------------------------------|
 |-- CMD_INIT (0x01) + 10 2f 11 17 -------->|
 |<-- EVT_INIT_RESULT (0x02), 38 bytes ------|
 |-- CMD_GET_TLS_KEY (0x0B) --------------->|
 |<-- sealed key blob -----------------------|
 |   (derive PSK locally)
 |-- CMD_TLS_INIT (0x05) ------------------->|
 |<-- EVT_TLS: ClientHello ------------------|
 |--- TLS-PSK handshake, host accepts ------>|
 |-- CMD_ARM (0x02) + 11 2f 11 17 --------->|
 |<-- EVT_ARM_RESULT (0x03) -----------------|
 |                                [touch]
 |<-- EVT_FINGER_DWN (0x06) -----------------|
 |-- CMD_GET_IMG (0x09) -------------------->|
 |<-- EVT_IMG (0x08), 12 + 11264 bytes ------|
 |   (2 s … 3 s cooldown)
 |-- CMD_ARM (0x02) ------------------------>|   re-arm for next touch
```

The handshake loop pumps OpenSSL against a memory BIO and feeds it only
`EVT_TLS` payloads; it gives up after 400 iterations or when a bulk read
times out.

**The sensor self-disables after every capture** — a hardware overheat guard,
not a protocol error. After the image the driver sleeps **3 s** and re-arms.
At 1 s the guard re-trips and enrollment stalls at stage 4 of 5; this is
reproducible and is the single most confusing symptom in the whole port.

### 3.7 The image, and how the geometry was actually proven

`EVT_IMG` payload layout:

```
offset 0    .. 11    image header (12 bytes; not interpreted by the driver)
offset 12   .. 11275 11 264 pixel bytes
```

The pixels are **already** a 128 × 88 image, 128 bytes per scan row, in
top-to-bottom order. No unpacking, no de-interleaving, no bit-plane
reconstruction, no enclave. This is the biggest difference from `e340`, where
the payload is ridge-free and needs a full reconstruction stage.

Getting here took a correction. The first port assumed 64 × 176 because that is
the `e340` geometry, and the driver produced `verify-no-match` on every attempt.
Small greyscale renders of the two candidate layouts look plausible either way,
so the question was settled **quantitatively** instead of by eye:

> Take the same 11 264 bytes. Generate every plausible reshape — 128×88
> verbatim, 64×176 with each half-width pair interleaved, the transpose of
> both, and the row-halves-stacked variants. Run the NBIS/LFS minutiae
> detector on each. Count minutiae.

Result:

| Layout | Minutiae |
|---|---|
| **128 × 88, verbatim** | **12** |
| 64 × 176 (any variant) | 2–5 |
| transpose / interleave / half-stack | 2–5 |

A factor of 2–6 is not ambiguous. 128 × 88 was correct; the failure had a
different cause (see 3.8). The general lesson is recorded in
`feedback_re_method.md` in the author's notes: **decide layout questions with a
numeric oracle over all candidates, never by inspecting a small render.**

### 3.8 The real cause of `verify-no-match`: dpi, not geometry

With 128 × 88 confirmed, the driver still failed to match. Instrumenting the
capture path showed `fpi_print_bz3_match()` scoring 0–7 and, on some presses,
libfprint reporting zero minutiae.

Root cause: this sensor is **≈250 dpi**. NBIS/LFS is tuned for **≈500 dpi** —
its Gabor filter bank and minutiae spacing assume roughly 10 px/mm. At native
resolution the detector finds 7–18 minutiae per press (13 on the reference
press), which is below the ~10–12 usable-after-filtering threshold bozorth3
needs.

Fix: 2× bilinear upscale before handing the frame to libfprint, and declare the
matching pitch:

```c
fpc_upscale2x (px, 128, 88, image->data, 256, 176);
image->ppmm = 19.685;    /* 500 dpi / 25.4 mm-per-inch */
```

`fp_image_new()` leaves `ppmm == 0`; NBIS reads it, so leaving it unset
silently degenerates the detector even after the upscale. Only `secugen.c` in
the libfprint tree sets it, which is why this is easy to miss.

Effect on the same press:

| | Minutiae | bozorth3 score |
|---|---|---|
| Native 128 × 88, ppmm 0 | 7–18 | 0–7 (intermittent) |
| 2× upscale, ppmm 19.685 | 41–71 | 15–30 |

`bz3_threshold` was then set to **15**, comfortably below the observed genuine
range without approaching the impostor range (impostor scores stay in single
digits on this sensor).

### 3.9 libfprint driver design

`fpc2040.c` is a `FP_TYPE_IMAGE_DEVICE`, not a custom `FP_TYPE_DEVICE`:

| Hook | Role |
|---|---|
| `img_open` / `img_close` | open the `GUsbDevice`, find bulk IN |
| `activate` | spawn a capture thread; run `fpc_session_start()` |
| `deactivate` | cancel, `fpc_session_stop()`, complete asynchronously |
| capture thread | read events, feed TLS, dispatch `fpc_handle_event()` |

Class configuration that matters:

```c
dev_class->id             = "fpc2040";
dev_class->type           = FP_DEVICE_TYPE_USB;
dev_class->nr_enroll_stages = 5;
dev_class->scan_type      = FP_SCAN_TYPE_PRESS;
dev_class->temp_hot_seconds = -1;   /* see below */
dev_class->features       = CAPTURE | VERIFY | IDENTIFY;
img_class->bz3_threshold  = 15;
```

* `temp_hot_seconds = -1` disables libfprint's **software** thermal guard. The
  sensor has its own hardware guard and resets the link; the software guard
  otherwise trips mid-enrollment and aborts with `FP_DEVICE_ERROR_TOO_HOT`.
* `FP_DEVICE_FEATURE_STORAGE` is deliberately absent: prints are host-side.
* `deactivate` must not block the main loop. The driver joins the capture
  thread via an atomic flag plus a `g_timeout_add()` poll, and uses a private
  `GCancellable` so cancellation does not race with libfprint's own.

`EVT_IMG` is delivered to libfprint as `fpi_image_device_image_captured()`,
followed by a synthetic finger-off status — queued in that order so libfprint
observes `capture → finger off`, which is what makes the 5-stage enrollment
advance.

### 3.10 Validation oracles

Every claim above is backed by one of these, all reproducible:

| Oracle | What it proves |
|---|---|
| `fpc_disum_tool` capture to PGM | transport, TLS, framing, geometry |
| Minutiae count across candidate reshapes | 128×88 is the true layout |
| Minutiae count before/after upscale | the dpi hypothesis |
| bozorth3 score logged by `fpi_print_bz3_match()` | threshold choice |
| Enroll 5/5 + 4/4 `verify-match` on hardware | end-to-end correctness |
| Verify with a different finger → `FPI_MATCH_FAIL` | not a rubber stamp |

---

## 4. Troubleshooting & gotchas

| Symptom | Cause | Fix |
|---|---|---|
| `verify-no-match` on every press | 64×176 assumption, or `ppmm == 0` | 128×88 verbatim; set `ppmm = 19.685` |
| Minutiae count 0 at runtime but 12 offline | frame not upscaled, or `ppmm` unset | 2× upscale + `ppmm` |
| Enrollment stalls at stage 4/5 | post-capture cooldown too short | raise to 3 s before re-arming |
| `FP_DEVICE_ERROR_TOO_HOT` mid-enroll | libfprint software thermal guard | `temp_hot_seconds = -1` |
| `bad record mac` in handshake | PKCS#7 padding left enabled | `EVP_CIPHER_CTX_set_padding(c, 0)` |
| Handshake timeout | host treated as TLS client | `SSL_set_accept_state()` + PSK **server** callback |
| `EVT_IMG` ignored | `img_pending` not set, or duplicate `EVT_FINGER_DWN` | send `CMD_GET_IMG` on first `EVT_FINGER_DWN`; debounce 700 ms |
| Image short by 12 bytes | `length` excludes header assumption | `length` **includes** the header |
| `AlreadyInUse` from fprintd | stale `fprintd-enroll` holding the claim | `pkill -x fprintd-enroll; systemctl restart fprintd` |
| `fprintd-list` → `PermissionDenied` | polkit `allow_active` and you are on SSH | run from a local session |
| Device not found after rebuild | udev rule / autosuspend | install rule, disable autosuspend, replug |

Two process notes that cost real time:

* `pkill -f "fprintd-enroll"` also matches your own SSH command line and kills
  the session. Use `pkill -x fprintd-enroll`.
* `journalctl | tail -n` in a pipe buffers until EOF, which hides live enroll
  progress. Read the journal without `tail` while a test runs.

---

## 5. File map

```
Honor Magicbook X 2024/
├── RE_GUIDE.md                     ← this document
├── CROSS_DISTRO_BUILD_GUIDE.md     ← build/install on Debian, Fedora, Arch
├── README.md                       ← findings summary + quickstart
├── build.sh                        ← automated build / udev install
├── deploy_honor.sh                 ← rsync driver into a libfprint tree + rebuild
└── linux-driver/
    ├── Makefile                    ← standalone capture tool
    ├── include/fpc_protocol.h      ← opcodes, events, framing, key constants
    ├── src/fpc_disum_tool.c        ← standalone CLI (no fprintd needed)
    ├── src/fpc2040.c               ← libfprint driver (1072 lines)
    └── udev/70-libfprint-2-fpc2040.rules
```

---

## 6. Status & roadmap

Working and validated on hardware:

- [x] Transport, framing, TLS-PSK with reversed roles
- [x] PSK derivation + signature check
- [x] 128×88 image extraction
- [x] 2× upscale + correct `ppmm`
- [x] Enroll (5/5), verify (`verify-match`), identify
- [x] fprintd, PAM, SDDM login screen, KDE lock screen, GDM login screen

Open / not attempted:

- [ ] Firmware update (DFU path is documented but unimplemented)
- [ ] `CMD_GET_DEAD_PIXELS` compensation
- [ ] Power management beyond the 3 s re-arm cooldown
- [ ] Finger-on-sensor detection without arming (not supported by firmware)
