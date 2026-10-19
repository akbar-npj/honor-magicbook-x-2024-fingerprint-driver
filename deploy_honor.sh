#!/usr/bin/env bash
#
# Deploy the updated fpc2040 driver + protocol header to the Honor laptop
# (10.240.74.242) and rebuild/install libfprint there.
#
# Prerequisites:
#   - passwordless SSH from this machine to shaan@10.240.74.242
#   - the libfprint source tree at ~/src/libfprint-v1.94.100 on the laptop,
#     with fpc2040 already registered in meson.build (drivers_info helper
#     openssl) and libfprint/meson.build.
#
# Usage:
#   ./deploy_honor.sh           # sync + ninja + meson install + ldconfig + restart fprintd
#   ./deploy_honor.sh nobuild   # only sync the two source files (no rebuild)

set -e

HONOR="shaan@10.240.74.242"
LIBFP="~/src/libfprint-v1.94.100"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${SCRIPT_DIR}/linux-driver"

echo "[*] Syncing fpc2040.c + fpc_protocol.h -> ${HONOR}:${LIBFP}/libfprint/drivers/"
ssh "$HONOR" "mkdir -p ${LIBFP}/libfprint/drivers"
rsync -az \
  "${SRC_DIR}/src/fpc2040.c" \
  "${SRC_DIR}/include/fpc_protocol.h" \
  "${HONOR}:${LIBFP}/libfprint/drivers/"

if [ "$1" = "nobuild" ]; then
  echo "[+] Sync done (nobuild requested)."
  exit 0
fi

echo "[*] Rebuilding + installing libfprint on ${HONOR}"
ssh "$HONOR" "set -e; cd ${LIBFP}; ninja -C build; sudo meson install -C build; sudo ldconfig; sudo systemctl restart fprintd 2>/dev/null || sudo service fprintd restart 2>/dev/null || true"
echo "[+] Deploy complete. Driver is now 128x88 native; re-enroll + verify to confirm the match."
