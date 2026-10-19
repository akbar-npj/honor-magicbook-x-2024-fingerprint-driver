#ifndef FPC_PROTOCOL_H
#define FPC_PROTOCOL_H

#include <stdint.h>

/* USB Hardware IDs */
#define FPC_USB_VID              0x10a5
#define FPC_USB_PID_ACER         0xe340  /* Acer Swift series (Swift Go, Swift 21) */
#define FPC_USB_PID_HONOR        0xa900  /* Honor MagicBook series (MagicBook X 14 & X 16 2024) */

/* USB Control Transfer bmRequestType */
#define FPC_REQTYPE_VENDOR_OUT   0x40  /* Host-to-Device | Vendor | Device */
#define FPC_REQTYPE_VENDOR_IN    0xc0  /* Device-to-Host | Vendor | Device */
#define FPC_REQTYPE_CLASS_OUT    0x21  /* Host-to-Device | Class | Interface (DFU) */
#define FPC_REQTYPE_CLASS_IN     0xa1  /* Device-to-Host | Class | Interface (DFU) */

/* Command Codes (bRequest) reverse-engineered from fpc_disum.dll */
enum fpc_cmd {
    CMD_INIT                     = 0x01,
    CMD_ARM                      = 0x02,
    CMD_ABORT                    = 0x03,
    CMD_BOOT0_REQ                = 0x04,
    CMD_TLS_INIT                 = 0x05,
    CMD_TLS_DATA                 = 0x06,
    CMD_INDICATE_S_STATE         = 0x08,
    CMD_GET_IMG                  = 0x09,
    CMD_GET_DEAD_PIXELS          = 0x0A,
    CMD_GET_TLS_KEY              = 0x0B,
    CMD_GET_KPI                  = 0x0C,
    CMD_SET_TLS_KEY              = 0x0D,
    CMD_FINISH_ENROLL            = 0x0E,
    CMD_FUSE_DEVICE              = 0x10,
    CMD_FINGERPRINT_SESSION_OFF  = 0x12,
    CMD_REFRESH_SENSOR           = 0x20,
    CMD_GET_FW_VERSION           = 0x30,
    CMD_GET_HW_UNIQUE_ID         = 0x31,
    CMD_FLUSH_KEYS               = 0x32,
    CMD_PASSTHRU_INT_CONTROL     = 0x40,
    CMD_PASSTHRU_CS_CONTROL      = 0x41,
    CMD_PASSTHRU_INT_VALUE_OUT   = 0x42,
    CMD_PASSTHRU_TO_SPI          = 0x43,
    CMD_PASSTHRU_FROM_SPI        = 0x44,
    CMD_PASSTHRU_INT_VALUE_IN    = 0x45,
    CMD_GET_MSOS                 = 0xAA,
    GET_STATE                    = 0x50,
};

/* Event Codes (received via Interrupt / Bulk IN packets) */
enum fpc_event {
    EVT_HELLO                    = 0x01,
    EVT_INIT_RESULT              = 0x02,
    EVT_ARM_RESULT               = 0x03,
    EVT_DEAD_PIXEL_REPORT        = 0x04,
    EVT_TLS                      = 0x05,
    EVT_FINGER_DWN               = 0x06,
    EVT_FINGER_UP                = 0x07,
    EVT_IMG                      = 0x08,
    EVT_USB_LOGS                 = 0x09,
    EVT_TLS_KEY                  = 0x0A,
    EVT_REFRESH_SENSOR           = 0x20,
};

/* DFU Standard & Vendor Command Codes */
enum fpc_dfu_cmd {
    DFU_DETACH                   = 0x00,
    DFU_DNLOAD                   = 0x01,
    DFU_UPLOAD                   = 0x02,
    DFU_GETSTATUS                = 0x03,
    DFU_CLRSTATUS                = 0x04,
    DFU_GETSTATE                 = 0x05,
    DFU_ABORT                    = 0x06,
    DFU_FPC_SETTINGS             = 0x07,
    DFU_FPC_KEYS                 = 0x08,
    DFU_FPC_GET_FW_STATUS        = 0x09,
    DFU_FPC_BOOT0                = 0x0A,
};

/* Endpoints */
#define FPC_EP_INTERRUPT_IN      0x81  /* e340 (Acer) */
#define FPC_EP_BULK_IN           0x82  /* a900 (Honor) */

/* Event framing: 12-byte header.  NOTE: the a900 (Honor) header is
 * big-endian and `length` includes the header itself; the e340 (Acer)
 * header is little-endian. */
#define FPC_EVENT_HDR_SIZE       12

/* a900 EVT_IMG payload: 12-byte image header + 11264 pixels = a 128x88
 * capacitive image (128 bytes per scan row), delivered verbatim on the
 * wire.  The sensor is ~250 dpi; NBIS/LFS is tuned for ~500 dpi, so the
 * driver 2x-upscales the frame before minutiae extraction (empirically:
 * 13 minutiae native vs 42 upscaled on the same press). */
#define FPC_IMG_HDR_SIZE         12
#define FPC_SENSOR_WIDTH         128
#define FPC_SENSOR_HEIGHT        88
#define FPC_IMAGE_BYTES          (FPC_SENSOR_WIDTH * FPC_SENSOR_HEIGHT) /* 11264 */
#define FPC_RIDGE_WIDTH          (FPC_SENSOR_WIDTH * 2)   /* 256 */
#define FPC_RIDGE_HEIGHT         (FPC_SENSOR_HEIGHT * 2)  /* 176 */

/* 4-byte session / capture ids exchanged with CMD_INIT / CMD_ARM. */
#define FPC_INIT_MAGIC           0x10, 0x2f, 0x11, 0x17
#define FPC_ARM_MAGIC            0x11, 0x2f, 0x11, 0x17
#define FPC_DISARM_MAGIC         0x12, 0x2f, 0x11, 0x17

/* TLS key derivation constants (NUL terminator included in the length). */
#define FPC_HMAC_KEY_STR         "FPC_HMAC_KEY"
#define FPC_HMAC_KEY_LEN         13
#define FPC_SEALING_KEY_STR      "FPC_SEALING_KEY"
#define FPC_SEALING_KEY_LEN      16

/* Event Packet Framing Header (a900 is big-endian on the wire) */
#pragma pack(push, 1)
struct fpc_packet_header {
    uint32_t event_id;   /* One of enum fpc_event */
    uint32_t length;     /* Total frame length incl. this header */
    uint32_t status;     /* Status / sequence / return code */
};

/* Blob returned by CMD_GET_TLS_KEY (little-endian offsets). */
struct fpc_tls_key {
    uint32_t magic;        /* 0x0dec0ded */
    uint32_t key_offset;
    uint32_t key_len;
    uint32_t aad_offset;
    uint32_t aad_len;
    uint32_t sig_offset;
    uint32_t sig_len;
};
#pragma pack(pop)

static inline const char *fpc_cmd_to_str(uint8_t cmd) {
    switch (cmd) {
        case CMD_INIT: return "CMD_INIT";
        case CMD_ARM: return "CMD_ARM";
        case CMD_ABORT: return "CMD_ABORT";
        case CMD_BOOT0_REQ: return "CMD_BOOT0_REQ";
        case CMD_TLS_INIT: return "CMD_TLS_INIT";
        case CMD_TLS_DATA: return "CMD_TLS_DATA";
        case CMD_INDICATE_S_STATE: return "CMD_INDICATE_S_STATE";
        case CMD_GET_IMG: return "CMD_GET_IMG";
        case CMD_GET_DEAD_PIXELS: return "CMD_GET_DEAD_PIXELS";
        case CMD_GET_TLS_KEY: return "CMD_GET_TLS_KEY";
        case CMD_GET_KPI: return "CMD_GET_KPI";
        case CMD_SET_TLS_KEY: return "CMD_SET_TLS_KEY";
        case CMD_FINISH_ENROLL: return "CMD_FINISH_ENROLL";
        case CMD_FUSE_DEVICE: return "CMD_FUSE_DEVICE";
        case CMD_FINGERPRINT_SESSION_OFF: return "CMD_FINGERPRINT_SESSION_OFF";
        case CMD_REFRESH_SENSOR: return "CMD_REFRESH_SENSOR";
        case CMD_GET_FW_VERSION: return "CMD_GET_FW_VERSION";
        case CMD_GET_HW_UNIQUE_ID: return "CMD_GET_HW_UNIQUE_ID";
        case CMD_FLUSH_KEYS: return "CMD_FLUSH_KEYS";
        case CMD_PASSTHRU_INT_CONTROL: return "CMD_PASSTHRU_INT_CONTROL";
        case CMD_PASSTHRU_CS_CONTROL: return "CMD_PASSTHRU_CS_CONTROL";
        case CMD_PASSTHRU_INT_VALUE_OUT: return "CMD_PASSTHRU_INT_VALUE_OUT";
        case CMD_PASSTHRU_TO_SPI: return "CMD_PASSTHRU_TO_SPI";
        case CMD_PASSTHRU_FROM_SPI: return "CMD_PASSTHRU_FROM_SPI";
        case CMD_PASSTHRU_INT_VALUE_IN: return "CMD_PASSTHRU_INT_VALUE_IN";
        case CMD_GET_MSOS: return "CMD_GET_MSOS";
        case GET_STATE: return "GET_STATE";
        default: return "UNKNOWN_CMD";
    }
}

static inline const char *fpc_event_to_str(uint32_t evt) {
    switch (evt) {
        case EVT_HELLO: return "EVT_HELLO";
        case EVT_INIT_RESULT: return "EVT_INIT_RESULT";
        case EVT_ARM_RESULT: return "EVT_ARM_RESULT";
        case EVT_DEAD_PIXEL_REPORT: return "EVT_DEAD_PIXEL_REPORT";
        case EVT_TLS: return "EVT_TLS";
        case EVT_FINGER_DWN: return "EVT_FINGER_DWN";
        case EVT_FINGER_UP: return "EVT_FINGER_UP";
        case EVT_IMG: return "EVT_IMG";
        case EVT_USB_LOGS: return "EVT_USB_LOGS";
        case EVT_TLS_KEY: return "EVT_TLS_KEY";
        case EVT_REFRESH_SENSOR: return "EVT_REFRESH_SENSOR";
        default: return "UNKNOWN_EVT";
    }
}

#endif /* FPC_PROTOCOL_H */
