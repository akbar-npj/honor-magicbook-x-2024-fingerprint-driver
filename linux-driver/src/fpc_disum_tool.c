/*
 * FPC Sensor Controller (10a5:a900 / 10a5:e340) Linux Driver Utility
 * Reverse-engineered from Honor MagicBook & Acer Windows drivers (fpc_disum.dll) using REA & Ghidra.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <libusb-1.0/libusb.h>

#include "fpc_protocol.h"

static volatile int running = 1;
static libusb_device_handle *devh = NULL;
static uint16_t matched_pid = 0;
static int capture_count = 0;

static void sigint_handler(int signum) {
    (void)signum;
    running = 0;
}

/* Helper to send vendor control request (Host -> Device OUT) */
static int fpc_send_vendor_cmd(libusb_device_handle *handle, uint8_t cmd, uint16_t value, uint16_t index,
                               const uint8_t *data, uint16_t length) {
    int ret = libusb_control_transfer(
        handle,
        FPC_REQTYPE_VENDOR_OUT,
        cmd,
        value,
        index,
        (unsigned char *)data,
        length,
        2000 /* timeout ms */
    );
    if (ret < 0) {
        fprintf(stderr, "[-] Control transfer for %s (0x%02x) failed: %s\n",
                fpc_cmd_to_str(cmd), cmd, libusb_error_name(ret));
        return ret;
    }
    printf("[+] Sent %s (0x%02x), val=0x%04x, idx=0x%04x, len=%u\n",
           fpc_cmd_to_str(cmd), cmd, value, index, length);
    return 0;
}

/* Helper to receive vendor control request (Device -> Host IN) */
static int fpc_recv_vendor_cmd(libusb_device_handle *handle, uint8_t cmd, uint16_t value, uint16_t index,
                               uint8_t *data, uint16_t length) {
    int ret = libusb_control_transfer(
        handle,
        FPC_REQTYPE_VENDOR_IN,
        cmd,
        value,
        index,
        (unsigned char *)data,
        length,
        2000 /* timeout ms */
    );
    if (ret < 0) {
        fprintf(stderr, "[-] Read control transfer for %s (0x%02x) failed: %s\n",
                fpc_cmd_to_str(cmd), cmd, libusb_error_name(ret));
        return ret;
    }
    return ret;
}

/* Save raw image buffer as PGM (Portable Graymap) */
static void save_pgm(const uint8_t *img_data, size_t size, int frame_num) {
    char filename[64];
    const char *prefix = (matched_pid == FPC_USB_PID_HONOR) ? "honor" :
                         (matched_pid == FPC_USB_PID_ACER) ? "acer" : "fpc";
    snprintf(filename, sizeof(filename), "%s_fingerprint_%03d.pgm", prefix, frame_num);

    int width = 160;
    int height = 160;
    if (size == 160 * 160) {
        width = 160;
        height = 160;
    } else if (size == 192 * 192) {
        width = 192;
        height = 192;
    } else if (size > 0) {
        width = 160;
        height = (int)(size / width);
    }

    FILE *f = fopen(filename, "wb");
    if (!f) {
        perror("[-] Failed to open output PGM file");
        return;
    }
    fprintf(f, "P5\n%d %d\n255\n", width, height);
    fwrite(img_data, 1, size, f);
    fclose(f);
    printf("[*] Saved image to %s (%zu bytes, %dx%d)\n", filename, size, width, height);
}

/* Parse and handle an incoming event packet */
static void handle_event_packet(const uint8_t *buffer, int actual_length) {
    if (actual_length < (int)sizeof(struct fpc_packet_header)) {
        printf("[?] Packet too short: %d bytes\n", actual_length);
        return;
    }

    const struct fpc_packet_header *hdr = (const struct fpc_packet_header *)buffer;
    printf("[<] Event: %s (0x%02x), payload_len=%u, status=0x%08x\n",
           fpc_event_to_str(hdr->event_id), hdr->event_id, hdr->length, hdr->status);

    const uint8_t *payload = buffer + sizeof(struct fpc_packet_header);
    int payload_len = actual_length - sizeof(struct fpc_packet_header);

    switch (hdr->event_id) {
        case EVT_HELLO:
            printf("    [*] Device greeted host (EVT_HELLO)\n");
            break;

        case EVT_INIT_RESULT:
            printf("    [*] Sensor initialized successfully (status: 0x%x)\n", hdr->status);
            break;

        case EVT_ARM_RESULT:
            printf("    [*] Sensor armed and listening for touch...\n");
            break;

        case EVT_FINGER_DWN:
            printf("\n=========================================\n");
            printf(">>> [!] FINGER DETECTED ON SENSOR! <<<\n");
            printf("=========================================\n");
            /* Trigger image acquisition */
            printf("[*] Requesting image (CMD_GET_IMG)...\n");
            fpc_send_vendor_cmd(devh, CMD_GET_IMG, 0x0000, 0x0000, NULL, 0);
            break;

        case EVT_FINGER_UP:
            printf("\n--- Finger removed from sensor ---\n");
            /* Re-arm sensor for next touch */
            uint32_t arm_val = 0x00000001;
            fpc_send_vendor_cmd(devh, CMD_ARM, 0x0001, 0x0000, (uint8_t *)&arm_val, 4);
            break;

        case EVT_IMG:
            printf("[*] Received image packet! Total size: %d bytes\n", actual_length);
            if (payload_len > FPC_IMG_HEADER_SIZE) {
                const uint8_t *img_bytes = payload + FPC_IMG_HEADER_SIZE;
                size_t img_size = payload_len - FPC_IMG_HEADER_SIZE;
                capture_count++;
                save_pgm(img_bytes, img_size, capture_count);
            } else {
                printf("[-] Image payload too small (%d <= %d header)\n", payload_len, FPC_IMG_HEADER_SIZE);
            }
            break;

        case EVT_DEAD_PIXEL_REPORT:
            printf("    [*] Dead pixel report received (%d bytes)\n", payload_len);
            break;

        case EVT_USB_LOGS:
            if (payload_len > 0) {
                printf("    [FW_LOG]: %.*s\n", payload_len, (const char *)payload);
            }
            break;

        default:
            printf("    [?] Unhandled event payload (%d bytes)\n", payload_len);
            break;
    }
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    int r;

    printf("=== FPC Disum Sensor Linux Driver Utility ===\n");
    printf("[*] Supported targets: Honor MagicBook (10a5:a900), Acer Swift (10a5:e340)\n");

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    r = libusb_init(NULL);
    if (r < 0) {
        fprintf(stderr, "[-] libusb_init failed: %s\n", libusb_error_name(r));
        return 1;
    }

    /* Probe for Honor MagicBook PID 0xa900 first, then fallback to Acer PID 0xe340 */
    devh = libusb_open_device_with_vid_pid(NULL, FPC_USB_VID, FPC_USB_PID_HONOR);
    if (devh) {
        matched_pid = FPC_USB_PID_HONOR;
        printf("[+] Found Honor MagicBook sensor: %04x:%04x\n", FPC_USB_VID, matched_pid);
    } else {
        devh = libusb_open_device_with_vid_pid(NULL, FPC_USB_VID, FPC_USB_PID_ACER);
        if (devh) {
            matched_pid = FPC_USB_PID_ACER;
            printf("[+] Found Acer sensor: %04x:%04x\n", FPC_USB_VID, matched_pid);
        }
    }

    if (!devh) {
        fprintf(stderr, "[-] Neither device (10a5:a900 nor 10a5:e340) was found!\n");
        fprintf(stderr, "    Hint: Check 'lsusb', run with sudo, or install udev rules.\n");
        libusb_exit(NULL);
        return 1;
    }
    printf("[+] Device opened successfully!\n");

    /* Detach kernel driver if attached */
    if (libusb_kernel_driver_active(devh, 0) == 1) {
        printf("[*] Detaching active kernel driver...\n");
        libusb_detach_kernel_driver(devh, 0);
    }

    r = libusb_claim_interface(devh, 0);
    if (r < 0) {
        fprintf(stderr, "[-] Failed to claim interface 0: %s\n", libusb_error_name(r));
        libusb_close(devh);
        libusb_exit(NULL);
        return 1;
    }
    printf("[+] Claimed interface 0\n");

    /* Query Firmware Version */
    uint8_t fw_ver[32] = {0};
    r = fpc_recv_vendor_cmd(devh, CMD_GET_FW_VERSION, 0x0000, 0x0000, fw_ver, sizeof(fw_ver));
    if (r >= 0) {
        printf("[*] Firmware response: ");
        for (int i = 0; i < r; i++) printf("%02x ", fw_ver[i]);
        printf("\n");
    }

    /* Query Hardware Unique ID */
    uint8_t hw_uid[32] = {0};
    r = fpc_recv_vendor_cmd(devh, CMD_GET_HW_UNIQUE_ID, 0x0000, 0x0000, hw_uid, sizeof(hw_uid));
    if (r >= 0) {
        printf("[*] Hardware UID: ");
        for (int i = 0; i < r; i++) printf("%02x ", hw_uid[i]);
        printf("\n");
    }

    /* Step 1: Send CMD_INIT (wValue=1, wIndex=0, length=4) */
    uint32_t init_param = 0x00000001;
    printf("[*] Step 1: Initializing sensor (CMD_INIT)...\n");
    r = fpc_send_vendor_cmd(devh, CMD_INIT, 0x0001, 0x0000, (uint8_t *)&init_param, 4);
    if (r < 0) {
        fprintf(stderr, "[-] Sensor initialization failed!\n");
    }

    /* Step 2: Send CMD_ARM (wValue=1, wIndex=0, length=4) */
    uint32_t arm_param = 0x00000001;
    printf("[*] Step 2: Arming sensor for finger detection (CMD_ARM)...\n");
    r = fpc_send_vendor_cmd(devh, CMD_ARM, 0x0001, 0x0000, (uint8_t *)&arm_param, 4);
    if (r < 0) {
        fprintf(stderr, "[-] Sensor arming failed!\n");
    }

    printf("\n[+] Sensor ready! Place your finger on the sensor (Press Ctrl+C to stop)...\n\n");

    /* Read events loop from Interrupt Endpoint (0x81) */
    uint8_t recv_buf[65536];
    while (running) {
        int transferred = 0;
        r = libusb_interrupt_transfer(
            devh,
            FPC_EP_INTERRUPT_IN,
            recv_buf,
            sizeof(recv_buf),
            &transferred,
            500 /* 500ms timeout */
        );

        if (r == 0 && transferred > 0) {
            handle_event_packet(recv_buf, transferred);
        } else if (r == LIBUSB_ERROR_TIMEOUT) {
            continue;
        } else if (r < 0) {
            fprintf(stderr, "[-] Interrupt read error: %s\n", libusb_error_name(r));
            usleep(100000);
        }
    }

    printf("\n[*] Cleaning up and powering off session...\n");
    fpc_send_vendor_cmd(devh, CMD_ABORT, 0x0001, 0x0000, NULL, 0);
    fpc_send_vendor_cmd(devh, CMD_FINGERPRINT_SESSION_OFF, 0x0000, 0x0000, NULL, 0);

    libusb_release_interface(devh, 0);
    libusb_close(devh);
    libusb_exit(NULL);
    printf("[+] Done.\n");
    return 0;
}
