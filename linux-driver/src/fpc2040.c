/*
 * FPC Disum (FPC2040 / Galileo) Fingerprint Driver for libfprint
 * Target Devices:
 *   - USB 10a5:a900 (Honor MagicBook X 14 / X 16 2024)
 *   - USB 10a5:e340 (Acer Swift Go series)
 *
 * Reverse-engineered from Windows driver (fpc_disum.dll) using REA & Ghidra.
 * Copyright (C) 2026
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "fpc2040"

#include "drivers_api.h"
#include "fpc_protocol.h"

#define FPC2040_DEFAULT_WIDTH  160
#define FPC2040_DEFAULT_HEIGHT 160

struct _FpiDeviceFpc2040 {
    FpImageDevice parent;

    GUsbDevice   *usb_device;
    FpiUsbTransfer *interrupt_transfer;
    gboolean      is_capturing;
};

G_DECLARE_FINAL_TYPE(FpiDeviceFpc2040, fpi_device_fpc2040, FPI, DEVICE_FPC2040, FpImageDevice)
G_DEFINE_TYPE(FpiDeviceFpc2040, fpi_device_fpc2040, FPI_TYPE_IMAGE_DEVICE)

static const FpIdEntry id_table[] = {
    { .vid = FPC_USB_VID, .pid = FPC_USB_PID_HONOR }, /* Honor MagicBook X (10a5:a900) */
    { .vid = FPC_USB_VID, .pid = FPC_USB_PID_ACER },  /* Acer Swift (10a5:e340) */
    { .vid = 0, .pid = 0 }
};

static void fpc2040_read_events(FpiDeviceFpc2040 *self);

/* Control transfer completion callback */
static void fpc2040_ctrl_cb(FpiUsbTransfer *transfer, FpDevice *device,
                            gpointer user_data, GError *error) {
    if (error) {
        fp_warn("Control transfer error: %s", error->message);
        g_error_free(error);
    }
}

/* Helper to dispatch asynchronous control requests */
static void fpc2040_send_cmd_async(FpiDeviceFpc2040 *self, uint8_t cmd, uint16_t val, uint16_t idx,
                                   uint8_t *data, gsize length) {
    FpDevice *dev = FP_DEVICE(self);
    FpiUsbTransfer *transfer = fpi_usb_transfer_new(dev);

    fpi_usb_transfer_fill_control(
        transfer,
        G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
        G_USB_DEVICE_REQUEST_TYPE_VENDOR,
        G_USB_DEVICE_RECIPIENT_DEVICE,
        cmd,
        val,
        idx,
        length
    );

    if (data && length > 0) {
        memcpy(transfer->buffer + G_USB_CONTROL_MESSAGE_SIZE, data, length);
    }

    fpi_usb_transfer_submit(transfer, 2000, NULL, fpc2040_ctrl_cb, NULL);
}

/* Handle received USB event packets */
static void fpc2040_process_packet(FpiDeviceFpc2040 *self, const uint8_t *buf, gsize len) {
    FpImageDevice *img_dev = FP_IMAGE_DEVICE(self);

    if (len < sizeof(struct fpc_packet_header)) {
        fp_warn("Short packet received: %zu bytes", len);
        return;
    }

    const struct fpc_packet_header *hdr = (const struct fpc_packet_header *)buf;
    fp_dbg("Received event %s (0x%02x), status=0x%x, length=%u",
           fpc_event_to_str(hdr->event_id), hdr->event_id, hdr->status, hdr->length);

    const uint8_t *payload = buf + sizeof(struct fpc_packet_header);
    gsize payload_len = len - sizeof(struct fpc_packet_header);

    switch (hdr->event_id) {
        case EVT_FINGER_DWN:
            fp_dbg("Sensor reports finger down");
            fpi_image_device_report_finger_status(img_dev, TRUE);

            /* Trigger image fetch */
            fpc2040_send_cmd_async(self, CMD_GET_IMG, 0x0000, 0x0000, NULL, 0);
            break;

        case EVT_FINGER_UP:
            fp_dbg("Sensor reports finger up");
            fpi_image_device_report_finger_status(img_dev, FALSE);

            /* Re-arm sensor for subsequent touch if still active */
            if (self->is_capturing) {
                uint32_t arm_val = 0x00000001;
                fpc2040_send_cmd_async(self, CMD_ARM, 0x0001, 0x0000, (uint8_t *)&arm_val, 4);
            }
            break;

        case EVT_IMG: {
            fp_dbg("Received image payload (%zu bytes)", payload_len);
            if (payload_len > FPC_IMG_HEADER_SIZE) {
                const uint8_t *raw_pixels = payload + FPC_IMG_HEADER_SIZE;
                gsize img_size = payload_len - FPC_IMG_HEADER_SIZE;

                gint width = FPC2040_DEFAULT_WIDTH;
                gint height = (gint)(img_size / width);
                if (height <= 0) height = FPC2040_DEFAULT_HEIGHT;

                FpImage *image = fpi_image_new(width, height);
                memcpy(image->data, raw_pixels, MIN(img_size, (gsize)(width * height)));

                fpi_image_device_image_captured(img_dev, image);
            }
            break;
        }

        case EVT_INIT_RESULT:
        case EVT_ARM_RESULT:
        case EVT_HELLO:
        default:
            break;
    }
}

/* Interrupt read completion callback */
static void fpc2040_interrupt_cb(FpiUsbTransfer *transfer, FpDevice *device,
                                 gpointer user_data, GError *error) {
    FpiDeviceFpc2040 *self = FPI_DEVICE_FPC2040(device);

    if (error) {
        if (!g_error_matches(error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT) &&
            !g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
            fp_warn("Interrupt transfer error: %s", error->message);
        }
        g_error_free(error);
    } else {
        fpc2040_process_packet(self, transfer->buffer, transfer->actual_length);
    }

    /* Resubmit continuous reader if active */
    if (self->is_capturing) {
        fpc2040_read_events(self);
    }
}

/* Start continuous interrupt reader on Endpoint 0x81 */
static void fpc2040_read_events(FpiDeviceFpc2040 *self) {
    FpDevice *dev = FP_DEVICE(self);
    self->interrupt_transfer = fpi_usb_transfer_new(dev);

    fpi_usb_transfer_fill_bulk_full(
        self->interrupt_transfer,
        FPC_EP_INTERRUPT_IN,
        NULL,
        65536,
        NULL
    );

    fpi_usb_transfer_submit(self->interrupt_transfer, 1000, NULL, fpc2040_interrupt_cb, NULL);
}

/* Device Open */
static void fpc2040_dev_open(FpImageDevice *dev) {
    FpDevice *fp_dev = FP_DEVICE(dev);
    GError *error = NULL;

    if (!g_usb_device_claim_interface(fpi_device_get_usb_device(fp_dev), 0, 0, &error)) {
        fpi_image_device_open_complete(dev, error);
        return;
    }

    fpi_image_device_open_complete(dev, NULL);
}

/* Device Close */
static void fpc2040_dev_close(FpImageDevice *dev) {
    FpDevice *fp_dev = FP_DEVICE(dev);
    GError *error = NULL;

    g_usb_device_release_interface(fpi_device_get_usb_device(fp_dev), 0, 0, &error);
    fpi_image_device_close_complete(dev, error);
}

/* Device Activate (Start listening/enrolling) */
static void fpc2040_dev_activate(FpImageDevice *dev) {
    FpiDeviceFpc2040 *self = FPI_DEVICE_FPC2040(dev);

    self->is_capturing = TRUE;

    /* 1. Send CMD_INIT */
    uint32_t init_val = 0x00000001;
    fpc2040_send_cmd_async(self, CMD_INIT, 0x0001, 0x0000, (uint8_t *)&init_val, 4);

    /* 2. Send CMD_ARM */
    uint32_t arm_val = 0x00000001;
    fpc2040_send_cmd_async(self, CMD_ARM, 0x0001, 0x0000, (uint8_t *)&arm_val, 4);

    /* 3. Begin continuous interrupt polling */
    fpc2040_read_events(self);

    fpi_image_device_activate_complete(dev, NULL);
}

/* Device Deactivate (Stop listening) */
static void fpc2040_dev_deactivate(FpImageDevice *dev) {
    FpiDeviceFpc2040 *self = FPI_DEVICE_FPC2040(dev);

    self->is_capturing = FALSE;

    /* Abort ongoing operations */
    fpc2040_send_cmd_async(self, CMD_ABORT, 0x0001, 0x0000, NULL, 0);
    fpc2040_send_cmd_async(self, CMD_FINGERPRINT_SESSION_OFF, 0x0000, 0x0000, NULL, 0);

    if (self->interrupt_transfer) {
        g_cancellable_cancel(self->interrupt_transfer->cancellable);
    }

    fpi_image_device_deactivate_complete(dev, NULL);
}

static void fpi_device_fpc2040_init(FpiDeviceFpc2040 *self) {
    self->is_capturing = FALSE;
}

static void fpi_device_fpc2040_class_init(FpiDeviceFpc2040Class *klass) {
    FpDeviceClass *dev_class = FP_DEVICE_CLASS(klass);
    FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS(klass);

    dev_class->id = "fpc2040";
    dev_class->full_name = "Fingerprint Cards Disum (Honor / Acer)";
    dev_class->type = FP_DEVICE_TYPE_USB;
    dev_class->id_table = id_table;
    dev_class->nr_enroll_stages = 5;
    dev_class->scan_type = FP_SCAN_TYPE_PRESS;

    img_class->img_open = fpc2040_dev_open;
    img_class->img_close = fpc2040_dev_close;
    img_class->activate = fpc2040_dev_activate;
    img_class->deactivate = fpc2040_dev_deactivate;

    img_class->bz3_threshold = 24;
}
