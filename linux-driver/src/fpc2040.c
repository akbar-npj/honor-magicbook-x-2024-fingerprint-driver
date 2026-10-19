/*
 * FPC Disum (FPC2040 / Galileo) fingerprint driver for libfprint
 * Target: USB 10a5:a900 (Honor MagicBook X 14 / X 16, 2024)
 *
 * This sensor is match-on-host: the decrypted EVT_IMG payload already
 * contains a native 128x88 ridge image, so the generic FpImageDevice + NBIS
 * (bozorth3) path is used.  Unlike the Acer
 * 10a5:e340 strip, no clean-room BEP or correlation matcher is needed.
 *
 * Protocol verified live against FW 22.26.2.29:
 *   - bulk IN endpoint 0x82 (auto-discovered from the descriptors)
 *   - events are big-endian {u32 code, u32 total_len, u32 status}, and
 *     total_len includes the 12-byte header
 *   - the channel is TLS-PSK, but the roles are reversed vs the Acer:
 *     the HOST is the TLS server and the device is the client
 *   - EVT_IMG payload = 12-byte image header + 11264 pixels
 *
 * Reverse-engineered from the Windows driver (fpc_disum.dll) using REA &
 * Ghidra.  Copyright (C) 2026.  SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "fpc2040"

#include "drivers_api.h"
#include "fpc_protocol.h"

#include <string.h>
#include <math.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FPC2040_NR_ENROLL_STAGES 5
#define FPC2040_INNER_BUF_SIZE   65536
#define FPC2040_EP_MPS_DEFAULT   64

struct _FpiDeviceFpc2040
{
  FpImageDevice parent;

  GUsbDevice *usb;
  guint8 ep_in;
  guint ep_mps;

  /* TLS-PSK session state */
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  BIO *rbio;
  BIO *wbio;
  gboolean tls_ready;
  guint8 psk[64];
  guint psk_len;
  gboolean session_up;

  /* Decrypted inner-event reassembly.  Heap-allocated: GObject instance
   * sizes are limited to 64 KiB. */
  guint8 *inner_buf;
  gsize inner_len;

  /* Background event reader. */
  GThread *thread;
  GCancellable *cancellable;
  gboolean running;
  gint thread_done;

  /* The device re-sends EVT_FINGER_DWN while the finger stays down and
   * never sends EVT_FINGER_UP, so one press is delimited by the image
   * itself plus a short cooldown. */
  gboolean finger_down;
  gboolean img_pending;
  gint64 last_capture_us;
};

G_DECLARE_FINAL_TYPE (FpiDeviceFpc2040, fpi_device_fpc2040,
                      FPI, DEVICE_FPC2040, FpImageDevice)
G_DEFINE_TYPE (FpiDeviceFpc2040, fpi_device_fpc2040, FP_TYPE_IMAGE_DEVICE)

static const FpIdEntry id_table[] = {
  { .vid = FPC_USB_VID, .pid = FPC_USB_PID_HONOR },
  { .vid = 0, .pid = 0 }
};

/* ------------------------------------------------------------------ */
/* endian + USB helpers                                               */
/* ------------------------------------------------------------------ */

/* a900 event headers are big-endian (the e340 is little-endian). */
static inline guint32
fpc_be32 (const guint8 *p)
{
  return ((guint32) p[0] << 24) | ((guint32) p[1] << 16) |
         ((guint32) p[2] << 8) | (guint32) p[3];
}

static gboolean
fpc_ctrl (FpiDeviceFpc2040 *self, gboolean out, guint8 cmd,
          guint16 val, guint16 idx, guint8 *data, gsize len,
          gsize *actual_out, GCancellable *cancellable, GError **error)
{
  gsize actual = 0;
  gboolean ok;

  ok = g_usb_device_control_transfer (
      self->usb,
      out ? G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE
          : G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
      G_USB_DEVICE_REQUEST_TYPE_VENDOR,
      G_USB_DEVICE_RECIPIENT_DEVICE,
      cmd, val, idx, data, len, &actual, 5000, cancellable, error);
  if (actual_out)
    *actual_out = actual;
  return ok;
}

static gboolean
fpc_ctrl_out (FpiDeviceFpc2040 *self, guint8 cmd, guint16 val, guint16 idx,
              guint8 *data, gsize len, GCancellable *c, GError **error)
{
  return fpc_ctrl (self, TRUE, cmd, val, idx, data, len, NULL, c, error);
}

static gboolean
fpc_ctrl_in (FpiDeviceFpc2040 *self, guint8 cmd, guint16 val, guint16 idx,
             guint8 *data, gsize len, gsize *actual,
             GCancellable *c, GError **error)
{
  gsize got = 0;

  if (!fpc_ctrl (self, FALSE, cmd, val, idx, data, len, &got, c, error))
    return FALSE;
  if (actual)
    *actual = got;
  return TRUE;
}

/* Read one complete framed packet (12-byte header + payload).
 * Returns packet length, 0 on timeout with no data, -1 on error. */
static gssize
fpc_bulk_read_event (FpiDeviceFpc2040 *self, guint8 *buf, gsize cap,
                     guint timeout, GCancellable *cancellable,
                     GError **error)
{
  gsize got = 0;

  for (;;)
    {
      if (got >= FPC_EVENT_HDR_SIZE)
        {
          guint32 want = fpc_be32 (buf + 4);

          if (want < FPC_EVENT_HDR_SIZE || want > cap)
            {
              g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                           "bad bulk frame length %u", want);
              return -1;
            }
          if (got >= want)
            return (gssize) got;
        }

      {
        gsize actual = 0;
        GError *e = NULL;

        if (g_cancellable_is_cancelled (cancellable))
          return 0;

        if (!g_usb_device_bulk_transfer (self->usb, self->ep_in,
                                         buf + got, cap - got, &actual,
                                         timeout, cancellable, &e))
          {
            if (e && g_error_matches (e, G_USB_DEVICE_ERROR,
                                      G_USB_DEVICE_ERROR_TIMED_OUT))
              {
                g_error_free (e);
                if (got == 0)
                  return 0;
                /* A frame stalled mid-transfer; drop it rather than
                 * spinning on timeouts (which would block deactivate). */
                g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                             "partial bulk frame (%zu bytes)", got);
                return -1;
              }
            g_debug ("bulk error: %s (got=%zu)",
                     e ? e->message : "unknown", got);
            g_propagate_error (error, e);
            return -1;
          }
        if (actual == 0)
          {
            if (got == 0)
              return 0;
            continue;
          }
        got += actual;
      }
    }
}

static gboolean
fpc_find_bulk_in (FpiDeviceFpc2040 *self, GError **error)
{
  g_autoptr(GPtrArray) interfaces = NULL;
  guint i, j;

  interfaces = g_usb_device_get_interfaces (self->usb, error);
  if (!interfaces)
    return FALSE;

  for (i = 0; i < interfaces->len; i++)
    {
      GUsbInterface *iface = g_ptr_array_index (interfaces, i);
      GPtrArray *eps = g_usb_interface_get_endpoints (iface);

      if (!eps)
        continue;

      for (j = 0; j < eps->len; j++)
        {
          GUsbEndpoint *ep = g_ptr_array_index (eps, j);

          if (g_usb_endpoint_get_direction (ep) !=
              G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST)
            continue;

          self->ep_in = g_usb_endpoint_get_address (ep);
          self->ep_mps = g_usb_endpoint_get_maximum_packet_size (ep);
          if (self->ep_mps == 0)
            self->ep_mps = FPC2040_EP_MPS_DEFAULT;
          g_debug ("bulk IN endpoint 0x%02x (mps=%u)",
                   self->ep_in, self->ep_mps);
          return TRUE;
        }
    }

  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "no bulk IN endpoint found");
  return FALSE;
}

/* ------------------------------------------------------------------ */
/* TLS-PSK (host is the server for a900)                              */
/* ------------------------------------------------------------------ */

static void
fpc_sha256 (const void *data, size_t len, guint8 *out)
{
  unsigned int out_len = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();

  EVP_DigestInit_ex (ctx, EVP_sha256 (), NULL);
  EVP_DigestUpdate (ctx, data, len);
  EVP_DigestFinal_ex (ctx, out, &out_len);
  EVP_MD_CTX_free (ctx);
}

static gboolean
fpc_derive_psk (FpiDeviceFpc2040 *self, const guint8 *blob, gsize blob_len,
                GError **error)
{
  const struct fpc_tls_key *k = (const struct fpc_tls_key *) blob;
  const guint8 *aad, *key, *sig;
  guint8 hmac_key[32], mac[32], msg[1024];
  unsigned int mac_len = 32;
  guint8 sealing_key[32];
  EVP_CIPHER_CTX *c;
  int o1 = 0, o2 = 0;

  if (blob_len < sizeof (struct fpc_tls_key) ||
      k->magic != 0x0dec0ded ||
      (gsize) k->key_offset + k->key_len > blob_len ||
      (gsize) k->aad_offset + k->aad_len > blob_len ||
      (gsize) k->sig_offset + k->sig_len > blob_len)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "invalid TLS key blob");
      return FALSE;
    }

  aad = blob + k->aad_offset;
  key = blob + k->key_offset;
  sig = blob + k->sig_offset;

  if (k->aad_len < 13 || memcmp ("FPC TLS Keys", aad, 13) != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "bad TLS key AAD");
      return FALSE;
    }

  fpc_sha256 (FPC_HMAC_KEY_STR, FPC_HMAC_KEY_LEN, hmac_key);
  if (k->aad_len + k->key_len > sizeof msg)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "TLS key blob too large");
      return FALSE;
    }
  memcpy (msg, aad, k->aad_len);
  memcpy (msg + k->aad_len, key, k->key_len);
  HMAC (EVP_sha256 (), hmac_key, 32, msg, k->aad_len + k->key_len,
        mac, &mac_len);
  if (k->sig_len < 32 || memcmp (mac, sig, 32) != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "TLS key signature verification failed");
      return FALSE;
    }

  fpc_sha256 (FPC_SEALING_KEY_STR, FPC_SEALING_KEY_LEN, sealing_key);
  c = EVP_CIPHER_CTX_new ();
  EVP_CipherInit_ex (c, EVP_aes_256_cbc (), NULL, sealing_key, NULL, 0);
  EVP_CIPHER_CTX_set_padding (c, 0);
  EVP_CipherUpdate (c, self->psk, &o1, key, k->key_len);
  EVP_CipherFinal_ex (c, self->psk + o1, &o2);
  EVP_CIPHER_CTX_free (c);

  self->psk_len = (guint) (o1 + o2);
  if (self->psk_len == 0 || self->psk_len > sizeof self->psk)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "PSK derivation failed");
      return FALSE;
    }
  return TRUE;
}

static unsigned int
fpc_psk_server_cb (SSL *ssl, const char *identity,
                   unsigned char *psk, unsigned int max_psk_len)
{
  FpiDeviceFpc2040 *self = (FpiDeviceFpc2040 *) SSL_get_app_data (ssl);

  (void) identity;
  if (max_psk_len < self->psk_len)
    return 0;
  memcpy (psk, self->psk, self->psk_len);
  return self->psk_len;
}

static gboolean
fpc_tls_setup (FpiDeviceFpc2040 *self, GError **error)
{
  /* Generic method: the host accepts (server role) on a900. */
  self->ssl_ctx = SSL_CTX_new (TLS_method ());
  if (!self->ssl_ctx)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "SSL_CTX_new failed");
      return FALSE;
    }
  SSL_CTX_set_min_proto_version (self->ssl_ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version (self->ssl_ctx, TLS1_2_VERSION);
  SSL_CTX_set_psk_server_callback (self->ssl_ctx, fpc_psk_server_cb);
  SSL_CTX_set_cipher_list (self->ssl_ctx,
                           "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:"
                           "PSK-AES128-CBC-SHA256:PSK-AES256-CBC-SHA384");

  self->ssl = SSL_new (self->ssl_ctx);
  if (!self->ssl)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "SSL_new failed");
      return FALSE;
    }
  self->rbio = BIO_new (BIO_s_mem ());
  self->wbio = BIO_new (BIO_s_mem ());
  BIO_set_mem_eof_return (self->rbio, -1);
  BIO_set_mem_eof_return (self->wbio, -1);
  SSL_set_bio (self->ssl, self->rbio, self->wbio);
  SSL_set_app_data (self->ssl, self);
  SSL_set_accept_state (self->ssl);
  return TRUE;
}

static gboolean
fpc_tls_flush_out (FpiDeviceFpc2040 *self, GCancellable *c, GError **error)
{
  guint8 tmp[4096];
  int pending;

  while ((pending = (int) BIO_ctrl_pending (self->wbio)) > 0)
    {
      int n = BIO_read (self->wbio, tmp, pending);
      int off;

      if (n <= 0)
        break;
      for (off = 0; off < n; )
        {
          int chunk = MIN (n - off, (int) self->ep_mps);

          if (!fpc_ctrl_out (self, CMD_TLS_DATA, 0x0001, 0x0000,
                             tmp + off, (gsize) chunk, c, error))
            return FALSE;
          off += chunk;
        }
    }
  return TRUE;
}

static gboolean fpc_handle_event (FpiDeviceFpc2040 *self, guint32 code,
                                  const guint8 *payload, gsize len,
                                  GCancellable *c, GError **error);

static gboolean fpc_arm (FpiDeviceFpc2040 *self, GCancellable *c, GError **error);

/* Reassemble decrypted inner events (big-endian 12-byte header). */
static gboolean
fpc_inner_feed (FpiDeviceFpc2040 *self, const guint8 *data, gsize len,
                GCancellable *c, GError **error)
{
  gsize off = 0;

  if (len > FPC2040_INNER_BUF_SIZE - self->inner_len)
    self->inner_len = 0;
  memcpy (self->inner_buf + self->inner_len, data, len);
  self->inner_len += len;

  while (self->inner_len - off >= FPC_EVENT_HDR_SIZE)
    {
      guint32 code = fpc_be32 (self->inner_buf + off);
      guint32 plen = fpc_be32 (self->inner_buf + off + 4);

      if (plen < FPC_EVENT_HDR_SIZE || plen > FPC2040_INNER_BUF_SIZE)
        {
          self->inner_len = 0;
          return TRUE;
        }
      if (self->inner_len - off < plen)
        break;

      if (!fpc_handle_event (self, code,
                             self->inner_buf + off + FPC_EVENT_HDR_SIZE,
                             plen - FPC_EVENT_HDR_SIZE, c, error))
        return FALSE;

      off += plen;
    }

  if (off > 0)
    {
      memmove (self->inner_buf, self->inner_buf + off, self->inner_len - off);
      self->inner_len -= off;
    }
  return TRUE;
}

/* 1 = progress/done, 0 = want read, -1 = error */
static int
fpc_tls_pump (FpiDeviceFpc2040 *self, GCancellable *c, GError **error)
{
  if (!self->tls_ready)
    {
      int r = SSL_do_handshake (self->ssl);
      int e;

      if (!fpc_tls_flush_out (self, c, error))
        return -1;
      if (r == 1)
        {
          self->tls_ready = TRUE;
          return 1;
        }
      e = SSL_get_error (self->ssl, r);
      if (e == SSL_ERROR_WANT_READ)
        return 0;
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "TLS handshake error %d", e);
      ERR_print_errors_fp (stderr);
      return -1;
    }

  {
    guint8 tmp[8192];
    int r = SSL_read (self->ssl, tmp, sizeof tmp);
    int e;

    if (!fpc_tls_flush_out (self, c, error))
      return -1;
    if (r > 0)
      {
        if (!fpc_inner_feed (self, tmp, (gsize) r, c, error))
          return -1;
        return 1;
      }
    e = SSL_get_error (self->ssl, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_ZERO_RETURN)
      return 0;
    g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                 "TLS read error %d", e);
    return -1;
  }
}

/* ------------------------------------------------------------------ */
/* main-context marshalling                                           */
/* ------------------------------------------------------------------ */

typedef struct
{
  FpiDeviceFpc2040 *self;
  gboolean down;
} FpcFingerStatus;

static gboolean
fpc_emit_finger_status_cb (gpointer data)
{
  FpcFingerStatus *s = data;

  fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (s->self), s->down);
  g_object_unref (s->self);
  g_free (s);
  return G_SOURCE_REMOVE;
}

static void
fpc_emit_finger_status (FpiDeviceFpc2040 *self, gboolean down)
{
  FpcFingerStatus *s = g_new0 (FpcFingerStatus, 1);

  s->self = g_object_ref (self);
  s->down = down;
  g_main_context_invoke (NULL, fpc_emit_finger_status_cb, s);
}

/* Abort the current enroll/verify/capture action from the capture thread. */
typedef struct
{
  FpiDeviceFpc2040 *self;
  GError *error;
} FpcErrorEvent;

static gboolean
fpc_emit_session_error_cb (gpointer data)
{
  FpcErrorEvent *e = data;

  fpi_image_device_session_error (FP_IMAGE_DEVICE (e->self), e->error);
  g_object_unref (e->self);
  g_free (e);
  return G_SOURCE_REMOVE;
}

static void
fpc_emit_session_error (FpiDeviceFpc2040 *self, GError *error)
{
  FpcErrorEvent *e = g_new0 (FpcErrorEvent, 1);

  e->self = g_object_ref (self);
  e->error = error; /* takes ownership */
  g_main_context_invoke (NULL, fpc_emit_session_error_cb, e);
}

typedef struct
{
  FpiDeviceFpc2040 *self;
  FpImage *image;
} FpcImageEvent;

static gboolean
fpc_emit_image_cb (gpointer data)
{
  FpcImageEvent *e = data;

  fpi_image_device_image_captured (FP_IMAGE_DEVICE (e->self), e->image);
  g_object_unref (e->self);
  g_free (e);
  return G_SOURCE_REMOVE;
}

/* Bilinear 2x upscale: the sensor is ~250 dpi while NBIS/LFS is tuned for
 * ~500 dpi; doubling the image puts the ridge frequency into the range the
 * detector expects (13 -> 42 minutiae on the same press). */
static void
fpc_upscale2x (const guint8 *src, guint sw, guint sh,
               guint8 *dst, guint dw, guint dh)
{
  guint x, y;

  for (y = 0; y < dh; y++)
    {
      gdouble fy = (y + 0.5) / 2.0 - 0.5;
      gint y0 = (gint) floor (fy);
      gint y1 = y0 + 1;
      gdouble wy = fy - y0;

      if (y0 < 0)
        { y0 = 0; wy = 0.0; }
      if (y1 >= (gint) sh)
        { y1 = sh - 1; if (y0 >= (gint) sh) y0 = sh - 1; wy = 0.0; }

      for (x = 0; x < dw; x++)
        {
          gdouble fx = (x + 0.5) / 2.0 - 0.5;
          gint x0 = (gint) floor (fx);
          gint x1 = x0 + 1;
          gdouble wx = fx - x0;
          gdouble a, b, v;

          if (x0 < 0)
            { x0 = 0; wx = 0.0; }
          if (x1 >= (gint) sw)
            { x1 = sw - 1; if (x0 >= (gint) sw) x0 = sw - 1; wx = 0.0; }

          a = src[y0 * sw + x0] * (1.0 - wx) + src[y0 * sw + x1] * wx;
          b = src[y1 * sw + x0] * (1.0 - wx) + src[y1 * sw + x1] * wx;
          v = a * (1.0 - wy) + b * wy;
          dst[y * dw + x] = (guint8) (v + 0.5);
        }
    }
}

static void
fpc_emit_image (FpiDeviceFpc2040 *self, const guint8 *px)
{
  FpImage *image = fp_image_new (FPC_RIDGE_WIDTH, FPC_RIDGE_HEIGHT);
  FpcImageEvent *e;

  fpc_upscale2x (px, FPC_SENSOR_WIDTH, FPC_SENSOR_HEIGHT,
                 image->data, FPC_RIDGE_WIDTH, FPC_RIDGE_HEIGHT);
  image->ppmm = 19.685;  /* 500 dpi / 25.4 mm/in (after 2x upscale) */

  e = g_new0 (FpcImageEvent, 1);
  e->self = g_object_ref (self);
  e->image = image;
  g_main_context_invoke (NULL, fpc_emit_image_cb, e);
}

static gboolean
fpc_handle_event (FpiDeviceFpc2040 *self, guint32 code,
                  const guint8 *payload, gsize len,
                  GCancellable *c, GError **error)
{
  g_debug ("event 0x%08x (%zu bytes)", code, len);

  switch (code)
    {
    case EVT_FINGER_DWN:
      /* The firmware repeats this ~250 ms after the image of the same
       * press; anything inside the cooldown is the same touch. */
      if (self->finger_down ||
          g_get_monotonic_time () - self->last_capture_us < 700000)
        {
          g_debug ("event: finger down (duplicate, ignored)");
          return TRUE;
        }
      g_debug ("event: finger down");
      self->finger_down = TRUE;
      self->img_pending = TRUE;
      fpc_emit_finger_status (self, TRUE);
      return fpc_ctrl_out (self, CMD_GET_IMG, 0x0000, 0x0000,
                           NULL, 0, c, error);

    case EVT_FINGER_UP:
      /* Not emitted by FW 22.26.2.29, kept for other firmware. */
      g_debug ("event: finger up");
      self->finger_down = FALSE;
      self->img_pending = FALSE;
      fpc_emit_finger_status (self, FALSE);
      return TRUE;

    case EVT_IMG:
      if (!self->img_pending)
        {
          g_debug ("event: unsolicited image (%zu bytes), ignored", len);
          return TRUE;
        }
      self->img_pending = FALSE;
      self->finger_down = FALSE;
      self->last_capture_us = g_get_monotonic_time ();
      if (len >= FPC_IMG_HDR_SIZE + FPC_IMAGE_BYTES)
        {
          g_debug ("event: image (%zu bytes)", len);
          fpc_emit_image (self, payload + FPC_IMG_HDR_SIZE);
        }
      else
        {
          g_debug ("event: short image (%zu bytes)", len);
        }
      /* No EVT_FINGER_UP on this firmware: the image is the end of the
       * press, so release the state machine here.  Queued after the
       * image callback, so libfprint sees capture -> finger off. */
      fpc_emit_finger_status (self, FALSE);
      /* The sensor self-disables after a capture (overheat guard) and must
       * be re-armed before the next touch.  Wait several seconds to let the
       * firmware clear its lockout, otherwise the next capture trips the
       * guard and stalls the enrollment. */
      g_usleep (3000000);
      fpc_arm (self, c, NULL);
      return TRUE;

    default:
      return TRUE;
    }
}

/* ------------------------------------------------------------------ */
/* session                                                            */
/* ------------------------------------------------------------------ */

static gboolean
fpc_arm (FpiDeviceFpc2040 *self, GCancellable *c, GError **error)
{
  guint8 magic[4] = { FPC_ARM_MAGIC };

  return fpc_ctrl_out (self, CMD_ARM, 0x0001, 0x0000, magic, 4, c, error);
}

static gboolean
fpc_handshake (FpiDeviceFpc2040 *self, GCancellable *c, GError **error)
{
  guint8 buf[65536];
  int i;

  for (i = 0; i < 400 && !self->tls_ready; i++)
    {
      int r = fpc_tls_pump (self, c, error);
      gssize n;

      if (r < 0)
        return FALSE;
      if (self->tls_ready)
        break;

      n = fpc_bulk_read_event (self, buf, sizeof buf, 500, c, error);
      if (n < 0)
        return FALSE;
      if (n >= FPC_EVENT_HDR_SIZE && fpc_be32 (buf) == EVT_TLS)
        BIO_write (self->rbio, buf + FPC_EVENT_HDR_SIZE,
                   (int) (n - FPC_EVENT_HDR_SIZE));
    }

  if (!self->tls_ready)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "TLS handshake timed out");
      return FALSE;
    }
  return TRUE;
}

static gboolean
fpc_session_start (FpiDeviceFpc2040 *self, GCancellable *c, GError **error)
{
  guint8 buf[65536];
  guint8 init_magic[4] = { FPC_INIT_MAGIC };
  guint8 keybuf[1000];
  gsize got = 0;
  gssize n;

  if (self->session_up)
    return TRUE;

  self->finger_down = FALSE;
  self->img_pending = FALSE;
  self->last_capture_us = 0;
  g_debug ("session: INDICATE_S_STATE");
  if (!fpc_ctrl_out (self, CMD_INDICATE_S_STATE, 0x0010, 0x0000,
                     NULL, 0, c, error))
    return FALSE;

  /* Best-effort firmware state read; failure is not fatal. */
  fpc_ctrl_in (self, GET_STATE, 0, 0, buf, 72, &got, c, NULL);
  g_debug ("session: GET_STATE returned %zu bytes", got);

  g_debug ("session: CMD_INIT");
  if (!fpc_ctrl_out (self, CMD_INIT, 0x0001, 0x0000,
                     init_magic, 4, c, error))
    return FALSE;

  n = fpc_bulk_read_event (self, buf, sizeof buf, 3000, c, error);
  if (n < 0)
    return FALSE;
  g_debug ("session: init event n=%zd code=0x%08x", n,
           n >= FPC_EVENT_HDR_SIZE ? fpc_be32 (buf) : 0);

  g_debug ("session: CMD_GET_TLS_KEY");
  if (!fpc_ctrl_in (self, CMD_GET_TLS_KEY, 0, 0, keybuf, sizeof keybuf,
                    &got, c, error))
    return FALSE;
  if (got == 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "empty TLS key blob");
      return FALSE;
    }
  if (!fpc_derive_psk (self, keybuf, got, error))
    return FALSE;
  g_debug ("session: derived PSK (%u bytes)", self->psk_len);

  if (!fpc_tls_setup (self, error))
    return FALSE;

  g_debug ("session: CMD_TLS_INIT");
  if (!fpc_ctrl_out (self, CMD_TLS_INIT, 0x0001, 0x0000,
                     NULL, 0, c, error))
    return FALSE;

  if (!fpc_handshake (self, c, error))
    return FALSE;
  g_debug ("session: TLS handshake complete (host is server)");

  if (!fpc_arm (self, c, error))
    return FALSE;
  g_debug ("session: sensor armed");

  self->session_up = TRUE;
  return TRUE;
}

static void
fpc_session_stop (FpiDeviceFpc2040 *self)
{
  if (self->usb)
    {
      guint8 disarm[4] = { FPC_DISARM_MAGIC };

      fpc_ctrl_out (self, CMD_ARM, 0x0001, 0x0000, disarm, 4, NULL, NULL);
      fpc_ctrl_out (self, CMD_ABORT, 0x0000, 0x0000, NULL, 0, NULL, NULL);
      fpc_ctrl_out (self, CMD_FINGERPRINT_SESSION_OFF, 0x0000, 0x0000,
                    NULL, 0, NULL, NULL);
    }

  if (self->ssl)
    {
      SSL_free (self->ssl);
      self->ssl = NULL;
      self->rbio = NULL;
      self->wbio = NULL;
    }
  if (self->ssl_ctx)
    {
      SSL_CTX_free (self->ssl_ctx);
      self->ssl_ctx = NULL;
    }
  self->tls_ready = FALSE;
  self->session_up = FALSE;
  self->finger_down = FALSE;
  self->img_pending = FALSE;
  self->last_capture_us = 0;
  self->inner_len = 0;
}

/* ------------------------------------------------------------------ */
/* capture thread                                                     */
/* ------------------------------------------------------------------ */

static gpointer
fpc_capture_thread (gpointer data)
{
  FpiDeviceFpc2040 *self = data;
  guint8 buf[65536];
  GError *error = NULL;

  g_debug ("capture thread started");

  while (self->running && !g_cancellable_is_cancelled (self->cancellable))
    {
      int r;

      while ((r = fpc_tls_pump (self, self->cancellable, &error)) == 1)
        ;
      if (r < 0)
        break;

      {
        gssize n = fpc_bulk_read_event (self, buf, sizeof buf, 500,
                                        self->cancellable, &error);
        guint32 code;

        if (n < 0)
          break;
        if (n < FPC_EVENT_HDR_SIZE)
          continue;

        code = fpc_be32 (buf);
        if (code == EVT_TLS)
          {
            BIO_write (self->rbio, buf + FPC_EVENT_HDR_SIZE,
                       (int) (n - FPC_EVENT_HDR_SIZE));
          }
        else
          {
            if (!fpc_handle_event (self, code, buf + FPC_EVENT_HDR_SIZE,
                                   (gsize) n - FPC_EVENT_HDR_SIZE,
                                   self->cancellable, &error))
              break;
          }
      }
    }

  if (error)
    {
      g_debug ("capture thread: %s", error->message);
      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        g_error_free (error);
      else
        fpc_emit_session_error (self, error); /* takes ownership */
    }
  g_debug ("capture thread stopped");
  g_atomic_int_set (&self->thread_done, 1);
  return NULL;
}

/* ------------------------------------------------------------------ */
/* FpImageDevice callbacks                                            */
/* ------------------------------------------------------------------ */

static void
fpc2040_dev_open (FpImageDevice *dev)
{
  FpiDeviceFpc2040 *self = FPI_DEVICE_FPC2040 (dev);
  GError *error = NULL;

  self->usb = fpi_device_get_usb_device (FP_DEVICE (dev));
  if (!g_usb_device_claim_interface (self->usb, 0, 0, &error))
    {
      fpi_image_device_open_complete (dev, error);
      return;
    }
  if (!fpc_find_bulk_in (self, &error))
    {
      g_usb_device_release_interface (self->usb, 0, 0, NULL);
      fpi_image_device_open_complete (dev, error);
      return;
    }
  fpi_image_device_open_complete (dev, NULL);
}

static void
fpc2040_dev_close (FpImageDevice *dev)
{
  FpiDeviceFpc2040 *self = FPI_DEVICE_FPC2040 (dev);
  GError *error = NULL;

  if (self->usb)
    g_usb_device_release_interface (self->usb, 0, 0, &error);
  fpi_image_device_close_complete (dev, error);
}

static void
fpc2040_dev_activate (FpImageDevice *dev)
{
  FpiDeviceFpc2040 *self = FPI_DEVICE_FPC2040 (dev);
  GCancellable *c = fpi_device_get_cancellable (FP_DEVICE (dev));
  GError *error = NULL;

  if (!fpc_session_start (self, c, &error))
    {
      fpi_image_device_activate_complete (dev, error);
      return;
    }

  /* Private cancellable: cancelling the action's own cancellable would
   * make libfprint report the capture as cancelled.  libfprint calls
   * deactivate() when the action is cancelled, which cancels this one. */
  self->cancellable = g_cancellable_new ();
  self->running = TRUE;
  g_atomic_int_set (&self->thread_done, 0);
  self->thread = g_thread_new ("fpc2040-capture", fpc_capture_thread, self);
  fpi_image_device_activate_complete (dev, NULL);
}

/* The capture thread calls g_usb_device_bulk_transfer(), whose synchronous
 * wrapper runs a GMainLoop on the default context.  Joining it from a main
 * context callback would hold the context lock and deadlock, so wait for it
 * from a timeout source instead. */
static gboolean
fpc_deactivate_poll (gpointer data)
{
  FpiDeviceFpc2040 *self = data;

  if (!g_atomic_int_get (&self->thread_done))
    return G_SOURCE_CONTINUE;

  g_thread_join (self->thread);
  self->thread = NULL;
  fpc_session_stop (self);
  g_clear_object (&self->cancellable);
  fpi_image_device_deactivate_complete (FP_IMAGE_DEVICE (self), NULL);
  g_object_unref (self);
  return G_SOURCE_REMOVE;
}

static void
fpc2040_dev_deactivate (FpImageDevice *dev)
{
  FpiDeviceFpc2040 *self = FPI_DEVICE_FPC2040 (dev);

  self->running = FALSE;
  if (self->cancellable)
    g_cancellable_cancel (self->cancellable);

  if (self->thread)
    {
      g_timeout_add (10, fpc_deactivate_poll, g_object_ref (self));
      return;
    }

  fpc_session_stop (self);
  g_clear_object (&self->cancellable);
  fpi_image_device_deactivate_complete (dev, NULL);
}

/* ------------------------------------------------------------------ */
/* GObject                                                            */
/* ------------------------------------------------------------------ */

static void
fpi_device_fpc2040_init (FpiDeviceFpc2040 *self)
{
  self->inner_buf = g_malloc0 (FPC2040_INNER_BUF_SIZE);
  self->inner_len = 0;
}

static void
fpi_device_fpc2040_finalize (GObject *object)
{
  FpiDeviceFpc2040 *self = FPI_DEVICE_FPC2040 (object);

  self->running = FALSE;
  if (self->cancellable)
    g_cancellable_cancel (self->cancellable);
  if (self->thread)
    {
      g_thread_join (self->thread);
      self->thread = NULL;
    }
  fpc_session_stop (self);
  g_clear_object (&self->cancellable);
  g_free (self->inner_buf);

  G_OBJECT_CLASS (fpi_device_fpc2040_parent_class)->finalize (object);
}

static void
fpi_device_fpc2040_class_init (FpiDeviceFpc2040Class *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  object_class->finalize = fpi_device_fpc2040_finalize;

  dev_class->id = "fpc2040";
  dev_class->full_name = "Fingerprint Cards Disum (Honor MagicBook X)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->nr_enroll_stages = FPC2040_NR_ENROLL_STAGES;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  /* The sensor has its own hardware overheat protection (it resets the
   * link); libfprint's software thermal guard trips mid-enrollment and
   * aborts with FP_DEVICE_ERROR_TOO_HOT.  Disable it. */
  dev_class->temp_hot_seconds = -1;
  /* Prints are matched and stored on the host (NBIS + fprintd), so no
   * FP_DEVICE_FEATURE_STORAGE: that would require marking prints as
   * device-stored and makes fprintd reject the enrollment. */
  dev_class->features = FP_DEVICE_FEATURE_CAPTURE |
                        FP_DEVICE_FEATURE_VERIFY |
                        FP_DEVICE_FEATURE_IDENTIFY;

  img_class->img_open = fpc2040_dev_open;
  img_class->img_close = fpc2040_dev_close;
  img_class->activate = fpc2040_dev_activate;
  img_class->deactivate = fpc2040_dev_deactivate;
  /* Observed genuine-match bozorth3 scores: 16-30 (with ~50-70 minutiae
   * probes after the 2x upscale).  15 keeps a comfortable margin without
   * meaningfully raising the false-accept rate. */
  img_class->bz3_threshold = 15;
}
