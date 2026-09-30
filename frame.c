#include "frame.h"
#include "config.h"
#include "io.h"
#include "stdint.h"
#include <stdint.h>

void encode_header(uint8_t hdr[HEADER_SIZE], uint8_t type, uint32_t len) {
  // extracting the len info byte by byte;
  // len is in machine native format but hdr stores len in big endian
  hdr[0] = type;
  hdr[1] = ((len >> 24) & 0xFF); // MSB
  hdr[2] = ((len >> 16) & 0xFF);
  hdr[3] = ((len >> 8) & 0xFF);
  hdr[4] = ((len) & 0xFF);
}

void decode_header(const uint8_t hdr[HEADER_SIZE], uint8_t *type,
                   uint32_t *len) {
  *type = hdr[0];
  *len = ((uint32_t)hdr[1] << 24) | ((uint32_t)hdr[2] << 16) |
         ((uint32_t)hdr[3] << 8) |
         (uint32_t)hdr[4]; // len in machine native format
}

int send_frame(int fd, Frame *in) {
  if (in->len > MAX_PAYLOAD) {
    return -1; // can't send this large payload
  }
  uint8_t hdr[HEADER_SIZE];
  encode_header(hdr, in->type, in->len);
  int res = write_all(fd, hdr, 5);
  if (res == -1) {
    return -1;
  }
  res = write_all(fd, in->payload, in->len);
  if (res == -1) {
    return -1;
  }
  return 0;
}

int recv_frame(int fd, Frame *out) {
  out->type = 0;
  out->len = 0;
  out->payload = NULL;
  uint8_t hdr[HEADER_SIZE];
  if (read_all(fd, hdr, HEADER_SIZE) == -1) {
    DEBUG_LOG(stderr, "recv: header\n");
    return -1;
  };
  uint8_t type;
  uint32_t len;
  decode_header(hdr, &type, &len);
  if (len > MAX_PAYLOAD) {
    DEBUG_LOG(stderr, "recv: too big\n");
    return -1; // can't recieve this large payload
  }
  uint8_t *payload = NULL;
  if (len > 0) {
    payload = malloc(len);
    if (payload == NULL) { // only meaningful when len > 0
      DEBUG_LOG(stderr, "recv: malloc\n");
      return -1;
    }
    if (read_all(fd, payload, len) == -1) {
      DEBUG_LOG(stderr, "recv: payload\n");
      free(payload);
      return -1;
    }
  }
  out->type = type;
  out->len = len;
  out->payload = payload; // NULL is correct when len == 0
  return 0;
}

void frame_free(Frame *f) {
  free(f->payload);
  f->payload = NULL;
  f->len = 0;
}
