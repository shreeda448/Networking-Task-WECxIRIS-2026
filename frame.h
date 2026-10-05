#ifndef CSL_FRAME_H
#define CSL_FRAME_H
#include "enc.h"
#include "stdint.h"
#define HEADER_SIZE 5
#define MAX_PAYLOAD (1u << 20)

// message types

enum msg_type : uint8_t {
  MSG_HELLO = 0x01,
  MSG_FINISHED,
  MSG_DATA,
  MSG_ALERT,
  MSG_CLOSE
};

// my message frame structure

typedef struct {
  uint8_t type;
  uint32_t len;
  uint8_t *payload;
} Frame;

int send_frame(int fd, Frame *in);
int recv_frame(int fd, Frame *out); // 0 on success, -1 on error/EOF/oversize

// Helper functions

void encode_header(uint8_t hdr[HEADER_SIZE], uint8_t type, uint32_t len);
void decode_header(const uint8_t hdr[HEADER_SIZE], uint8_t *type,
                   uint32_t *len);
void frame_free(Frame *f);
#endif
