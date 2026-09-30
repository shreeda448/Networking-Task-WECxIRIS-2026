#include "config.h"
#include "frame.h"
#include "io.h"
#include "net.h"
#include "stdio.h"
#include "stdlib.h"
#include "unistd.h"
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

static int round_trip(int fd, uint8_t type, const uint8_t *data, uint32_t len) {
  Frame out = {type, len, (uint8_t *)data};
  Frame in;
  if (send_frame(fd, &out) < 0)
    return -1;
  if (recv_frame(fd, &in) < 0)
    return -1;

  int same = in.type == out.type && in.len == out.len &&
             (len == 0 || memcmp(in.payload, data, len) == 0);
  printf("type=%u len=%u: %s\n", type, len, same ? "PASS" : "FAIL");
  frame_free(&in);
  return same ? 0 : -1;
}

int main(void) {
  int fd = tcp_connect();
  int failures = 0;

  const char *hello = "hello";
  failures += round_trip(fd, MSG_HELLO, (const uint8_t *)hello, 5) < 0;

  uint32_t big_len = 100 * 1024; // bigger than one recv typically returns
  uint8_t *big;
  uint8_t *t = malloc(big_len);
  if (t == NULL) {
    close(fd);
    return 1;
  }
  big = t;
  for (uint32_t i = 0; i < big_len; i++)
    big[i] = i % 251;
  if (round_trip(fd, MSG_DATA, big, big_len) < 0) {
    close(fd);
    free(big);
    return 1;
  };
  free(big);

  uint8_t bin[] = {0x00, 0xFF, 0x10, 0x00}; // zero bytes inside a payload
  if (round_trip(fd, MSG_ALERT, bin, sizeof bin) < 0) {
    close(fd);
    return 1;
  }

  if (round_trip(fd, MSG_CLOSE, NULL, 0) < 0) {
    close(fd);
    return 1;
  };

  close(fd);
  return failures ? 1 : 0;
}
