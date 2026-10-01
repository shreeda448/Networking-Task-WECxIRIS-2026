#include "config.h"
#include "frame.h"
#include "io.h"
#include "net.h"
#include "unistd.h"
#include <stdint.h>

int main(void) {
  int serverfd = tcp_listen(port);
  int connfd = tcp_accept(serverfd);
  Frame in;
  uint8_t last_type = 0;
  while (recv_frame(connfd, &in) == 0) {
    printf("got type=%u len=%u: ", in.type, in.len);
    last_type = in.type;
    printf("\n");
    int done = (in.type == MSG_CLOSE);
    int rc = send_frame(connfd, &in);
    frame_free(&in);
    if (rc < 0 || done)
      break;
  }
  if (last_type != MSG_CLOSE) {
    fprintf(stderr, "closing: bad or missing frame\n");
  }
  close(connfd);
  close(serverfd);
  return 0;
}
