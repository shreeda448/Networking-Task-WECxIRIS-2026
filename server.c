#include "config.h"
#include "frame.h"
#include "io.h"
#include "net.h"
#include "unistd.h"

int main(void) {
  int serverfd = tcp_listen(port);
  int connfd = tcp_accept(serverfd);
  Frame in;
  while (recv_frame(connfd, &in) == 0) {
    printf("got type=%u len=%u: ", in.type, in.len);
    printf("\n");
    int done = (in.type == MSG_CLOSE);
    int rc = send_frame(connfd, &in);
    frame_free(&in);
    if (rc < 0 || done)
      break;
  }
  close(connfd);
  close(serverfd);
  return 0;
}
