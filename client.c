#include "config.h"
#include "io.h"
#include "net.h"
#include "stddef.h"
#include "unistd.h"
int main() {
  int fd = tcp_connect();
  const char *msg = "Testing message from client to server";
  send_msg(msg, fd, strlen(msg));

  char rbuf[buffSize];
  ssize_t n = recv_msg(rbuf, fd, sizeof rbuf);
  if (n <= 0) {
    perror("recv");
    return 1;
  }
  printf("reply: %.*s", (int)n, rbuf);

  close(fd);
  return 0;
}
