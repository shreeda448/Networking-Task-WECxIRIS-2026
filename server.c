#include "config.h"
#include "io.h"
#include "net.h"
#include "unistd.h"
#include <stddef.h>

int main() {
  int serverfd = tcp_listen(port);
  int connfd = tcp_accept(serverfd);

  char rbuf[buffSize];
  ssize_t n = recv_msg(rbuf, connfd, sizeof rbuf);
  if (n <= 0) {
    perror("recv");
    return 1;
  }
  printf("got %zd bytes: %.*s\n", n, (int)n,
         rbuf); // rbuf isn't null-terminated

  const char *reply = "Your message has been read by the server\n";
  send_msg(reply, connfd, strlen(reply));

  close(connfd);
  close(serverfd);
  return 0;
}
