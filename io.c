#include "stddef.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/socket.h"

int send_msg(const char *msg, int sockfd, size_t siz) {
  int res = send(sockfd, msg, siz, MSG_NOSIGNAL);
  return res;
}

int recv_msg(void *buf, int sockfd, size_t siz) {
  int res = recv(sockfd, buf, siz, 0);
  return res;
}
