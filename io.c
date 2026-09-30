#include "io.h"
#include "errno.h"
#include <stddef.h>
#include <sys/socket.h>

int send_msg(const char *msg, int sockfd, size_t siz) {
  int res = send(sockfd, msg, siz, MSG_NOSIGNAL);
  return res;
}

int recv_msg(void *buf, int sockfd, size_t siz) {
  int res = recv(sockfd, buf, siz, 0);
  return res;
}

int write_all(int sockfd, const uint8_t *wbuf, size_t bytes) {
  errno = 0;
  size_t bytes_sent = 0;
  while (bytes_sent < bytes) {
    int n = send(sockfd, wbuf + bytes_sent, bytes - bytes_sent, MSG_NOSIGNAL);
    if (n == 0) // peer closed before we gave everything
      return -1;
    if (n < 0) {
      if (errno == EINTR)
        continue; // interrupted, just retry
      return -1;  // real error
    }
    bytes_sent += (size_t)n;
  }
  return 0;
};

int read_all(int sockfd, uint8_t *rbuf, size_t bytes) {
  errno = 0;
  size_t bytes_read = 0;
  while (bytes_read < bytes) {
    int n = recv(sockfd, rbuf + bytes_read, bytes - bytes_read, 0);
    if (n == 0) // peer closed before we got everything
      return -1;
    if (n < 0) {
      if (errno == EINTR)
        continue; // interrupted, just retry
      return -1;  // real error
    }
    bytes_read += (size_t)n;
  }
  return 0;
};
