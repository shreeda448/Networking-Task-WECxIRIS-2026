#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/socket.h"
#include <stddef.h>
#include <stdint.h>

int send_msg(const char *msg, int sockfd, size_t siz);
int recv_msg(void *buf, int sockfd, size_t siz);
int write_all(int sockfd, const uint8_t *wbuf, size_t bytes);
int read_all(int sockfd, uint8_t *rbuf, size_t bytes);
