#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/socket.h"
#include <stddef.h>

int send_msg(const char *msg, int sockfd, size_t siz);
int recv_msg(void *buf, int sockfd, size_t siz);
