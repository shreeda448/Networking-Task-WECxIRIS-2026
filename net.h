#include "arpa/inet.h"
#include "netinet/in.h"
#include "stdio.h"
#include "stdlib.h"
#include "sys/socket.h"
#include <stddef.h>

int tcp_listen(int port_num);
int tcp_connect();
int tcp_accept(int serverSocketfd);
