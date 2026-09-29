#include "arpa/inet.h"
#include "netinet/in.h"
#include "stdio.h"
#include "stdlib.h"
#include "sys/socket.h"
#include <stddef.h>
#define port 8080
#define buffSize 1024

int tcp_listen(int port_num) {
  int serverSocketfd = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSocketfd == -1) {
    perror("socker error\n");
    exit(-1);
  }
  printf("socket created successfully\n");
  struct sockaddr_in socketAddress = {AF_INET, htons(port_num),
                                      inet_addr("127.0.0.1")};
  int bindResult = bind(serverSocketfd, (struct sockaddr *)&socketAddress,
                        sizeof(socketAddress));
  if (bindResult == -1) {
    perror("binding error\n");
    exit(-1);
  }
  int maxPendingConn = 1;
  int listenResult = listen(serverSocketfd, maxPendingConn);
  printf("Server is running and listening on port 8080...\n");
  return serverSocketfd;
}

int tcp_accept(int serverSocketfd) {
  struct sockaddr clientAddr;
  socklen_t clientAddrlen = sizeof(clientAddr);
  int connectionfd = accept(serverSocketfd, (struct sockaddr *)&clientAddr,
                            (socklen_t *)&clientAddrlen);
  if (connectionfd == -1) {
    perror("Failed to accept connection\n");
    exit(-1);
  }
  printf("connection accepted. \n");
  return connectionfd;
}

int tcp_connect() {
  int clientSocketfd = socket(AF_INET, SOCK_STREAM, 0);
  if (clientSocketfd == -1) {
    perror("socker  error");
    exit(-1);
  }
  printf("socket created successfully\n");
  struct sockaddr_in socketAddress = {AF_INET, htons(port),
                                      inet_addr("127.0.0.1")};
  int connectResult = connect(clientSocketfd, (struct sockaddr *)&socketAddress,
                              sizeof(socketAddress));
  if (connectResult == -1) {
    perror("connection error");
    exit(-1);
  }
  return clientSocketfd;
}
