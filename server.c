#include "config.h"
#include "handshake.h"
#include "io.h"
#include "net.h"
#include "unistd.h"
#include <openssl/bn.h>
#include <stdint.h>

int main(void) {
  if (dh_init() < 0) {
    fprintf(stderr, "dh_init failed\n");
    return 1;
  }
  int serverfd = tcp_listen(port);
  int connfd = tcp_accept(serverfd);
  Keys *k = gen_key_pair();
  if (!k) {
    goto clean;
  }
  int res = do_handshake_server(connfd, k);
  if (res == -1) {
    cleanup_keys(k);
    goto clean;
  }
  printf("handshake successfull\n");

  cleanup_keys(k);
  free(k);
  close(connfd);
  close(serverfd);
  dh_cleanup();
  return 0;
clean:
  close(connfd);
  close(serverfd);
  dh_cleanup();
  return 1;
}
