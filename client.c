#include "config.h"
#include "frame.h"
#include "handshake.h"
#include "io.h"
#include "net.h"
#include "stdio.h"
#include "unistd.h"
#include <openssl/bn.h>
#include <stdint.h>
#include <sys/types.h>

int main(void) {
  if (dh_init() < 0) {
    fprintf(stderr, "dh_init failed\n");
    return 1;
  }
  int fd = tcp_connect();
  // client role in diffie hellman key-exchange
  //  Generate the private key
  //  Generate the public key
  //  send the public key to the server (in payload), type HELLO
  // Recieve the public key of the server , type HELLO
  // Generate the shared secret key
  // Generate the transcript using the public  keys
  // free the public keys and private keys
  //  Generate the derived keys
  // free the shared secret key
  // recieve the ALERT/FINISHED
  // start transmitting the data
  Keys *k = gen_key_pair();
  if (!k) {
    goto clean;
  }
  int res = do_handshake_client(fd, k);
  if (res == -1) {
    cleanup_keys(k);
    goto clean;
  }
  fprintf(stdout, "handshake successfull\n");
  cleanup_keys(k);
  free(k);
  close(fd);
  dh_cleanup();
  return 0;
clean:
  close(fd);
  dh_cleanup();
  return 1;
}
