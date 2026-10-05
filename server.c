#include "chat.h"
#include "config.h"
#include "dh.h"
#include "enc.h"
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
  unsigned char *plain = NULL;
  int serverfd = tcp_listen(port);
  int connfd = tcp_accept(serverfd);
  Keys *k = gen_key_pair();
  if (!k) {
    goto clean;
  }
  D_Keys dk;
  int res = do_handshake_server(connfd, k, &dk);
  if (res == -1) {
    cleanup_keys(k);
    goto clean;
  }
  printf("handshake successfull\n");
  cleanup_keys(k);
  free(k);
  while (1) {
    Frame out = {0};
    res = recv_frame(connfd, &out);
    size_t ciphertext_len = out.len - NONCE_SIZE - TAG_SIZE;
    unsigned char *nonce = out.payload;
    unsigned char *ciphertext = out.payload + NONCE_SIZE;
    unsigned char *tag = out.payload + NONCE_SIZE + ciphertext_len;
    plain = malloc(ciphertext_len);
    res = gcm_decrypt(ciphertext, ciphertext_len, NULL, 0, tag,
                      dk.encryption_client, nonce, NONCE_SIZE, plain);
    if (res == -1) {
      free(plain);
      break;
      goto clean;
    }
    for (size_t i = 0; i < ciphertext_len; i++) {
      printf("%c", plain[i]);
    }
    printf("\n");
    Frame hello = {0};
    res = gen_data_frame(plain, ciphertext_len, dk.encryption_server, &hello);
    if (res != 0) {
      printf("failed to encrypt the message");
      free(plain);
      break;
      goto clean;
    }
    res = send_frame(connfd, &hello);
    if (res != 0) {
      free(plain);
      break;
      goto clean;
    }
    free(plain);
  }
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
