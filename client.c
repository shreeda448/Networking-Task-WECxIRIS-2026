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
  D_Keys dk;
  int res = do_handshake_client(fd, k, &dk);
  if (res == -1) {
    cleanup_keys(k);
    goto clean;
  }
  fprintf(stdout, "handshake successfull\n");
  cleanup_keys(k);
  free(k);
  while (1) {
    uint8_t *msg = (uint8_t *)malloc(MAX_BUFFER * sizeof(uint8_t));
    if (msg == NULL) {
      printf("Memory allocation failed!\n");
      return 1;
    }
    printf("Enter your message: ");
    if (scanf(" %1023[^\n]", (char *)msg) != 1) {
      goto clean;
    }
    printf("Message stored successfully.\n");
    size_t msg_len = strlen((char *)msg);
    Frame hello = {0};
    res = gen_data_frame(msg, msg_len, dk.encryption_client, &hello);
    if (res != -0) {
      printf("failed to encrypt the message");
      goto clean;
    }
    res = send_frame(fd, &hello);
    if (res != 0) {
      free(msg);
      goto clean;
    }
    Frame out = {0};
    res = recv_frame(fd, &out);
    if (res != 0) {
      free(msg);
      goto clean;
    }
    size_t ciphertext_len = out.len - NONCE_SIZE - TAG_SIZE;
    unsigned char *nonce = out.payload;
    unsigned char *ciphertext = out.payload + NONCE_SIZE;
    unsigned char *tag = out.payload + NONCE_SIZE + ciphertext_len;
    plain = malloc(ciphertext_len);
    res = gcm_decrypt(ciphertext, ciphertext_len, NULL, 0, tag,
                      dk.encryption_server, nonce, NONCE_SIZE, plain);
    if (res == -1) {
      free(plain);
      goto clean;
    }
    for (size_t i = 0; i < ciphertext_len; i++) {
      printf("%c", plain[i]);
    }
    printf("\n");
    free(plain);
  }
  close(fd);
  dh_cleanup();
  return 0;
clean:
  close(fd);
  dh_cleanup();
  return 1;
}
