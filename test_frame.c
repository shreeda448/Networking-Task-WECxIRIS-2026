#include "frame.h"
#include "io.h"
#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void test_header(void) {
  uint8_t hdr[HEADER_SIZE], t;
  uint32_t l;
  encode_header(hdr, 3, 258);
  const uint8_t expect[] = {3, 0, 0, 1, 2};
  assert(memcmp(hdr, expect, HEADER_SIZE) == 0);

  uint32_t lens[] = {0, 1, 258, 0x7FFFFFFF, 0x80000000u, 0xFFFFFFFFu};
  for (size_t i = 0; i < sizeof lens / sizeof *lens; i++) {
    encode_header(hdr, 0xAB, lens[i]);
    decode_header(hdr, &t, &l);
    assert(t == 0xAB && l == lens[i]);
  }
}

static void test_slow_writer(void) {
  int sv[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  if (fork() == 0) { // child: dribble 5 bytes
    close(sv[0]);
    for (uint8_t i = 1; i <= 5; i++) {
      write(sv[1], &i, 1);
      usleep(50000);
    }
    exit(0);
  }
  close(sv[1]);
  uint8_t buf[5];
  assert(read_all(sv[0], buf, 5) == 0);
  assert(buf[0] == 1 && buf[4] == 5);
  close(sv[0]);
  wait(NULL);
}

static void test_oversize_rejected(void) {
  int sv[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  uint8_t hdr[HEADER_SIZE];
  encode_header(hdr, MSG_DATA, MAX_PAYLOAD + 1);
  assert(write_all(sv[1], hdr, HEADER_SIZE) == 0);
  Frame f;
  assert(recv_frame(sv[0], &f) == -1);
  assert(f.payload == NULL);
  close(sv[0]);
  close(sv[1]);
}

static void pair(int sv[2]) {
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
}

// test 11: empty payload (also exercises write_all with 0 bytes)
static void test_empty_frame(void) {
  int sv[2];
  pair(sv);
  Frame in = {MSG_CLOSE, 0, NULL}, out;
  assert(send_frame(sv[1], &in) == 0);
  assert(recv_frame(sv[0], &out) == 0);
  assert(out.type == MSG_CLOSE && out.len == 0 && out.payload == NULL);
  frame_free(&out); // must not crash on NULL
  close(sv[0]);
  close(sv[1]);
}

// test 14: three frames written before any is read; boundaries must hold
static void test_back_to_back(void) {
  int sv[2];
  pair(sv);
  uint8_t big[1000];
  memset(big, 0xAB, sizeof big);
  Frame a = {MSG_HELLO, 1, (uint8_t[]){0x42}};
  Frame b = {MSG_DATA, sizeof big, big};
  Frame c = {MSG_CLOSE, 0, NULL};
  assert(send_frame(sv[1], &a) == 0);
  assert(send_frame(sv[1], &b) == 0);
  assert(send_frame(sv[1], &c) == 0);

  Frame r;
  assert(recv_frame(sv[0], &r) == 0);
  assert(r.type == MSG_HELLO && r.len == 1 && r.payload[0] == 0x42);
  frame_free(&r);
  assert(recv_frame(sv[0], &r) == 0);
  assert(r.type == MSG_DATA && r.len == 1000 &&
         memcmp(r.payload, big, 1000) == 0);
  frame_free(&r);
  assert(recv_frame(sv[0], &r) == 0);
  assert(r.type == MSG_CLOSE && r.len == 0);
  frame_free(&r);
  close(sv[0]);
  close(sv[1]);
}

// test 21: header promises 100 bytes, only 10 arrive, then EOF
static void test_truncated_payload(void) {
  int sv[2];
  pair(sv);
  uint8_t hdr[HEADER_SIZE], junk[10] = {0};
  encode_header(hdr, MSG_DATA, 100);
  assert(write_all(sv[1], hdr, HEADER_SIZE) == 0);
  assert(write_all(sv[1], junk, 10) == 0);
  close(sv[1]); // EOF after 10 of 100 bytes
  Frame f;
  assert(recv_frame(sv[0], &f) == -1);
  assert(f.payload == NULL); // nothing half-built left behind
  close(sv[0]);
}

int main(void) {
  test_header();
  puts("header: ok");
  test_slow_writer();
  puts("slow writer: ok");
  test_oversize_rejected();
  puts("oversize: ok");
  test_truncated_payload();
  puts("truncated_payload: ok");
  test_empty_frame();
  puts("empty_payload: ok");
  test_back_to_back();
  puts("back_to_back: ok");
}
