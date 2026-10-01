#include "frame.h"
#include "io.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
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
    _exit(0);
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
// EOF in the middle of a read: peer sends 3 bytes then closes, we wait for 5
static void test_eof_mid_read(void) {
  int sv[2];
  pair(sv);
  uint8_t b[3] = {1, 2, 3}, buf[5];
  assert(write_all(sv[1], b, 3) == 0);
  close(sv[1]);
  assert(read_all(sv[0], buf, 5) == -1); // must fail, not hang
  close(sv[0]);
}

// zero-length calls are a no-op success (guards the `while (total < bytes)`
// logic)
static void test_zero_bytes(void) {
  int sv[2];
  pair(sv);
  uint8_t buf[1];
  assert(read_all(sv[0], buf, 0) == 0);
  assert(write_all(sv[1], buf, 0) == 0);
  close(sv[0]);
  close(sv[1]);
}

// writing to a closed peer must return -1, not kill us with SIGPIPE
static void test_write_closed_peer(void) {
  int sv[2];
  pair(sv);
  close(sv[0]);
  uint8_t b[16] = {0};
  int rc = 0;
  for (int i = 0; i < 5 && rc == 0;
       i++) // over TCP the first send can still succeed
    rc = write_all(sv[1], b, sizeof b);
  assert(rc == -1);
  close(sv[1]);
}

static void test_max_size_frame(void) {
  int sv[2];
  pair(sv);
  pid_t pid = fork();
  assert(pid >= 0);
  if (pid == 0) { // child: sender
    close(sv[0]);
    uint8_t *buf = malloc(MAX_PAYLOAD);
    for (uint32_t i = 0; i < MAX_PAYLOAD; i++)
      buf[i] = i % 251;
    Frame f = {MSG_DATA, MAX_PAYLOAD, buf};
    int rc = send_frame(sv[1], &f);
    free(buf);
    _exit(rc == 0 ? 0 : 1);
  }
  close(sv[1]); // parent: receiver
  Frame r;
  assert(recv_frame(sv[0], &r) == 0);
  assert(r.type == MSG_DATA && r.len == MAX_PAYLOAD);
  for (uint32_t i = 0; i < MAX_PAYLOAD; i++)
    assert(r.payload[i] == i % 251);
  frame_free(&r);
  close(sv[0]);
  int status;
  waitpid(pid, &status, 0);
  assert(WIFEXITED(status) &&
         WEXITSTATUS(status) == 0); // child's result counts too
}

static void test_fragmented_frame(void) {
  int sv[2];
  pair(sv);
  pid_t pid = fork();
  assert(pid >= 0);
  if (pid == 0) {
    close(sv[0]);
    uint8_t wire[HEADER_SIZE + 10];
    encode_header(wire, MSG_DATA, 10);
    for (int i = 0; i < 10; i++)
      wire[HEADER_SIZE + i] = (uint8_t)(100 + i);
    for (size_t i = 0; i < sizeof wire; i++) {
      (void)write(sv[1], &wire[i], 1);
      usleep(20000);
    }
    _exit(0);
  }
  close(sv[1]);
  Frame r;
  assert(recv_frame(sv[0], &r) == 0);
  assert(r.type == MSG_DATA && r.len == 10 && r.payload[0] == 100 &&
         r.payload[9] == 109);
  frame_free(&r);
  close(sv[0]);
  waitpid(pid, NULL, 0);
}

static void test_closed_before_or_inside_header(void) {
  int sv[2];
  pair(sv);
  close(sv[1]); // nothing sent at all
  Frame f;
  assert(recv_frame(sv[0], &f) == -1 && f.payload == NULL);
  close(sv[0]);

  pair(sv);
  uint8_t h[3] = {MSG_DATA, 0, 0}; // 3 of the 5 header bytes
  assert(write_all(sv[1], h, 3) == 0);
  close(sv[1]);
  assert(recv_frame(sv[0], &f) == -1 && f.payload == NULL);
  close(sv[0]);
}

static void test_send_frame_rejects_bad_input(void) {
  int sv[2];
  pair(sv);
  uint8_t x = 0;
  Frame too_big = {MSG_DATA, MAX_PAYLOAD + 1, &x}; // rejected before x is read
  assert(send_frame(sv[1], &too_big) == -1);
  close(sv[0]);
  close(sv[1]);
}

static void test_huge_length_rejected(void) {
  int sv[2];
  pair(sv);
  uint8_t hdr[HEADER_SIZE];
  encode_header(hdr, MSG_DATA, 0xFFFFFFFFu); // claims a 4 GB payload
  assert(write_all(sv[1], hdr, HEADER_SIZE) == 0);
  Frame f;
  assert(recv_frame(sv[0], &f) == -1);
  assert(f.payload == NULL);
  close(sv[0]);
  close(sv[1]);
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
  test_write_closed_peer();
  puts("write to closed peer: ok");
  test_eof_mid_read();
  puts("eof mid read: ok");
  test_zero_bytes();
  puts("zero bytes: ok");
  test_send_frame_rejects_bad_input();
  puts("send_frame_rejects_bad_input: ok");
  test_max_size_frame();
  puts("max_size_frame: ok");
  test_fragmented_frame();
  puts("fragmented_fram: ok");
  test_closed_before_or_inside_header();
  puts("closed_before_or_inside_header: ok");
  test_huge_length_rejected();
  puts("huge_length_regected: ok");
}
