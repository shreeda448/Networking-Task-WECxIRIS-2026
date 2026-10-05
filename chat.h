#ifndef CHAT_H
#define CHAT_H
#include "enc.h"
#include "frame.h"
#include "string.h"
#include <stdint.h>
int gen_data_frame(uint8_t *msg, size_t msg_len, uint8_t *enc_key, Frame *f);
#endif
