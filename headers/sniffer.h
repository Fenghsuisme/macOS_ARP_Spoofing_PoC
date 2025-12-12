#ifndef SNIFFER_H
#define SNIFFER_H
#include "common.h"

void start_sniffer(MitmContext *ctx);
void add_new_victim(MitmContext *ctx, uint32_t ip, uint8_t *mac);

#endif