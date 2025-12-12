#ifndef TOOLS_H
#define TOOLS_H
#include "common.h"

int get_mac_os_info(const char *iface, uint32_t *ip, uint8_t *mac, uint32_t *netmask);
int get_default_gateway_mac_os(uint32_t *gw_ip);
void print_ip(const char* label, uint32_t ip);
void print_mac(const char* label, uint8_t *mac);

#endif