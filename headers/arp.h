#ifndef ARP_H
#define ARP_H
#include "common.h"

#define ARPOP_REQUEST 1
#define ARPOP_REPLY   2

void send_arp_raw(pcap_t *handle, uint16_t op, uint8_t *src_mac, uint32_t src_ip, uint8_t *dst_mac, uint32_t dst_ip);
void *arp_spoof_loop(void *arg);
void *arp_scan_loop(void *arg);
int get_mac_of_ip(pcap_t *handle, uint8_t *my_mac, uint32_t my_ip, uint32_t target_ip, uint8_t *target_mac_out);
uint32_t scan_network_for_victim(pcap_t *handle, uint32_t my_ip, uint32_t gateway_ip, uint32_t netmask, uint8_t *my_mac);

#endif