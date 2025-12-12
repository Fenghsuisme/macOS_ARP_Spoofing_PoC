#include "tools.h"
#include <ifaddrs.h>
#include <net/if_dl.h> 

void print_ip(const char* label, uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    printf("%s: %s\n", label, inet_ntoa(addr));
}

void print_mac(const char* label, uint8_t *mac) {
    printf("%s: %02X:%02X:%02X:%02X:%02X:%02X\n", label,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int get_mac_os_info(const char *iface, uint32_t *ip, uint8_t *mac, uint32_t *netmask) {
    struct ifaddrs *ifap, *ifa;
    int found_ip = 0, found_mac = 0;

    if (getifaddrs(&ifap) != 0) return -1;

    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, iface) != 0) continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            *ip = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
            *netmask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
            found_ip = 1;
        }
        else if (ifa->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
            memcpy(mac, LLADDR(sdl), 6);
            found_mac = 1;
        }
    }
    freeifaddrs(ifap);
    return (found_ip && found_mac) ? 0 : -1;
}

int get_default_gateway_mac_os(uint32_t *gw_ip) {
    FILE *fp = popen("route -n get default | grep 'gateway' | awk '{print $2}'", "r");
    if (!fp) return -1;

    char line[64];
    if (fgets(line, sizeof(line), fp) != NULL) {
        line[strcspn(line, "\n")] = 0; 
        inet_pton(AF_INET, line, gw_ip);
        pclose(fp);
        return 0;
    }
    pclose(fp);
    return -1;
}