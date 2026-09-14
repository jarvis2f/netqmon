/* Construct discovery traffic on a disposable OpenWrt test interface.
 * No captured packets are read, saved, or printed. */
#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned char packet[4096];
static size_t length;
static void bytes(const void *p, size_t n) {
    if (length + n > sizeof(packet)) abort();
    memcpy(packet + length, p, n); length += n;
}
static void u16(unsigned n) { unsigned char p[] = {n >> 8, n}; bytes(p, 2); }
static void dns_name(const char *name) {
    while (*name) {
        const char *end = strchr(name, '.');
        size_t n = end ? (size_t)(end-name) : strlen(name);
        unsigned char size = n; bytes(&size, 1); bytes(name, n);
        name += n; if (*name == '.') name++;
    }
    bytes("\0", 1);
}
static void udp4(unsigned port, const char *destination) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0), yes = 1;
    struct sockaddr_in local = {.sin_family=AF_INET, .sin_port=htons(port)};
    inet_pton(AF_INET, "192.0.2.2", &local.sin_addr);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &local.sin_addr, sizeof(local.sin_addr));
    if (bind(fd, (void *)&local, sizeof(local))) { perror("bind4"); exit(1); }
    inet_pton(AF_INET, destination, &local.sin_addr);
    if (sendto(fd, packet, length, 0, (void *)&local, sizeof(local)) != (ssize_t)length) { perror("send4"); exit(1); }
    close(fd);
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    unsigned index = if_nametoindex(argv[1]);
    if (!index) return 2;
    /* One complete TXT RR: instance and model are sufficient mDNS evidence. */
    u16(0); u16(0x8400); u16(0); u16(1); u16(0); u16(0);
    dns_name("Netqmon HP LaserJet._ipp._tcp.local");
    u16(16); u16(1); u16(0); u16(120);
    const char *model = "model=HP LaserJet";
    u16(1 + strlen(model) + 3 * 231);
    unsigned char n = strlen(model); bytes(&n, 1); bytes(model, n);
    for (int i=0; i<3; i++) {
        n = 230; bytes(&n, 1); bytes("pad=", 4);
        for (int j=0; j<226; j++) bytes("x", 1);
    }
    size_t mdns_length = length;
    udp4(5353, "224.0.0.251");
    length = 0;
    const char *headers = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: urn:schemas-upnp-org:device:Printer:1\r\nNTS: ssdp:alive\r\nSERVER: HP LaserJet UPnP/1.1\r\nUSN: uuid:netqmon-recognition\r\nX-Test: ";
    bytes(headers, strlen(headers));
    for (int j=0; j<650; j++) bytes("x", 1);
    bytes("\r\n\r\n", 4);
    size_t ssdp_length = length;
    udp4(1900, "239.255.255.250");
    length = 0;
    bytes("\1NQM", 4);
    u16(1); u16(10); bytes("\0\3\0\1\2\0\0\0\0\2", 10);
    u16(16); u16(17); bytes("\0\6\171\62", 4); u16(11); bytes("HP LaserJet", 11);
    u16(17); u16(19); bytes("\0\6\171\62", 4); u16(1); u16(11); bytes("HP LaserJet", 11);
    u16(39); u16(20); bytes("\0", 1); dns_name("HP-LaserJet.local");
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 addr = {.sin6_family=AF_INET6, .sin6_port=htons(546), .sin6_scope_id=index};
    inet_pton(AF_INET6, "fd42:6e71::2", &addr.sin6_addr);
    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &index, sizeof(index));
    if (bind(fd, (void *)&addr, sizeof(addr))) { perror("bind6"); return 1; }
    addr.sin6_port = htons(547);
    inet_pton(AF_INET6, "ff02::1:2", &addr.sin6_addr);
    if (sendto(fd, packet, length, 0, (void *)&addr, sizeof(addr)) != (ssize_t)length) { perror("send6"); return 1; }
    close(fd);
    printf("discovery_sent mdns_length=%zu ssdp_length=%zu dhcp6_length=%zu\n", mdns_length, ssdp_length, length);
    return 0;
}
