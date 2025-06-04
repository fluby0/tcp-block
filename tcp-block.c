#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>

#define MAC_LEN 6
#define ETH_TYPE_IP 0x0800
#define REDIRECT_MSG "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n"

#pragma pack(push, 1)
typedef struct {
    uint8_t dmac[MAC_LEN];
    uint8_t smac[MAC_LEN];
    uint16_t type;
} EthHdr;

typedef struct {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} IpHdr;

typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t offset;
    uint8_t flags;
    uint16_t win;
    uint16_t sum;
    uint16_t urp;
} TcpHdr;

typedef struct {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_len;
} PseudoHdr;
#pragma pack(pop)

void usage() {
    printf("syntax: tcp-block <interface> <pattern>\n");
    printf("sample: tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

bool get_Mac(char* dev, uint8_t* mac_buf) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return false;
    }
    memcpy(mac_buf, ifr.ifr_hwaddr.sa_data, MAC_LEN);
    close(sock);
    return true;
}

uint16_t checksum(const void* data, int len) {
    const uint16_t* ptr = data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len) sum += *(uint8_t*)ptr;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

int match_pattern(const uint8_t* data, int len, const char* pattern) {
    if (len < 4 || memcmp(data, "GET ", 4) != 0) return 0;

    int target_len = strlen(pattern);
    if (target_len == 0) return 0;

    for (int i = 4; i <= len - target_len; i++) {
        int match = 1;
        for (int j = 0; j < target_len; j++) {
            if (data[i + j] != pattern[j]) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}


void send_RST_flag(pcap_t* pcap, const EthHdr* eth, const IpHdr* ip, const TcpHdr* tcp, const uint8_t* my_mac, int payload_len) {
    uint8_t buf[sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr)] = {0};
    EthHdr* e = (EthHdr*)buf;
    IpHdr* iph = (IpHdr*)(buf + sizeof(EthHdr));
    TcpHdr* tcph = (TcpHdr*)(buf + sizeof(EthHdr) + sizeof(IpHdr));

    memcpy(e->dmac, eth->dmac, MAC_LEN);
    memcpy(e->smac, my_mac, MAC_LEN);
    e->type = htons(ETH_TYPE_IP);

    iph->ver_ihl = 0x45;
    iph->tos = 0;
    iph->total_len = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->proto = IPPROTO_TCP;
    iph->saddr = ip->saddr;
    iph->daddr = ip->daddr;
    iph->check = 0;
    iph->check = checksum(iph, sizeof(IpHdr));

    tcph->sport = tcp->sport;
    tcph->dport = tcp->dport;
    tcph->seq = htonl(ntohl(tcp->seq) + payload_len);
    tcph->ack = tcp->ack;
    tcph->offset = (sizeof(TcpHdr) / 4) << 4;
    tcph->flags = 0x14;
    tcph->win = htons(512);
    tcph->sum = 0;
    tcph->urp = 0;

    PseudoHdr pseudo;
    pseudo.saddr = iph->saddr;
    pseudo.daddr = iph->daddr;
    pseudo.reserved = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_len = htons(sizeof(TcpHdr));

    uint8_t cksum[sizeof(PseudoHdr) + sizeof(TcpHdr)];
    memcpy(cksum, &pseudo, sizeof(PseudoHdr));
    memcpy(cksum + sizeof(PseudoHdr), tcph, sizeof(TcpHdr));
    tcph->sum = checksum(cksum, sizeof(cksum));

    pcap_sendpacket(pcap, buf, sizeof(buf));
}

void send_FIN_flag(const IpHdr* ip, const TcpHdr* tcp, int payload_len) {
    const char* msg = REDIRECT_MSG;
    int msg_len = strlen(msg);
    int pkt_len = sizeof(IpHdr) + sizeof(TcpHdr) + msg_len;
    uint8_t* pkt = calloc(1, pkt_len);
    if (!pkt) return;

    IpHdr* iph = (IpHdr*)pkt;
    TcpHdr* tcph = (TcpHdr*)(pkt + sizeof(IpHdr));
    uint8_t* data = pkt + sizeof(IpHdr) + sizeof(TcpHdr);

    iph->ver_ihl = 0x45;
    iph->tos = 0;
    iph->total_len = htons(pkt_len);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->proto = IPPROTO_TCP;
    iph->saddr = ip->daddr;
    iph->daddr = ip->saddr;
    iph->check = 0;
    iph->check = checksum(iph, sizeof(IpHdr));

    tcph->sport = tcp->dport;
    tcph->dport = tcp->sport;
    tcph->seq = tcp->ack;
    tcph->ack = htonl(ntohl(tcp->seq) + payload_len);
    tcph->offset = (sizeof(TcpHdr) / 4) << 4;
    tcph->flags = 0x11;
    tcph->win = htons(512);
    tcph->sum = 0;
    tcph->urp = 0;

    memcpy(data, msg, msg_len);

    PseudoHdr pseudo;
    pseudo.saddr = iph->saddr;
    pseudo.daddr = iph->daddr;
    pseudo.reserved = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_len = htons(sizeof(TcpHdr) + msg_len);

    uint8_t* cksum = malloc(sizeof(PseudoHdr) + sizeof(TcpHdr) + msg_len);
    memcpy(cksum, &pseudo, sizeof(PseudoHdr));
    memcpy(cksum + sizeof(PseudoHdr), tcph, sizeof(TcpHdr) + msg_len);
    tcph->sum = checksum(cksum, sizeof(PseudoHdr) + sizeof(TcpHdr) + msg_len);
    free(cksum);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { free(pkt); return; }
    int on = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = iph->daddr;
    dst.sin_port = tcph->dport;
    sendto(sock, pkt, pkt_len, 0, (struct sockaddr*)&dst, sizeof(dst));
    close(sock);
    free(pkt);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return EXIT_FAILURE;
    }
    char* dev = argv[1];
    const char* pattern = argv[2];

    uint8_t my_mac[MAC_LEN];
    if (!get_Mac(dev, my_mac)) {
        fprintf(stderr, "Failed to get local MAC\n");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!pcap) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    while (1) {
        struct pcap_pkthdr* hdr;
        const u_char* pkt;
        int res = pcap_next_ex(pcap, &hdr, &pkt);
        if (res != 1) continue;
        if (hdr->caplen < sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr)) continue;

        const EthHdr* eth = (const EthHdr*)pkt;
        if (ntohs(eth->type) != ETH_TYPE_IP) continue;
        const IpHdr* ip = (const IpHdr*)(pkt + sizeof(EthHdr));
        if (ip->proto != IPPROTO_TCP) continue;
        int ip_hdr_len = (ip->ver_ihl & 0x0F) * 4;
        const TcpHdr* tcp = (const TcpHdr*)(pkt + sizeof(EthHdr) + ip_hdr_len);
        int tcp_hdr_len = ((tcp->offset & 0xF0) >> 4) * 4;
        int data_offset = sizeof(EthHdr) + ip_hdr_len + tcp_hdr_len;
        int data_len = ntohs(ip->total_len) - ip_hdr_len - tcp_hdr_len;
        if (data_len <= 0) continue;
        const uint8_t* tcp_data = pkt + data_offset;

        if (match_pattern(tcp_data, data_len, pattern)) {
            send_RST_flag(pcap, eth, ip, tcp, my_mac, data_len);
            send_FIN_flag(ip, tcp, data_len);
        }
    }
    pcap_close(pcap);
    return 0;
}
