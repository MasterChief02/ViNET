#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

uint16_t calculateIPChecksum(struct iphdr *ipHeader) {
    uint32_t sum = 0;
    uint16_t *buffer = (uint16_t *)ipHeader;
    int size = ipHeader->ihl * 4; // Size of the IP header in bytes

    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }

    if (size == 1) {
        sum += *(uint8_t *)buffer;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

// Define a function to calculate the UDP checksum
uint16_t calculateUDPChecksum(struct iphdr *ipHeader, struct udphdr *udpHeader, unsigned char *payload, int payloadLen) {

    struct {
        uint32_t sourceIP;
        uint32_t destIP;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udpLength;
    } pseudoHeader;

    pseudoHeader.sourceIP = ipHeader->saddr;
    pseudoHeader.destIP = ipHeader->daddr;
    pseudoHeader.zero = 0;
    pseudoHeader.protocol = IPPROTO_UDP;
    pseudoHeader.udpLength = htons(payloadLen + sizeof(struct udphdr));


    uint32_t sum = 0;
    uint16_t *buf = (uint16_t *)&pseudoHeader;
    int pseudolen = sizeof(pseudoHeader);

    while (pseudolen > 1) {
        sum += *buf++;
        pseudolen -= 2;
    }


    buf = (uint16_t *)udpHeader;
    int udpLen = payloadLen + sizeof(struct udphdr);

    while (udpLen > 1) {
        sum += *buf++;
        udpLen -= 2;
    }


    if (udpLen) {
        sum += *((uint8_t *)buf);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);

    unsigned char *pktData;
    int len = nfq_get_payload(nfa, &pktData);

    struct iphdr *ipHeader = (struct iphdr *)pktData;

    struct udphdr *udpHeader = (struct udphdr *)(pktData + ipHeader->ihl * 4);
    int payloadOffset = ipHeader->ihl * 4 + sizeof(struct udphdr);
    int new_payload_len = len - payloadOffset + 4;
    int new_len = ipHeader->ihl * 4 + sizeof(struct udphdr) + new_payload_len;

    // Recalculate IP checksum after modification
    ipHeader->tot_len = htons(new_len);
    ipHeader->check = 0;
    ipHeader->check = calculateIPChecksum(ipHeader);

    unsigned char *modified_pkt = (unsigned char *)malloc(new_len);
    if (!modified_pkt) {
        perror("Error in malloc()");
        return -1;
    }
    memcpy(modified_pkt, pktData, ipHeader->ihl * 4 + sizeof(struct udphdr)); 
    memcpy(&modified_pkt[ipHeader->ihl * 4 + sizeof(struct udphdr)], &pktData[payloadOffset], len - payloadOffset); // Copy the original payload
    memset(&modified_pkt[new_len - 4], 0xFF, 4); 

    udpHeader = (struct udphdr *)(modified_pkt + ipHeader->ihl * 4); 
    udpHeader->len = htons(new_payload_len + sizeof(struct udphdr)); 
    udpHeader->check = 0;
    udpHeader->check = calculateUDPChecksum(ipHeader, udpHeader, modified_pkt + ipHeader->ihl * 4 + sizeof(struct udphdr), new_payload_len);

    int verdict = nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, new_len, modified_pkt);
    free(modified_pkt);
    return verdict;
}

int main() {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;

    h = nfq_open();
    if (!h) {
        perror("Error in nfq_open()");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        perror("Error in nfq_unbind_pf()");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("Error in nfq_bind_pf()");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &callback, NULL);
    if (!qh) {
        perror("Error in nfq_create_queue()");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("Error in nfq_set_mode()");
        exit(1);
    }

    int fd = nfq_fd(h);
    char buf[4096];
    int rv;

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}

