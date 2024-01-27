#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>

uint16_t calc_ip_cheksum(struct iphdr *ipHeader) {
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

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *pkt_data;
    struct iphdr *ip_hdr;
    struct udphdr *udp_hdr;
    int pkt_len;
    struct timeval tval;

    ph = nfq_get_msg_packet_hdr(nfa);
    pkt_len = nfq_get_payload(nfa, &pkt_data);
    ip_hdr = (struct iphdr *)pkt_data;
    udp_hdr = (struct udphdr *)(pkt_data + ip_hdr->ihl * 4);

    gettimeofday(&tval, NULL);
    unsigned char modified_pkt[pkt_len + sizeof(struct timeval)];
    memcpy(modified_pkt, pkt_data, pkt_len);
    memcpy(modified_pkt + pkt_len, &tval, sizeof(struct timeval));
    // printf("tv_sec:%lu tv_usec:%lu\n", tval.tv_sec, tval.tv_usec);

    ip_hdr = (struct iphdr *) modified_pkt;
    ip_hdr->tot_len = htons(pkt_len + sizeof(struct timeval));
    ip_hdr->check = 0;
    ip_hdr->check = calc_ip_cheksum(ip_hdr);

    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len + sizeof(struct timeval), modified_pkt);
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

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) 
    {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}

