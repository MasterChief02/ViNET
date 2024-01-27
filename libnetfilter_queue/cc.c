#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// Define a callback function for handling received packets
static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);

    unsigned char *pktData;
    int len = nfq_get_payload(nfa, &pktData);

    struct iphdr *ipHeader = (struct iphdr *)pktData;
    

    if (ipHeader->version == 4 && ipHeader->protocol == IPPROTO_UDP) {
        struct udphdr *udpHeader = (struct udphdr *)(pktData + (ipHeader->ihl * 4));


        if (ntohs(udpHeader->dest) == 5050) {

            int udp_payload_len = ntohs(udpHeader->len) - sizeof(struct udphdr);

            if (udp_payload_len >= 16) {
                // Access the 4 extra bytes at the end of the payload
                unsigned char appended_data[16];
                memcpy(appended_data, pktData + (ipHeader->ihl * 4) + sizeof(struct udphdr) + udp_payload_len - 16, 16);

                printf("Received Appended Data: ");
                write(stdout, appended_data, 16);
            }
        }
    }


    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
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

