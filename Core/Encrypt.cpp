#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <cerrno>
#include <queue>
#include <utility>
#include <mutex>
#include <thread>

#include "../Common/Logger.h"
#include "Checksum.h"

class Core
  {
    private:
      int queue_num;
      int core_fd;
      struct nfq_handle *handle;
      struct nfq_q_handle *q_handle;

      char *self_ip;

      int middle_fd;
      int middle_port;
      std::string middle_ip;
      std::queue<std::pair<int, char*>> data_queue;
      bool data_queue_mutex;

      // std::thread data_recv_thread;

      Logger logger;



      void setup ()
        {
          this->handle = nfq_open ();
          if (!this->handle)
            {
              perror ("Error in nfq_open()");
              exit (EXIT_FAILURE);
            }

          if (nfq_unbind_pf (this->handle, AF_INET) < 0)
            {
              perror ("Error in nfq_unbind_pf()");
              exit (EXIT_FAILURE);
            }

          if (nfq_bind_pf (this->handle, AF_INET) < 0)
            {
              perror ("Error in nfq_bind_pf()");
              exit (EXIT_FAILURE);
            }

          this->q_handle = nfq_create_queue (this->handle, this->queue_num, &Core::callback_helper, this);
          if (!this->q_handle)
            {
              perror ("Error in nfq_create_queue()");
              exit (EXIT_FAILURE);
            }

          if (nfq_set_mode (this->q_handle, NFQNL_COPY_PACKET, 0xffff) < 0)
            {
              perror ("Error in nfq_set_mode()");
              exit (EXIT_FAILURE);
            }

          this->core_fd = nfq_fd (this->handle);
        }


      int callback (struct nfq_q_handle *q_handle,
                    struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa)
        {
          struct nfqnl_msg_packet_hdr *ph;

          ph = nfq_get_msg_packet_hdr (nfa);
          int packet_id = ntohl (ph->packet_id);
          unsigned char *pkt;
          int len = nfq_get_payload (nfa, &pkt);

          // Parsing IPv6 headers
          struct ip6_hdr *ip_header = (struct ip6_hdr *) pkt;

          // Parsing UDP headers
          struct udphdr *udp_header = (struct udphdr *) (pkt + sizeof (struct ip6_hdr));

          // Retrieving application payload
          char *payload = (char *) (pkt + sizeof (struct ip6_hdr) + sizeof (struct udphdr));
          int payload_length = udp_header->len - sizeof (struct udphdr);

          // Retrieving source IP
          char src_ip [INET6_ADDRSTRLEN];
          inet_ntop (AF_INET6, &(ip_header->ip6_src), src_ip, INET6_ADDRSTRLEN);

          if (strcmp (this->self_ip, src_ip) == 0)
            {
              // this->logger.print ("Sending", YELLOW, VERBOSE_HIGH);
              this->callback_send (ip_header, udp_header, payload, payload_length);
            }
          else
            {
              // this->logger.print ("Receiving", BLUE, VERBOSE_HIGH);
              this->callback_receive (payload, payload_length);
            }

          // std::cout << "VERDICT" << std::endl;
          int verdict = nfq_set_verdict (q_handle, packet_id, NF_ACCEPT, len, pkt);
          if (verdict == -1) {
              perror ("Error in nfq_set_verdict()");
              exit (EXIT_FAILURE);
          }

          return verdict;
        }



      void update_checksum(ip6_hdr* ip_header,
                            udphdr* udp_header)
        {
          udp_header->check = 0;
          udp_header->check = nfq_checksum_tcp_udp_ipv6(ip_header, udp_header, IPPROTO_UDP);
        }



      void callback_send (ip6_hdr *ip_header,
                          udphdr *udp_header,
                          char *payload,
                          int payload_length)
        {
          return;
        }



        void callback_receive (char *payload,
                               int payload_length)
          {
            return;
          }



    public:
      Core (char *self_ip)
        {
          this->self_ip = self_ip;
          this->queue_num = 5;

          this->setup ();
        }



      void run ()
        {
          char buf[4096];
          int receive;
          while ((receive = recv(this->core_fd, buf, sizeof(buf), 0)) >= 0)
            {
              nfq_handle_packet(this->handle, buf, receive);
            }
          nfq_destroy_queue(this->q_handle);
          nfq_close(this->handle);
        }




      static int callback_helper (struct nfq_q_handle *q_handle,
                                  struct nfgenmsg *nfmsg,
                                  struct nfq_data *nfa,
                                  void *context)
        {
          return ((Core *) context)->callback (q_handle, nfmsg, nfa);
        }

  };

int main (int argc, char *argv[])
  {
    // nice (-20);
    if (argc == 2)
      {
        Core core (argv[1]);
        core.run ();
      }

    else
      {
        std::cout << "Usage:" << std::endl << "   ./encrypt <self_ip>" << std::endl;
      }

    return 0;
  }