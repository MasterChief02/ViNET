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
#include <thread>

#include "../Common/Logger.h"
#include "Checksum.h"

class Core
  {
    private:
      int queue_num_send;
      int queue_num_recv;

      int core_fd_send;
      int core_fd_recv;

      struct nfq_handle *handle_send;
      struct nfq_handle *handle_recv;

      struct nfq_q_handle *q_handle_send;
      struct nfq_q_handle *q_handle_recv;

      char *self_ip;

      int middle_control_fd;
      int middle_data_fd;
      int middle_port;
      std::string middle_ip;

      Logger logger;

      void setup_core_send ()
        {
          this->handle_send = nfq_open ();
          if (!this->handle_send)
            {
              perror ("Error in nfq_open()");
              exit (EXIT_FAILURE);
            }

          if (nfq_unbind_pf (this->handle_send, AF_INET6) < 0)
            {
              perror ("Error in nfq_unbind_pf()");
              exit (EXIT_FAILURE);
            }

          if (nfq_bind_pf (this->handle_send, AF_INET6) < 0)
            {
              perror ("Error in nfq_bind_pf()");
              exit (EXIT_FAILURE);
            }

          this->q_handle_send = nfq_create_queue (this->handle_send, this->queue_num_send, &Core::callback_helper_send, this);
          if (!this->q_handle_send)
            {
              perror ("Error in nfq_create_queue()");
              exit (EXIT_FAILURE);
            }

          if (nfq_set_mode (this->q_handle_send, NFQNL_COPY_PACKET, 0xffff) < 0)
            {
              perror ("Error in nfq_set_mode()");
              exit (EXIT_FAILURE);
            }

          this->core_fd_send = nfq_fd (this->handle_send);
        }

      void setup_core_recv ()
        {
          this->handle_recv = nfq_open ();
          if (!this->handle_recv)
            {
              perror ("Error in nfq_open()");
              exit (EXIT_FAILURE);
            }

          if (nfq_unbind_pf (this->handle_recv, AF_INET6) < 0)
            {
              perror ("Error in nfq_unbind_pf()");
              exit (EXIT_FAILURE);
            }

          if (nfq_bind_pf (this->handle_recv, AF_INET6) < 0)
            {
              perror ("Error in nfq_bind_pf()");
              exit (EXIT_FAILURE);
            }

          this->q_handle_recv = nfq_create_queue (this->handle_recv, this->queue_num_recv, &Core::callback_helper_recv, this);
          if (!this->q_handle_recv)
            {
              perror ("Error in nfq_create_queue()");
              exit (EXIT_FAILURE);
            }

          if (nfq_set_mode (this->q_handle_recv, NFQNL_COPY_PACKET, 0xffff) < 0)
            {
              perror ("Error in nfq_set_mode()");
              exit (EXIT_FAILURE);
            }

          this->core_fd_recv = nfq_fd (this->handle_recv);
        }



      void setup ()
        {
          this->setup_core_send ();
          this->setup_core_recv ();
        }


      int send_callback (struct nfq_q_handle *q_handle,
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
          int payload_length = ntohs (udp_header->len);

          int safe_padding = 10;
          int const_str_length = 100;

          if (payload_length < const_str_length + safe_padding || payload_length < 200)
            goto set_verdict;

          this->callback_send (ip_header, udp_header, payload, payload_length);

          set_verdict:
            int verdict = nfq_set_verdict (q_handle, packet_id, NF_ACCEPT, len, pkt);
            if (verdict == -1) {
                perror ("Error in nfq_set_verdict()");
                exit (EXIT_FAILURE);
            }

            return verdict;
        }

      
      int recv_callback (struct nfq_q_handle *q_handle,
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
          int payload_length = ntohs (udp_header->len);

          set_verdict:
            int verdict = nfq_set_verdict (q_handle, packet_id, NF_ACCEPT, len, pkt);
            if (verdict == -1) {
                perror ("Error in nfq_set_verdict()");
                exit (EXIT_FAILURE);
            }

            return verdict;
        }


      void data_add (char *payload,
                     int payload_length)
        {
					const char *str = (char *)calloc(100, sizeof(char));
					memcpy(payload + (payload_length - 100), str, 100);

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
          this->data_add (payload, payload_length);
          this->update_checksum (ip_header, udp_header);

        }


    public:
      Core (char *self_ip)
        {
          this->self_ip = self_ip;
          this->queue_num_send = 5;
          this->queue_num_recv = 6;
          this->middle_port = 8080;
          this->middle_ip = "127.0.0.1";

          this->setup ();
        }


      void run_send_queue ()
        {
          char buf[4096];
          int receive;
          while ((receive = recv(this->core_fd_send, buf, sizeof(buf), 0)) >= 0)
            {
              nfq_handle_packet(this->handle_send, buf, receive);
            }

          nfq_destroy_queue(this->q_handle_send);
          nfq_close(this->handle_send);

        }

      void run_recv_queue ()
        {
          char buf[4096];
          int receive;
          while ((receive = recv(this->core_fd_recv, buf, sizeof(buf), 0)) >= 0)
            {
              nfq_handle_packet(this->handle_recv, buf, receive);
            }

          nfq_destroy_queue(this->q_handle_recv);
          nfq_close(this->handle_recv);
        }



      void run ()
        {

          std::thread send_thread(&Core::run_send_queue, this);
          std::thread recv_thread(&Core::run_recv_queue, this);

          send_thread.join();
          recv_thread.join();

        }




      static int callback_helper_send (struct nfq_q_handle *q_handle,
                                  struct nfgenmsg *nfmsg,
                                  struct nfq_data *nfa,
                                  void *context)
        {
          return ((Core *) context)->send_callback (q_handle, nfmsg, nfa);
        }

      static int callback_helper_recv (struct nfq_q_handle *q_handle,
                                  struct nfgenmsg *nfmsg,
                                  struct nfq_data *nfa,
                                  void *context)
        {
          return ((Core *) context)->recv_callback (q_handle, nfmsg, nfa);
        }

  };

int main (int argc, char *argv[])
  {
    if (argc == 2)
      {
        Core core (argv[1]);
        core.run ();
      }

    else
      {
        std::cout << "Usage:" << std::endl << "   ./core <self_ip>" << std::endl;
      }

    return 0;
  }