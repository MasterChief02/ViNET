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

      int middle_control_fd;
      int middle_data_fd;
      int middle_port;
      std::string middle_ip;

      Logger logger;

      void setup_middle ()
        {
          this->setup_socket (&this->middle_control_fd, this->middle_port, true);
          sleep (1);
          this->setup_socket (&this->middle_data_fd, this->middle_port+1, false);
        }



      void setup_socket (int *fd, int port, bool set_timeout)
        {
          struct sockaddr_in middle_socket;
          memset (&middle_socket, 0, sizeof (middle_socket));
          *fd = socket (AF_INET, SOCK_STREAM, 0);
          middle_socket.sin_family = AF_INET;
          middle_socket.sin_port = htons (port);
          middle_socket.sin_addr.s_addr = inet_addr (this->middle_ip.c_str ());

          if (set_timeout)
            {
              struct timeval timeout;
              memset (&timeout, 0, sizeof (timeout));
              timeout.tv_sec = 0;
              timeout.tv_usec = 1000;

              setsockopt(*fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval));
              // setsockopt(*fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval));
            }


          if (connect (*fd, (struct sockaddr *) &middle_socket, sizeof (middle_socket)) < 0)
            {
              perror ("Failed to connect to middle");
              exit (EXIT_FAILURE);
            }
          this->logger.print ("Connected to middle", GREEN, VERBOSE_LOW);
        }



      void setup_core ()
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



      void setup ()
        {
          this->setup_middle ();
          this->setup_core ();
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
          int payload_length = udp_header->len;

          payload_length = ntohs(payload_length);

          // std::cout << payload_length << "\n";
          // std::cout << ntohs(payload_length) << "\n";

          if (payload_length < 1100)
            goto set_verdict;


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

          set_verdict:
            int verdict = nfq_set_verdict (q_handle, packet_id, NF_ACCEPT, len, pkt);
            if (verdict == -1) {
                perror ("Error in nfq_set_verdict()");
                exit (EXIT_FAILURE);
            }

            return verdict;
        }



      void signature_add (char *payload,
                          int payload_length)
        {
          char signature[] = "ViNET";
          int signature_length = strlen (signature);

          memcpy (payload, signature, signature_length * sizeof (char));
        }



      bool signature_verify (char *payload,
                             int payload_length)
        {
          char signature[] = "ViNET";
          int signature_length = strlen (signature);

          char data [signature_length+1];
          memcpy (data, payload, signature_length * sizeof (char));

          return (strcmp (signature, data) == 0);
        }



      void data_add (char *payload,
                     char *data,
                     int payload_length,
                     int data_length)
        {
          char signature[] = "ViNET";
          int signature_length = strlen (signature);
          int32_t signature_size = signature_length * sizeof (char);

          int32_t metadata_1 = htonl (data_length);
          int32_t metadata_2 = htonl (payload_length);
          int metadata_1_size = sizeof (metadata_1);
          int metadata_2_size = sizeof (metadata_2);
          int metadata_size = metadata_1_size + metadata_2_size;

          int total_data_size = signature_size + metadata_size + ( payload_length * sizeof(char) ) ;

          // if (total_data_size > payload_length){
          //   std::cout << total_data_size << " " << payload_length;
          //   this->logger.print("CAUTION!", RED, VERBOSE_HIGH);
          // }

          memcpy (payload + signature_size, &metadata_1, metadata_1_size);
          memcpy (payload + signature_size + metadata_1_size, &metadata_2, metadata_2_size);
          memcpy (payload + signature_size + metadata_size, data, data_length * sizeof (char));

        }



      int32_t data_get (char *payload,
                     char *data,
                     int payload_length)
        {
          char signature[] = "ViNET";
          int signature_length = strlen (signature);
          int signature_size = signature_length * sizeof (char);

          int32_t metadata_1;
          int metadata_1_size = sizeof (metadata_1);
          int32_t metadata_2;
          int metadata_2_size = sizeof (metadata_2);


          memcpy (&metadata_1, payload + signature_size, metadata_1_size);
          metadata_1 = ntohl (metadata_1);

          memcpy (&metadata_2, payload + signature_size + metadata_1_size, metadata_1_size);
          metadata_2 = ntohl (metadata_2);

          if (metadata_2 != payload_length) {
            this->logger.print("CONCATENATED PACKET!", YELLOW, VERBOSE_HIGH);
          }

          memcpy (data, payload + signature_size + metadata_1_size + metadata_2_size, metadata_1);
          return metadata_1;
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
          uint32_t data_length;
          char data[2048];
          int n;

          n = read (this->middle_control_fd, &data_length, sizeof (data_length));
          if (n <= 0)
            {
              // this->logger.print ("TIMEOUT", RED, VERBOSE_HIGH);
              return;
            }

          data_length = ntohl (data_length);

          n = read (this->middle_data_fd, &data, data_length * sizeof (char));
          if (n <= 0 || n!= data_length)
            {
              this->logger.print ("Unable to read payload", RED, VERBOSE_HIGH);
              std::cout << data_length << " " << n << " " << payload_length << std::endl;
              return;
            }


          this->logger.print ("Sending data", GREEN, VERBOSE_HIGH);

          this->signature_add (payload, payload_length);
          this->data_add (payload, data, payload_length, data_length);
          this->update_checksum (ip_header, udp_header);

        }



        void callback_receive (char *payload,
                               int payload_length)
          {
            char data[2048];
            int data_length;
            uint32_t n;

            if (!this->signature_verify (payload, payload_length))
              return;

            this->logger.print ("Got some data", BLUE, VERBOSE_HIGH);


            data_length = this->data_get (payload, data, payload_length);
            n = htonl (data_length);

            if (write (this->middle_control_fd, &n, sizeof (n)) <= 0)
              {
                perror ("Failed to write len");
              }

            if (write (this->middle_data_fd, data, data_length * sizeof (char)) <= 0)
              {
                perror ("Failed to write data");
              }
          }



    public:
      Core (char *self_ip)
        {
          this->self_ip = self_ip;
          this->queue_num = 5;
          this->middle_port = 8080;
          this->middle_ip = "127.0.0.1";

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