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
#include <fcntl.h>
#include <sys/ioctl.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstdlib>
#include <vector>


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

      double alpha;

      bool collect_packets;
      std::vector<std::vector<unsigned char>> packets;
      int current_packet_index = 0;

      Logger logger;

      EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
      EVP_CIPHER_CTX *dctx = EVP_CIPHER_CTX_new();



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

          if (connect (*fd, (struct sockaddr *) &middle_socket, sizeof (middle_socket)) < 0)
            {
              perror ("Failed to connect to middle");
              exit (EXIT_FAILURE);
            }

          if (set_timeout)
            {
              int flags = fcntl(*fd, F_GETFL, 0);
              fcntl(*fd, F_SETFL, flags | O_NONBLOCK);
            }


          this->logger.print ("Connected to middle", GREEN, VERBOSE_LOW);
        }



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
          this->setup_middle ();
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

          if (this->collect_packets) {
            int verdict = nfq_set_verdict (q_handle, packet_id, NF_ACCEPT, len, pkt);
            if (verdict == -1) {
                perror ("Error in nfq_set_verdict()");
                exit (EXIT_FAILURE);
            }

            return verdict;
          }

          // Parsing IPv6 headers
          struct ip6_hdr *ip_header = (struct ip6_hdr *) pkt;

          // Parsing UDP headers
          struct udphdr *udp_header = (struct udphdr *) (pkt + sizeof (struct ip6_hdr));

          // Retrieving application payload
          int rtp_header_size = 14;
          
          char *payload = (char *) (pkt + sizeof (struct ip6_hdr) + sizeof (struct udphdr)) + rtp_header_size;
          int payload_length = ntohs (udp_header->len) - rtp_header_size;
          int iv_size = 16;
          int signature_size = 5 * sizeof (char);
          int metadata_size = sizeof (int32_t);
          
          if (ntohs(udp_header->len) < 200) {
            goto set_verdict;
          }

          if (payload_length < check_available_tcp_packet_len() + iv_size + signature_size + metadata_size || payload_length < 200)
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
          
          if (this->collect_packets) {
            if (len > 300) {
              std::vector<unsigned char> packet(pkt, pkt + len);
              this->packets.push_back(packet);
            }
            int verdict = nfq_set_verdict (q_handle, packet_id, NF_ACCEPT, len, pkt);
            if (verdict == -1) {
                perror ("Error in nfq_set_verdict()");
                exit (EXIT_FAILURE);
            }

            return verdict;
          }
          
          // Parsing IPv6 headers
          struct ip6_hdr *ip_header = (struct ip6_hdr *) pkt;
          
          // Parsing UDP headers
          struct udphdr *udp_header = (struct udphdr *) (pkt + sizeof (struct ip6_hdr));
          
          // Retrieving application payload
          int rtp_header_size = 14;
          
          char *payload = (char *) (pkt + sizeof (struct ip6_hdr) + sizeof (struct udphdr)) + rtp_header_size;
          int payload_length = ntohs (udp_header->len) - rtp_header_size;
          
          int iv_size = 16;
          int signature_size = 5 * sizeof (char);
          int metadata_size = sizeof (int32_t);
          

          if (ntohs(udp_header->len) < 200) {
            goto set_verdict;
          }

          if (payload_length < iv_size + signature_size + metadata_size || payload_length < 200)
            goto set_verdict;

          this->callback_receive (payload, payload_length);
          if (payload_length > 2000)
                this->logger.print ("Payload > 2000", YELLOW, VERBOSE_VERY_HIGH);


          set_verdict:

            std::vector<unsigned char> old_packet = this->packets[this->current_packet_index];
            this->current_packet_index = (this->current_packet_index + 1) % this->packets.size();

            unsigned char *old_pkt = old_packet.data();
            struct ip6_hdr *old_ip_header = (struct ip6_hdr *) old_pkt;
            struct udphdr *old_udp_header = (struct udphdr *) (old_pkt + sizeof (struct ip6_hdr));

            int header_len = sizeof (struct ip6_hdr) + sizeof (struct udphdr);
            memcpy (old_pkt + header_len, pkt + header_len, 12);

            // this->logger.print ("Copied packet", GREEN, VERBOSE_VERY_HIGH);

           
            this->update_checksum (old_ip_header, old_udp_header);
            int verdict = nfq_set_verdict (q_handle, packet_id, NF_ACCEPT, old_packet.size(), old_pkt);
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
          int signature_size = signature_length * sizeof (char);

          int32_t metadata = htonl (data_length);
          int metadata_size = sizeof (metadata);

          memcpy (payload + signature_size, &metadata, metadata_size);
          memcpy (payload + signature_size + metadata_size, data, data_length * sizeof (char));
        }



      int32_t data_get (char *payload,
                     char *data,
                     int payload_length)
        {
          char signature[] = "ViNET";
          int signature_length = strlen (signature);
          int signature_size = signature_length * sizeof (char);

          int32_t metadata;
          int metadata_size = sizeof (metadata);

          memcpy (&metadata, payload + signature_size, metadata_size);
          metadata = ntohl (metadata);

          memcpy (data, payload + signature_size + metadata_size, metadata);
          return metadata;
        }



      void update_checksum(ip6_hdr* ip_header,
                            udphdr* udp_header)
        {
          udp_header->check = 0;
          udp_header->check = nfq_checksum_tcp_udp_ipv6(ip_header, udp_header, IPPROTO_UDP);
        }


      uint32_t check_available_tcp_packet_len() {

        int bytes_available = 0;
        ioctl(this->middle_control_fd, FIONREAD, &bytes_available);

        if (bytes_available >= sizeof(uint32_t)) {
          int n;
          uint32_t data_length;
          n = recv (this->middle_control_fd, &data_length, sizeof (data_length), MSG_PEEK);
          // std::cout << "Before ntohl: " << data_length << std::endl;
          data_length = ntohl (data_length);
          // std::cout << "After ntohl: " << data_length << std::endl;
          return data_length;
        }

        return INT16_MAX;

        
      }

      void encrypt_payload(char* payload, int payload_length) {

        const unsigned char *KEY = (const unsigned char*)"1234567890abcdef";
        
        const int IV_SIZE = 16;

        unsigned char IV[IV_SIZE];
        RAND_bytes(IV, IV_SIZE);

        unsigned char* plaintext = (unsigned char*) payload;
        int plaintext_length = payload_length - IV_SIZE;

        unsigned char ciphertext[plaintext_length];

        EVP_EncryptInit_ex(this->ectx, EVP_aes_128_ctr(), NULL, KEY, IV);

        int len;

        EVP_EncryptUpdate(this->ectx, ciphertext, &len, plaintext, plaintext_length);

        int ciphertext_length = len;

        EVP_EncryptFinal_ex(this->ectx, ciphertext + len, &len);

        ciphertext_length += len;

        if (ciphertext_length != plaintext_length) {
          this->logger.print("ENCRYPTION FAILED", RED, VERBOSE_VERY_HIGH);
          return;
        }

        this->logger.print("ENCRYPTION SUCCESS", GREEN, VERBOSE_VERY_HIGH);

        memcpy(payload, IV, IV_SIZE);
        memcpy(payload + IV_SIZE, ciphertext, ciphertext_length);

        EVP_CIPHER_CTX_reset(this->ectx);

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
          std::cout << payload_length << std::endl;

          this->signature_add (payload, payload_length);
          this->data_add (payload, data, payload_length, data_length);
          this->encrypt_payload(payload, payload_length);
          this->update_checksum (ip_header, udp_header);

        }


        bool decrypt_payload(char *payload, int payload_length) {

          const unsigned char *KEY = (const unsigned char*)"1234567890abcdef";
          
          const int IV_SIZE = 16;

          unsigned char IV[IV_SIZE];
          memcpy(IV, payload, IV_SIZE);

          unsigned char *ciphertext = (unsigned char *) payload + IV_SIZE;
          int ciphertext_length = payload_length - IV_SIZE;

          unsigned char plaintext[ciphertext_length];

          EVP_DecryptInit_ex(this->dctx, EVP_aes_128_ctr(), NULL, KEY, IV);

          int len;

          EVP_DecryptUpdate(this->dctx, plaintext, &len, ciphertext, ciphertext_length);

          int plaintext_length = len;

          EVP_DecryptFinal_ex(this->dctx, plaintext + len, &len);

          plaintext_length += len;

          if (ciphertext_length != plaintext_length) {
            this->logger.print("DECRYPTION FAILED", RED, VERBOSE_VERY_HIGH);
            return false;
          }

          if (!signature_verify((char *) plaintext, plaintext_length)) return false;

          
          memcpy(payload, plaintext, plaintext_length);
          EVP_CIPHER_CTX_reset(this->dctx);

          return true;

        }



        void callback_receive (char *payload,
                               int payload_length)
          {
            char data[2048];
            int data_length;
            uint32_t n;



            if (!this->decrypt_payload (payload, payload_length))
              return;

            // FOR JIO
            // if (payload[12] == 0x5c)
            //   logger.print("Setting forbidden", YELLOW, VERBOSE_HIGH);
            //   payload[12] = 0xdc;

            // if (payload[12] == 0x7c)
            //   logger.print("Setting forbidden", YELLOW, VERBOSE_HIGH);
            //   payload[12] = 0xfc;

            // FOR AIRTEL
            // if (payload[12] == 0x41)
            //   logger.print("Setting forbidden", YELLOW, VERBOSE_HIGH);
            //   payload[12] = 0xc1;


            this->logger.print ("Got some data", BLUE, VERBOSE_HIGH);
            std::cout << payload_length << std::endl;

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
      Core (char *self_ip, double alpha)
        {
          this->self_ip = self_ip;
          this->queue_num_send = 5;
          this->queue_num_recv = 6;
          this->middle_port = 8080;
          this->middle_ip = "127.0.0.1";
          this->alpha = (double) alpha;
          this->collect_packets = true;
          this->packets.clear();

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

          std::thread recv_thread(&Core::run_recv_queue, this);
          std::thread send_thread(&Core::run_send_queue, this);

          std::this_thread::sleep_for(std::chrono::seconds(20));
          this->collect_packets = false;
          this->logger.print("Packet collection done!", YELLOW, VERBOSE_VERY_HIGH);
          std::cout << "Packets collected: " << this->packets.size() << std::endl;


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
        Core core (argv[1], 1.0);
        core.run ();
      }

    else if (argc == 3)
      {
        Core core (argv[1], atof (argv[2]));
        core.run ();
      }

    else
      {
        std::cout << "Usage:" << std::endl << "   ./core <self_ip> <alpha>" << std::endl;
      }

    return 0;
  } 