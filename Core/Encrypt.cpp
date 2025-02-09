#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <vector>
#include <iostream>
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
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "../Common/Logger.h"
#include "Checksum.h"

#define IV_SIZE 12
#define TAG_SIZE 16

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


      const unsigned char* key = (const unsigned char*)"0123456789ABCDEF";

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

          // Parsing IPv6 headers
          struct ip6_hdr *ip_header = (struct ip6_hdr *) pkt;

          // Parsing UDP headers
          struct udphdr *udp_header = (struct udphdr *) (pkt + sizeof (struct ip6_hdr));

          // Retrieving application payload
          char *payload = (char *) (pkt + sizeof (struct ip6_hdr) + sizeof (struct udphdr));
          int payload_length = ntohs (udp_header->len);

          int signature_size = 5 * sizeof (char);
          int metadata_size = sizeof (int32_t);
          int safe_padding = 10;

          if (payload_length < check_available_tcp_packet_len() + IV_SIZE + TAG_SIZE + sizeof(int32_t))
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

          // if (payload_length < 800)
          //   goto set_verdict;

          this->callback_receive (payload, payload_length);
          if (payload_length > 2000)
                this->logger.print ("Payload > 2000", YELLOW, VERBOSE_VERY_HIGH);


          set_verdict:
            int verdict = nfq_set_verdict (q_handle, packet_id, NF_ACCEPT, len, pkt);
            if (verdict == -1) {
                perror ("Error in nfq_set_verdict()");
                exit (EXIT_FAILURE);
            }

            return verdict;
        }

      unsigned char* data_encrypt_add ( char *payload, 
                                        char *data, 
                                        int payload_length, 
                                        int data_length)
        {

          unsigned char tag[TAG_SIZE];
          unsigned char iv[IV_SIZE];
          RAND_bytes(iv, sizeof(iv));

          int32_t metadata = htonl (data_length);

          int32_t plaintext_length = payload_length - TAG_SIZE - IV_SIZE;
          unsigned char plaintext[plaintext_length];
          RAND_bytes(plaintext, sizeof(plaintext));


          memcpy(plaintext, metadata, sizeof(metadata));
          memcpy(plaintext+sizeof(metadata), data, data_length);


          int32_t cipher_length = IV_SIZE + TAG_SIZE + plaintext_length;
          unsigned char ciphertext[cipher_length];

          int size_intial_blocks=0, size_final_block=0;

          EVP_CIPHER_CTX* e_ctx = EVP_CIPHER_CTX_new();

          EVP_EncryptInit_ex( e_ctx, EVP_aes_128_gcm(), NULL, this->key, iv );
          EVP_EncryptUpdate( e_ctx, &ciphertext[IV_SIZE + TAG_SIZE], &size_intial_blocks, plaintext, plaintext_length );
          EVP_EncryptFinal_ex( e_ctx, &ciphertext[IV_SIZE + TAG_SIZE + size_intial_blocks], &size_final_block );
          EVP_CIPHER_CTX_ctrl( e_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag );

          memcpy(ciphertext, tag, TAG_SIZE);
          memcpy(ciphertext + TAG_SIZE, iv, IV_SIZE);

          int32_t encrypted_data_length = IV_SIZE + TAG_SIZE + size_intial_blocks + size_final_block;
          if (encrypted_data_length != payload_length)
            {
              this->logger.print ("Encrypted data length mismatch", RED, VERBOSE_HIGH);
            }

          EVP_CIPHER_CTX_free(e_ctx);
          memcpy(payload, ciphertext, payload_length);
        }


      int32_t data_decrypt_get (char *payload,
                                char *data,
                                int payload_length)
        {

          unsigned char tag[TAG_SIZE];
          unsigned char iv[IV_SIZE];
          unsigned char* ciphertext = (unsigned char*) payload;

          memcpy(tag, ciphertext, TAG_SIZE);
          memcpy(iv, ciphertext + TAG_SIZE, IV_SIZE);

          int32_t plaintext_length = payload_length - TAG_SIZE - IV_SIZE;
          unsigned char plaintext[plaintext_length];

          int size_intial_blocks=0, size_final_block=0;

          EVP_CIPHER_CTX* d_ctx = EVP_CIPHER_CTX_new();
          EVP_DecryptInit_ex( d_ctx, EVP_aes_128_gcm(), NULL, this->key, iv );
          EVP_DecryptUpdate( d_ctx, plaintext, &size_intial_blocks, ciphertext + TAG_SIZE + IV_SIZE, plaintext_length );
          EVP_CIPHER_CTX_ctrl( d_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag );
          int verify = EVP_DecryptFinal_ex( d_ctx, plaintext + size_intial_blocks, &size_final_block );

          if (verify == 0) return 0;

          int32_t metadata;
          memcpy(&metadata, plaintext, sizeof(metadata));
          metadata = ntohl(metadata);

          memcpy(data, plaintext + sizeof(metadata), metadata);

          EVP_CIPHER_CTX_free(d_ctx);
          return metadata;
        }



      void update_checksum(ip6_hdr* ip_header,
                            udphdr* udp_header)
        {
          udp_header->check = 0;
          udp_header->check = nfq_checksum_tcp_udp_ipv6(ip_header, udp_header, IPPROTO_UDP);
        }


      uint32_t check_available_tcp_packet_len() {
        int n;
        uint32_t data_length;
        n = recv (this->middle_control_fd, &data_length, sizeof (data_length), MSG_PEEK);
        // std::cout << "Before ntohl: " << data_length << std::endl;
        data_length = ntohl (data_length);
        // std::cout << "After ntohl: " << data_length << std::endl;
        return data_length;
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

          this->data_encrypt_add (payload, data, payload_length, data_length);
          this->update_checksum (ip_header, udp_header);

        }

        void callback_receive (char *payload,
                               int payload_length)
          {
            char data[2048];
            int data_length;
            uint32_t n;

            data_length = this->data_decrypt_get (payload, data, payload_length);

            if (data_length == 0) return;

            this->logger.print ("Got some data", BLUE, VERBOSE_HIGH);
            std::cout << payload_length << std::endl;

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