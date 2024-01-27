#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <unordered_map>

#include "../Common/Logger.h"
#include "./Middle_Interface.h"

#define MAX_PACKET_SIZE 65536

class Router : public Middle
  {
    private:
      bool is_server;

      int input_raw_socket;
      int output_raw_socket;

      int packet_number;

      char *interface;
      char *client_1_ip;
      uint32_t server_ip;

      std::unordered_map <uint32_t, uint32_t> dnat;

      void calculateTCPChecksum(uint8_t* packet, size_t packetLength) {
        const uint8_t* sourceIP = &packet[12];  // Offset for source IP in IP header
        const uint8_t* destIP = &packet[16];    // Offset for destination IP in IP header

        uint32_t sum = 0;

        // Pseudo-header: Source IP + Destination IP + Reserved (8 bits) + Protocol (8 bits) + TCP length (16 bits)
        for (int i = 0; i < 4; ++i) {
            sum += (static_cast<uint16_t>(sourceIP[i]) << 8) + static_cast<uint16_t>(destIP[i]);
        }

        sum += 6 << 8; // Protocol: 6 for TCP
        sum += static_cast<uint16_t>(packetLength);

        // TCP header and data
        for (size_t i = 20; i < packetLength; i += 2) {  // Start from offset 20 for TCP header
            sum += (packet[i] << 8) + packet[i + 1];
        }

        // Add the carry
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        uint16_t checksum = static_cast<uint16_t>(~sum);
        packet[36] = (checksum >> 8) & 0xFF;  // Offset for TCP checksum in TCP header
        packet[37] = checksum & 0xFF;
    }

    protected:
      void setup_middle ()
        {
          // Setup input socket
          this->input_raw_socket = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));

          if (this->input_raw_socket < 0)
            {
              this->logger.print ("Failed to create input_raw_socket", RED, VERBOSE_LOW);
              exit (EXIT_FAILURE);
            }

          int ret = setsockopt (this->input_raw_socket, SOL_SOCKET, SO_BINDTODEVICE, (void *)interface, strlen (interface));
          if (ret < 0)
            {
              this->logger.print ("Failed to bind to interface", RED, VERBOSE_LOW);
              exit (EXIT_FAILURE);
            }

          // Setup output socket
          this->output_raw_socket = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
          if (this->output_raw_socket < 0)
            {
              this->logger.print ("Failed to create output_raw_socket", RED, VERBOSE_LOW);
              exit (EXIT_FAILURE);
            }

          int one = 1;
          ret = setsockopt (this->output_raw_socket, IPPROTO_IP, IP_HDRINCL, (void *) &one, sizeof (one));
          if (ret < 0)
            {
              this->logger.print ("Failed to set IP_HDRINCL", RED, VERBOSE_LOW);
              exit (EXIT_FAILURE);
            }

          ret = setsockopt (this->output_raw_socket, SOL_SOCKET, SO_BINDTODEVICE, (void *)interface, strlen (interface));
          if (ret < 0)
            {
              this->logger.print ("Failed to bind to interface", RED, VERBOSE_LOW);
              exit (EXIT_FAILURE);
            }
        }



      void *input ()
        {
          struct sockaddr saddr;
          while (1)
            {
              int saddr_size = sizeof (saddr);

              unsigned char packet [MAX_PACKET_SIZE];
              int packet_size = recvfrom (this->input_raw_socket,
                                          packet,
                                          MAX_PACKET_SIZE,
                                          0,
                                          &saddr,
                                          (socklen_t *) &saddr_size);

              if (packet_size < 0)
                continue;

              // Check for IPv4
              struct ethhdr *ethernet_header = (struct ethhdr *) packet;
              if (ethernet_header->h_proto != 8)
                continue;

              // Check for ICMP, UDP, TCP
              struct iphdr *ip_header = (struct iphdr *)(packet + sizeof (struct ethhdr));
              if ((ip_header->protocol != IPPROTO_ICMP) &&
                  (ip_header->protocol != IPPROTO_UDP) &&
                  (ip_header->protocol != IPPROTO_TCP))
                continue;

              // DNAT at server side
              if ((this->is_server) &&
                  (this->dnat.find (ip_header->saddr) != this->dnat.end ()))
                {
                  ip_header->daddr = this->dnat [ip_header->saddr];

                  // if (ip_header->protocol == IPPROTO_TCP)
                  //   this->calculateTCPChecksum (packet, packet_size);
                }


              char src_ip [INET_ADDRSTRLEN];
              inet_ntop (AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);

              char dst_ip [INET_ADDRSTRLEN];
              inet_ntop (AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

              // Check if valid client
              if ((!this->is_server && strcmp (src_ip, this->client_1_ip) != 0) ||
                  (this->is_server && strcmp (dst_ip, this->client_1_ip) != 0))
                continue;

              if (ip_header->protocol == IPPROTO_ICMP)
                this->logger.print ("ICMP packet", GREEN, VERBOSE_HIGH);
              else if (ip_header->protocol == IPPROTO_UDP)
                this->logger.print ("UDP packet", GREEN, VERBOSE_HIGH);
              else if (ip_header->protocol == IPPROTO_TCP)
                this->logger.print ("TCP packet", GREEN, VERBOSE_HIGH);

              // Update TCP checksum
              // if (!this->is_server && ip_header->protocol == IPPROTO_TCP)
              //   {
              //     uint16_t checksum = this->calculateTCPChecksum (packet, packet_size);
              //     packet[36] = (checksum >> 8) & 0xFF;  // Offset for TCP checksum in TCP header
              //     packet[37] = checksum & 0xFF;
              //   }


              std::cout << "SOURCE IP     : " << src_ip << std::endl;
              std::cout << "DESTINATION IP: " << dst_ip << std::endl;

              int32_t length = packet_size - sizeof (struct ethhdr);
              length = htonl (length);
              write (this->core_fd, &length, sizeof (length));
              write (this->core_fd, packet + sizeof (struct ethhdr), packet_size - sizeof (struct ethhdr));
            }
        }



      void *output ()
        {
          while (1)
            {
              int32_t packet_size;
              unsigned char packet [MAX_PACKET_SIZE];

              read (this->core_fd, &packet_size, sizeof (packet_size));
              packet_size = ntohl (packet_size);

              if (packet_size == 0)
                continue;

              int n = read (this->core_fd, packet, packet_size * sizeof (char));
              if (n<= 0)
                continue;

              // Check for ICMP, UDP, TCP
              struct iphdr *ip_header = (struct iphdr *) packet;
              if ((ip_header->protocol != IPPROTO_ICMP) &&
                  (ip_header->protocol != IPPROTO_UDP) &&
                  (ip_header->protocol != IPPROTO_TCP))
                continue;

              // SNAT at server side
              if (this->is_server)
                {
                  uint32_t temp = ip_header->saddr;
                  this->dnat [ip_header->daddr] = ip_header->saddr;
                  // ip_header->saddr = this->server_ip;

                  // if (ip_header->protocol == IPPROTO_TCP)
                  //   this->calculateTCPChecksum (packet, packet_size);

                  // ip_header->saddr = temp;
                }

              char src_ip [INET_ADDRSTRLEN];
              inet_ntop (AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);

              char dst_ip [INET_ADDRSTRLEN];
              inet_ntop (AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);


              if (ip_header->protocol == IPPROTO_ICMP)
                this->logger.print ("ICMP packet", BLUE, VERBOSE_HIGH);
              else if (ip_header->protocol == IPPROTO_UDP)
                this->logger.print ("UDP packet", BLUE, VERBOSE_HIGH);
              else if (ip_header->protocol == IPPROTO_TCP)
                this->logger.print ("TCP packet", BLUE, VERBOSE_HIGH);

              std::cout << "SOURCE IP     : " << src_ip << std::endl;
              std::cout << "DESTINATION IP: " << dst_ip << std::endl;

              struct sockaddr_in saddr;
              memset (&saddr, 0, sizeof (saddr));
              saddr.sin_family = AF_INET;
              saddr.sin_addr.s_addr = ip_header->saddr;

              n = sendto (this->output_raw_socket,
                          packet,
                          packet_size,
                          0,
                          (struct sockaddr*) &saddr,
                          sizeof (struct sockaddr));
              if (n < 0)
                {
                  this->logger.print ("Failed to send packet", RED, VERBOSE_LOW);
                }

            }
        }

      public:
        Router (bool is_server, char *client_1_ip, char *server_ip = NULL)
          {
            this->packet_number = 0;
            this->interface = "wlan0";

            this->is_server = is_server;
            this->client_1_ip = client_1_ip;

            if (this->is_server)
              {
                struct sockaddr_in sa;
                inet_pton(AF_INET, server_ip, &(sa.sin_addr));
                this->server_ip = sa.sin_addr.s_addr;
                std::cout << "Server " << this->client_1_ip << std::endl;
              }

            else
              {
                std::cout << "Client " << this->client_1_ip << std::endl;
              }

          }
  };



int main (int argc, char *argv[])
  {
    if (argc == 3 && atoi (argv[1]) == 0)
      {
        Router router (0, argv[2]);
        router.setup ();
        router.run ();
        return 0;
      }
    else if (argc == 4 && atoi (argv[1]) == 1)
      {
        Router router (1, argv[2], argv[3]);
        router.setup ();
        router.run ();
        return 0;
      }

    std::cout << "Usage" << std::endl;
    std::cout << " Client:   ./router 0 <client_1_ip>" << std::endl;
    std::cout << " Server:   ./router 1 <client_1_ip> <server_ip>" << std::endl;
    return 0;

  }