
// Client side C/C++ program to demonstrate Socket
// programming
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#define PORT 8080


#define DATA_REQUEST "data"
#define SIZE_OF_DATA_REQUEST 4

#define DATA_RECEIVED "received"
#define SIZE_OF_DATA_RECEIVED 8


int main(int argc, char const* argv[])
{
    int status, valread, client_fd;
    struct sockaddr_in serv_addr;
    char buffer[1024] = { 0 };
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)
        <= 0) {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }

    if ((status
         = connect(client_fd, (struct sockaddr*)&serv_addr,
                   sizeof(serv_addr)))
        < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    while (1)
      {
        for (int i=0; i<5; i++)
          {
            write (client_fd, DATA_REQUEST, SIZE_OF_DATA_REQUEST * sizeof (char));

            int length;
            read (client_fd, &length, sizeof (length));
            length = ntohl (length);
            if (length !=0)
              {
                std::cout<<length<< std::endl;
                char data[length];
                read (client_fd, data, length * sizeof (char));
                std::cout<< data << std::endl;
              }

            sleep(1);
          }

      }

    // closing the connected socket
    close(client_fd);
    return 0;
}