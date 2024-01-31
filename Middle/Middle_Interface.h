#ifndef MIDDLE_H
#define MIDDLE_H

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>

#include "../Common/Logger.h"

class Middle
  {
    private:
      void setup_core ()
        {
          this->setup_socket (&this->core_control_fd, this->port);
          this->setup_socket (&this->core_data_fd, this->port + 1);
        }


      void setup_socket (int *fd, int port)
        {
          int socket_fd;

          struct sockaddr_in address;
          socklen_t addrlen = sizeof(address);

          // Specifying the address
          address.sin_family = AF_INET;
          address.sin_addr.s_addr = INADDR_ANY;
          address.sin_port = htons(port);

          // Creating socket file descriptor
          if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
            {
              perror("Socket initialization failed");
              exit(EXIT_FAILURE);
            }

          // Binding socket to the port
          if (bind(socket_fd, (struct sockaddr*)&address, sizeof(address)) < 0)
            {
              perror("Socket binding failed");
              exit(EXIT_FAILURE);
            }

          // Listening for connection
          if (listen(socket_fd, 1) < 0)
            {
              perror("Socket listening failed");
              exit(EXIT_FAILURE);
            }
          this->logger.print("Waiting for connection", WHITE, VERBOSE_LOW);

          // Connecting to core
          if ((*fd = accept(socket_fd, (struct sockaddr*)&address, &addrlen)) < 0)
            {
              perror("Could not connect to core");
              exit(EXIT_FAILURE);
            }
          this->logger.print("Connected to core", GREEN, VERBOSE_LOW);
        }



    protected:
      int port;
      int core_data_fd, core_control_fd;
      Logger logger;


      virtual void *input () = 0;
      virtual void *output() = 0;
      virtual void setup_middle () = 0;



    public:
      Middle ()
        {
          this->port = 8080;
        }


      void setup ()
        {
          this->setup_core ();
          this->setup_middle ();
        }


      static void *input_helper (void *context)
        {
          return ((Middle *) context)->input();
        }



      static void *output_helper (void *context)
        {
          return ((Middle *) context)->output();
        }



      void run ()
        {
          pthread_t thread_input, thread_output;

          if (pthread_create (&thread_input, NULL, Middle::input_helper, this) < 0)
            {
              perror ("Thread creation failed");
              exit (EXIT_FAILURE);
            }

          if (pthread_create (&thread_output, NULL, Middle::output_helper, this) < 0)
            {
              perror ("Thread creation failed");
              exit (EXIT_FAILURE);
            }

          pthread_join (thread_input, NULL);
          pthread_join (thread_output, NULL);
        }

  };

#endif