#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>
#include <queue>
#include <cstring>

#include "Logger.h"



#define DATA_REQUEST "data"

#define NO_DATA "None"
#define SIZE_OF_NO_DATA 4

#define DATA_RECEIVED "received"
#define SIZE_OF_DATA_RECEIVED 8



class Middle {
  private:
    int port;
    Logger logger;
    std::queue<char *> data;

    pthread_t thread_core, thread_input;

    void *input () {
      while (1)
        {
          std::string s;

          std::cin >> s;
          char *s_array = new char[s.length()+1];
          std::strcpy (s_array, s.c_str());
          this->data.push(s_array);
        }
      return 0;
    }

    void output (char data[]) {
      this->logger.print(data, GREEN, VERBOSE_VERY_HIGH);
    }

    void *communication_socket () {
      int socket_fd, core_fd;
      struct sockaddr_in address;
      socklen_t addrlen = sizeof(address);

      // Specifying the address
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = INADDR_ANY;
      address.sin_port = htons(this->port);

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
      if ((core_fd = accept(socket_fd, (struct sockaddr*)&address, &addrlen)) < 0)
        {
          perror("Could not connect to core");
          exit(EXIT_FAILURE);
        }
      this->logger.print("Connected to core", GREEN, VERBOSE_LOW);

      // Communicating with core
      while (1)
        {
          char data[2048] = {};
          if (read(core_fd, data,2048 - 1) < 0)
            {
              perror("Failed to read data");
            }
          else
            {
              // this->logger.print(data, WHITE, VERBOSE_LOW);
              if (strcmp(data, DATA_REQUEST) == 0)
                {
                  if (this->data.empty())
                    {
                      write(core_fd, NO_DATA, sizeof(char) * SIZE_OF_NO_DATA);
                    }
                  else
                    {
                      char *response = this->data.front();
                      this->data.pop();
                      write(core_fd, response, std::strlen (response));
                    }
                }

              // else if (strcmp(data, "") == 0)
              //   {
              //     break;
              //   }

              else
                {
                  write(core_fd, DATA_RECEIVED, sizeof(char) * SIZE_OF_DATA_RECEIVED);
                  this->output(data);
                }

            }

        }

      return 0;
    };

  public:
    Middle () {
      port = 8080;
    };

    static void *communication_socket_helper (void *context) {
      return ((Middle *) context)->communication_socket();
    }

    static void *input_helper (void *context) {
      return ((Middle *) context)->input();
    }

    void run () {
      if (pthread_create (&this->thread_core, NULL, Middle::communication_socket_helper, this) < 0)
        {
          perror("Thread creation failed");
          exit(EXIT_FAILURE);
        }

      if (pthread_create (&this->thread_input, NULL, Middle::input_helper, this) < 0)
        {
          perror("Thread creation failed");
          exit(EXIT_FAILURE);
        }

      pthread_join(this->thread_core, NULL);
      pthread_join(this->thread_input, NULL);
    }


};

int main() {
  Middle middle;
  middle.run();
}