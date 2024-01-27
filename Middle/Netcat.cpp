#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>
#include <queue>
#include <utility>
#include <cstring>

#include "../Common/Logger.h"
#include "./Middle_Interface.h"


class Netcat : public Middle
  {
    protected:
      void setup_middle () {
        return;
      }



      void *input ()
        {
          while (1)
            {
              std::string s;

              std::cin >> s;
              int32_t length = htonl (s.length ());

              write (this->core_fd, &length, sizeof (length));
              write (this->core_fd, &s[0], s.length () * sizeof (char));
            }
        }



      void *output ()
        {
          while (1)
            {
              int32_t length;
              char s[2048];

              read (this->core_fd, &length, sizeof (length));
              length = ntohl (length);

              if (length == 0)
                continue;

              int n = read (this->core_fd, s, length * sizeof (char));
              if (n<= 0)
                {
                  this->logger.print ("read failed", RED, VERBOSE_HIGH);
                  continue;
                }
              for (int i=0; i< length; i++)
                {
                  std:: cout << s[i];
                }
              std::cout << std::endl;
            }
        }
  };



int main ()
  {
    Netcat nc;
    nc.setup ();
    nc.run ();
  }