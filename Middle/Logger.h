#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <string.h>

enum VERBOSE {
  VERBOSE_LOW,
  VERBOSE_MEDIUM,
  VERBOSE_HIGH,
  VERBOSE_VERY_HIGH,
};

enum COLOR {
  RED,
  GREEN,
  YELLOW,
  BLUE,
  MAGENTA,
  CYAN,
  WHITE,
};

class Logger {
  private:
    VERBOSE verbose;

  public:
    Logger ()
      {
        verbose = VERBOSE_VERY_HIGH;
      }

    Logger (VERBOSE _verbose)
      {
        verbose = _verbose;
      }

    void print(std::string string, COLOR color, VERBOSE verbose)
      {
        if (verbose <= this->verbose)
          {
            int code;
            if (color == RED)
              code = 31;
            else if (color == GREEN)
              code = 32;
            else if (color == YELLOW)
              code = 33;
            else if (color == BLUE)
              code = 34;
            else if (color == MAGENTA)
              code = 35;
            else if (color == CYAN)
              code = 36;
            else if (color == WHITE)
              code = 37;


            std::cout << "\033[" << code << "m" << string << "\033[0m" << std::endl;

          }
      }
};

#endif