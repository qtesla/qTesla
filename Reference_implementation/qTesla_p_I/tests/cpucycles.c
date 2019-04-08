/********************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: utility functions for testing and benchmarking
*********************************************************************************************/

#include "cpucycles.h"
#include <time.h>


int64_t cpucycles(void)
{ // Access system counter for benchmarking
  unsigned int hi, lo;

  asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
  return ((int64_t)lo) | (((int64_t)hi) << 32);
}