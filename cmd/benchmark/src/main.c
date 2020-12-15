#include<stdio.h>
#include "libbenchmark.h"

int main() {
  np_mls_clock *my_clock = np_mls_clock_start();
  for(int i = 0; i < 2200000000; i++) {
    int a = 0;
    a += i;
  }
  np_mls_clock_stop(my_clock);
  printf("--------------------------------------\n");
  printf("Benchmark Results:\n");
  printf("--------------------------------------\n");
  printf("Wall clock time spent: %.9fs\n", my_clock->wall_time_used);
  printf("       CPU time spent: %.9fs\n", my_clock->cpu_time_used);
  printf("--------------------------------------\n");
  np_mls_clock_destroy(my_clock);
  return 0;
}