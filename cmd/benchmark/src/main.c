#include "libbenchmark.h"
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

int
main()
{
  np_mls_benchmark* benchmark =
    np_mls_create_benchmark("MyBenchmark",
                            "ba4a8c4c-3f91-11eb-b378-0242ac130002",
                            4,
                            NP_MLS_BENCHMARK_MESH_TOPOLOGY,
                            true);

  np_mls_clock* my_clock = np_mls_clock_start();
  for (int i = 0; i < 2100000000; i++) {
    int a = 0;
    a += i;
    a *= a;
  }
  np_mls_clock_stop(my_clock);
  np_mls_benchmark_result *result = np_mls_create_benchmark_results("f3a6dd78-919d-486b-84c8-9dcd87ad5c76", true);
  np_mls_add_double_value_to_result("TestKey1", my_clock->wall_time_used, "s", result);
  np_mls_add_double_value_to_result("TestKey2", my_clock->cpu_time_used, "s", result);
  arraylist* my_nums = arraylist_create();
  for(double i = 0; i < my_clock->wall_time_used; i+=0.1) {
    double* my_double = calloc(1, sizeof(*my_double));
    memcpy(my_double, &i, sizeof(*my_double));
    arraylist_add(my_nums, my_double);
  }
  np_mls_add_list_to_result("TestKey3", my_nums, "s", result);
  printf("--------------------------------------\n");
  printf("Benchmark Results:\n");
  printf("--------------------------------------\n");
  printf("Wall clock time spent: %.9fs\n", *np_mls_get_double_value_from_result("TestKey1", result));
  printf("       CPU time spent: %.9fs\n", *np_mls_get_double_value_from_result("TestKey2", result));
  printf("--------------------------------------\n");
  printf("List:\n");
  printf("--------------------------------------\n");
  arraylist *my_list = np_mls_get_list_from_result("TestKey3", result);
  for(int i = 0; i < arraylist_size(my_list); i++) {
    double *value = arraylist_get(my_list, i);
    if(value != NULL) {
      printf("List Value: %.2fs\n", *value);
      free(value);
    }
  }
  arraylist_destroy(my_list);
  np_mls_clock_destroy(my_clock);
  np_mls_destroy_benchmark(benchmark);
  return 0;
}