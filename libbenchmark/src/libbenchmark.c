//
// Created by tobias on 15.12.20.
//

#include "libbenchmark.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// init
np_mls_benchmark* np_mls_create_benchmark(char *name, char *id, int num_clients_per_node, np_mls_benchmark_topology topology, bool has_sender) {
  if(name != NULL && id != NULL) {
    np_mls_benchmark *benchmark = calloc(1, sizeof(*benchmark));
    benchmark->id = calloc(1, strlen(name) + sizeof(*benchmark->id));
    strcpy(benchmark->id, id);
    benchmark->name = calloc(1, strlen(name) + sizeof(*benchmark->name));
    strcpy(benchmark->name, name);
    benchmark->results = arraylist_create();
    benchmark->num_clients_per_node = num_clients_per_node;
    benchmark->topology = topology;
    benchmark->lock = calloc(1, sizeof(*benchmark->lock));
    pthread_mutex_init(benchmark->lock, NULL);
    benchmark->has_sender = has_sender;
    return benchmark;
  }
  return NULL;
}

np_mls_benchmark_result* np_mls_create_benchmark_results(char *client_id, bool is_sender) {
  if(client_id != NULL) {
    np_mls_benchmark_result *benchmark_result = calloc(1, sizeof(*benchmark_result));
    benchmark_result->client_id = calloc(1, strlen(client_id) + sizeof(*benchmark_result->client_id));
    strcpy(benchmark_result->client_id, client_id);
    benchmark_result->is_sender = is_sender;
    benchmark_result->keys = arraylist_create();
    benchmark_result->units = hashtable_create();
    benchmark_result->values = hashtable_create();
    benchmark_result->lock = calloc(1, sizeof(*benchmark_result->lock));
    pthread_mutex_init(benchmark_result->lock, NULL);
    return benchmark_result;
  }
  return NULL;
}
// destroy
bool np_mls_destroy_benchmark(np_mls_benchmark *benchmark) {
  if(benchmark != NULL) {
    free(benchmark->name);
    free(benchmark->id);
    for(int i = 0; i < arraylist_size(benchmark->results); i++) {
      np_mls_benchmark_result *result = arraylist_get(benchmark->results, i);
      if(result != NULL) {
        np_mls_destroy_benchmark_result(result);
      }
    }
    arraylist_destroy(benchmark->results);
    pthread_mutex_unlock(benchmark->lock);
    pthread_mutex_destroy(benchmark->lock);
    return true;
  }
  return false;
}

bool np_mls_destroy_benchmark_result(np_mls_benchmark_result *result) {
  if(result != NULL) {
    free(result->client_id);
    for(int i = 0; i < arraylist_size(result->keys); i++) {
      char* key = arraylist_get(result->keys, i);
      if (key != NULL) {
        void* value = hashtable_get(result->values, key);
        free(value);
        void* unit = hashtable_get(result->units, key);
        free(unit);
      }
      free(key);
    }
    arraylist_destroy(result->keys);
    hashtable_destroy(result->units);
    hashtable_destroy(result->values);
    pthread_mutex_unlock(result->lock);
    pthread_mutex_destroy(result->lock);
    return true;
  } else {
    return false;
  }
}

// adding of results
bool np_mls_add_result_to_benchmark(np_mls_benchmark *benchmark, np_mls_benchmark_result *result) {
  if(benchmark != NULL && result != NULL && benchmark->results != NULL) {
    pthread_mutex_lock(benchmark->lock);
    arraylist_add(benchmark->results, result);
    pthread_mutex_unlock(benchmark->lock);
    return true;
  }
  return false;
}

bool np_mls_add_value_to_result(char *key, int value, char *unit, np_mls_benchmark_result *result) {
  if(key != NULL && unit != NULL && result != NULL) {
    pthread_mutex_lock(result->lock);
    arraylist_add(result->keys, key);
    char *ht_key = calloc(1, strlen(key) + sizeof(*ht_key));
    strcpy(ht_key, key);
    int *ht_value = calloc(1, sizeof(*ht_value));
    memcpy(ht_value, value, sizeof(*ht_value));
    hashtable_set(result->values, ht_key, ht_value);
    char *ht_unit = calloc(1, strlen(unit) + sizeof(*unit));
    strcpy(ht_unit, unit);
    hashtable_set(result->units, ht_key, ht_unit);
    pthread_mutex_unlock(result->lock);
    return true;
  }
  return false;
}

np_mls_clock* np_mls_clock_start() {
  np_mls_clock *cpu_clock = calloc(1, sizeof(*cpu_clock));
  cpu_clock->cpu_time_start = clock();
  clock_gettime(CLOCK_MONOTONIC, &cpu_clock->wall_time_start);
  return cpu_clock;
}

void np_mls_clock_stop(np_mls_clock *my_clock) {
  my_clock->cpu_time_end = clock();
  my_clock->cpu_time_used = ((double) (my_clock->cpu_time_end - my_clock->cpu_time_start)) / CLOCKS_PER_SEC;
  clock_gettime(CLOCK_MONOTONIC, &my_clock->wall_time_stop);
  my_clock->wall_time_used = ((double)my_clock->wall_time_stop.tv_sec + 1.0e-9*my_clock->wall_time_stop.tv_nsec) -
                             ((double)my_clock->wall_time_start.tv_sec + 1.0e-9*my_clock->wall_time_start.tv_nsec);
}

bool np_mls_clock_destroy(np_mls_clock *clock) {
  if(clock != NULL) {
    free(clock);
    return true;
  }
  return false;
}