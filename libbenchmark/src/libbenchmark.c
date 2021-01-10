#include "libbenchmark.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>
#include <stdio.h>
#include <unistd.h>

// init
np_mls_benchmark* np_mls_create_benchmark(char *name,
                                          char *id,
                                          int num_clients_per_node,
                                          int packet_byte_size,
                                          int message_send_num,
                                          np_mls_benchmark_topology topology,
                                          np_mls_benchmark_algorithm benchmark_algorithm,
                                          bool has_sender) {
  if(name != NULL && id != NULL) {
    np_mls_benchmark *benchmark = calloc(1, sizeof(*benchmark));
    benchmark->id = calloc(1, strlen(id) + sizeof(*benchmark->id));
    strcpy(benchmark->id, id);
    benchmark->name = calloc(1, strlen(name) + sizeof(*benchmark->name));
    strcpy(benchmark->name, name);
    benchmark->results = arraylist_create();
    benchmark->num_clients_per_node = num_clients_per_node;
    benchmark->packet_byte_size = packet_byte_size;
    benchmark->message_send_num = message_send_num;
    benchmark->topology = topology;
    benchmark->benchmark_algorithm = benchmark_algorithm;
    benchmark->lock = calloc(1, sizeof(*benchmark->lock));
    pthread_mutex_init(benchmark->lock, NULL);
    benchmark->has_sender = has_sender;
    benchmark->finished = false;
    return benchmark;
  }
  return NULL;
}

bool np_mls_benchmark_start(np_mls_benchmark *benchmark,
                            np_mls_benchmark_run benchmark_run_cb) {
  if(benchmark != NULL) {
    benchmark_run_cb(benchmark);
    return true;
  }
  return false;
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

bool np_mls_add_int_value_to_result(char *key, int value, char *unit, np_mls_benchmark_result *result) {
  return np_mls_add_value_to_result(key, &value, sizeof(value), unit, result);
}

bool np_mls_add_double_value_to_result(char *key, double value, char *unit, np_mls_benchmark_result *result) {
  return np_mls_add_value_to_result(key, &value, sizeof(value), unit, result);
}

bool np_mls_add_list_to_result(char *key, arraylist *list, char *unit, np_mls_benchmark_result *result) {
  return np_mls_add_value_to_result(key, list, sizeof(*list), unit, result);
}

bool np_mls_add_value_to_result(char *key, void *value, size_t value_size, char *unit, np_mls_benchmark_result *result) {
  if(key != NULL && unit != NULL && result != NULL && value != NULL) {
    pthread_mutex_lock(result->lock);
    arraylist_add(result->keys, key);
    char *ht_key = calloc(1, strlen(key) + sizeof(*ht_key));
    strcpy(ht_key, key);
    void *ht_value = calloc(1, value_size);
    memcpy(ht_value, value, value_size);
    hashtable_set(result->values, ht_key, ht_value);
    char *ht_unit = calloc(1, strlen(unit) + sizeof(*unit));
    strcpy(ht_unit, unit);
    hashtable_set(result->units, ht_key, ht_unit);
    pthread_mutex_unlock(result->lock);
    return true;
  }
  return false;
}

bool np_mls_add_int_to_list_result(char *key, int value, np_mls_benchmark_result *result) {
  return np_mls_add_value_to_list_result(key, &value, sizeof(value), result);
}

bool np_mls_add_double_to_list_result(char *key, double value, np_mls_benchmark_result *result) {
  return np_mls_add_value_to_list_result(key, &value, sizeof(value), result);
}

bool np_mls_add_value_to_list_result(char *key, void *value, size_t value_size, np_mls_benchmark_result *result) {
  if(key != NULL && result != NULL && value != NULL) {
    pthread_mutex_lock(result->lock);
    if(result->values != NULL) {
      arraylist *values = hashtable_get(result->values, key);
      if(values != NULL) {
        void *ht_value = calloc(1, value_size);
        memcpy(ht_value, value, value_size);
        arraylist_add(values, ht_value);
        pthread_mutex_unlock(result->lock);
        return true;
      }
    }
    pthread_mutex_unlock(result->lock);
  }
  return false;
}
// retrieval of results
char* np_mls_get_unit_from_result(char *key, np_mls_benchmark_result *result) {
  if(key != NULL && result != NULL) {
    char* unit = hashtable_get(result->units, key);
    if(unit != NULL) {
      return unit;
    }
  }
  return NULL;
}

int* np_mls_get_int_value_from_result(char *key, np_mls_benchmark_result *result) {
  return (int*) np_mls_get_value_from_result(key, result);
}

double* np_mls_get_double_value_from_result(char *key, np_mls_benchmark_result *result) {
  return (double*) np_mls_get_value_from_result(key, result);
}
arraylist* np_mls_get_list_from_result(char *key, np_mls_benchmark_result *result) {
  return (arraylist*) np_mls_get_value_from_result(key, result);
}

void* np_mls_get_value_from_result(char *key, np_mls_benchmark_result *result) {
  if(key != NULL && result != NULL) {
    void *value = hashtable_get(result->values, key);
    if(value != NULL) {
      return value;
    }
  }
  return NULL;
}

void np_mls_increase_message_count(np_mls_benchmark *benchmark, np_mls_benchmark_result *result) {
    if(benchmark != NULL && result != NULL && !benchmark->finished && result->message_count < benchmark->message_send_num) {
        pthread_mutex_lock(result->lock);
        result->message_count++;
        if(result->message_count >= benchmark->message_send_num) {
            result->finished = true;
            np_mls_clock_stop(result->duration_clock);
            int ready_results = 0;
            for(int i = 0; i < arraylist_size(benchmark->results); i++) {
                np_mls_benchmark_result *cur_result = arraylist_get(benchmark->results, i);
                if(cur_result != NULL && cur_result->finished) {
                    ready_results++;
                }
            }
            if(ready_results == benchmark->num_clients_per_node) {
                pthread_mutex_lock(benchmark->lock);
                benchmark->finished = true;
                pthread_mutex_unlock(benchmark->lock);
                np_mls_add_double_value_to_result(NP_BENCHMARK_TIME_WALL, result->duration_clock->wall_time_used, "s", result);
                np_mls_add_double_value_to_result(NP_BENCHMARK_TIME_CPU, result->duration_clock->cpu_time_used, "s", result);
            }
        } else if(result->message_count == 1) {
            result->duration_clock = np_mls_clock_start();
        }
        printf("[%s] Result messagecount: %d\n", result->client_id, result->message_count);
        pthread_mutex_unlock(result->lock);
    }
}

// free
bool np_mls_free_list_items_from_result(char *key, np_mls_benchmark_result *result) {
  if(key != NULL && result != NULL) {
    arraylist *list = hashtable_get(result->values, key);
    if(list != NULL) {
      for(int i = 0; i < arraylist_size(list); i++) {
        void *item = arraylist_get(list, i);
        if(item != NULL) {
          free(item);
        }
      }
      return true;
    }
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

// printing
void np_mls_benchmark_print_results(np_mls_benchmark *benchmark) {
    // calculate results
    // 1.) Get Benchmark Algorithm
    char *benchmark_algorithm = NULL;
    switch (benchmark->benchmark_algorithm) {
        case NP_MLS_JSON_ENCRYPTION:
            benchmark_algorithm = "JWE_128_CHACHA20POLY1305_SHA256_Ed25519";
            break;
        case NP_MLS_ENCRYPTION_X25519_AES128GCM_SHA256_Ed25519:
            benchmark_algorithm = "MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
            break;
        case NP_MLS_ENCRYPTION_X25519_CHACHA20POLY1305_SHA256_Ed25519:
            benchmark_algorithm = "MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519";
            break;
        case NP_MLS_ENCRYPTION_X448_CHACHA20POLY1305_SHA512_Ed448:
            benchmark_algorithm = "MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed44";
            break;
    }
    // 2.) Benchmark duration
    // get sender benchmark duration result
    np_mls_benchmark_result *sender_result;
    int sender_result_index = -1;
    for(int i = 0; i < arraylist_size(benchmark->results); i++) {
        np_mls_benchmark_result *cur_result = arraylist_get(benchmark->results, i);
        if(cur_result != NULL && cur_result->is_sender) {
            sender_result = cur_result;
            sender_result_index = i;
            np_mls_add_double_value_to_result(NP_BENCHMARK_TIME_WALL, cur_result->duration_clock->wall_time_used, "s", cur_result);
            np_mls_add_double_value_to_result(NP_BENCHMARK_TIME_CPU, cur_result->duration_clock->cpu_time_used, "s", cur_result);
            break;
        }
    }
    // get reeiver benchmark duration result

    // print results
    printf("-------------------------------------------------------------------------------\n");
    printf("Benchmark Results for %s:\n", benchmark->id);
    printf("-------------------------------------------------------------------------------\n");
    printf("    General Information \n");
    printf("-------------------------------------------------------------------------------\n");
    printf("                  Number of clients: %d\n", benchmark->num_clients_per_node);
    printf("            Number of messages sent: %d\n", benchmark->message_send_num);
    printf("                       Message size: %d bytes\n", benchmark->packet_byte_size);
    printf("               Encryption algorithm: %s\n", benchmark_algorithm);
    printf("               Encryption algorithm: %s\n", benchmark_algorithm);
    printf("             Communication Topology: %s\n", benchmark->topology == NP_MLS_BENCHMARK_STAR_TOPOLOGY ? "Star Topology" : "Mesh Topology");
    printf("-------------------------------------------------------------------------------\n");
    printf("                Results \n");
    printf("-------------------------------------------------------------------------------\n");
    printf("   Sender Benchmark Duration (Wall): %.9fs\n", sender_result != NULL ? *np_mls_get_double_value_from_result(NP_BENCHMARK_TIME_WALL, sender_result) : -1.0);
    printf("    Sender Benchmark Duration (CPU): %.9fs\n", sender_result != NULL ? *np_mls_get_double_value_from_result(NP_BENCHMARK_TIME_CPU, sender_result) : -1.0);
    printf("Average Receiver Benchmark Duration: %s\n", benchmark_algorithm);
    printf("             Averge Encryption Time: %s\n", benchmark_algorithm);
    printf("             Averge Decryption Time: %s\n", benchmark_algorithm);
    printf("             Message body byte size: %s\n", benchmark_algorithm);
    //printf("       CPU time spent: %.9fs\n", *np_mls_get_double_value_from_result("TestKey2", result));
    printf("-------------------------------------------------------------------------------\n");
}


// utility
char* generateUUID() {
  uuid_t binuuid;
  uuid_generate(binuuid);
  char *uuid = malloc(37);
  uuid_unparse(binuuid, uuid);
  return uuid;
}

char* str_concat(const char *s1, const char *s2)
{
  char *result = calloc(1,strlen(s1) + strlen(s2) + 1); // +1 for the null-terminator
  strcpy(result, s1);
  strcat(result, s2);
  return result;
}

double np_mls_get_double_average(char *key, np_mls_benchmark_result *result) {
    if(key != NULL && result != NULL) {
        arraylist *list = hashtable_get(result->values, key);
        if(list != NULL) {
            double sum = 0;
            unsigned int size = arraylist_size(list);
            for(int i = 0; i < arraylist_size(list); i++) {
                double *item = arraylist_get(list, i);
                if(item != NULL) {
                    sum+= *item;
                }
            }
            return size > 0 ? sum / size : 0;
        }
    }
    return -1;
}

double np_mls_get_int_average(char *key, np_mls_benchmark_result *result) {
    if(key != NULL && result != NULL) {
        arraylist *list = hashtable_get(result->values, key);
        if(list != NULL) {
            double sum = 0;
            unsigned int size = arraylist_size(list);
            for(int i = 0; i < arraylist_size(list); i++) {
                int *item = arraylist_get(list, i);
                if(item != NULL) {
                    sum+= *item;
                }
            }
            return size > 0 ? sum / size : 0;
        }
    }
    return -1;
}