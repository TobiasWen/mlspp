#pragma once
#include <pthread.h>
#include <stdbool.h>
#include <time.h>
#include "arraylist.h"
#include "hashtable.h"

static const char *NP_MLS_ENCRYPTION_TIME_WALL = "NP_MLS_ENCRYPTION_TIME_WALL";
static const char *NP_MLS_ENCRYPTION_TIME_CPU = "NP_MLS_ENCRYPTION_TIME_CPU";
static const char *NP_MLS_DECRYPTION_TIME_WALL = "NP_MLS_DECRYPTION_TIME_WALL";
static const char *NP_MLS_DECRYPTION_TIME_CPU = "NP_MLS_DECRYPTION_TIME_CPU";
static const char *NP_MLS_MESSAGE_OUT_BYTE_SIZE = "NP_MLS_MESSAGE_OUT_BYTE_SIZE";
static const char *NP_MLS_MESSAGE_IN_BYTE_SIZE = "NP_MLS_MESSAGE_IN_BYTE_SIZE";

typedef enum {
  NP_MLS_BENCHMARK_STAR_TOPOLOGY = 0x000,
  NP_MLS_BENCHMARK_MESH_TOPOLOGY = 0x001
} np_mls_benchmark_topology;

typedef enum {
  NP_MLS_NO_ENCRYPTION = 0x000,
  NP_MLS_JSON_ENCRYPTION = 0x001,
  NP_MLS_ENCRYPTION_X25519_AES128GCM_SHA256_Ed25519 = 0x002,
  NP_MLS_ENCRYPTION_P256_AES128GCM_SHA256_P256 = 0x002,
  NP_MLS_ENCRYPTION_X25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x003,
  NP_MLS_ENCRYPTION_X448_AES256GCM_SHA512_Ed448 = 0x004,
  NP_MLS_ENCRYPTION_P521_AES256GCM_SHA512_P521= 0x005,
  NP_MLS_ENCRYPTION_X448_CHACHA20POLY1305_SHA512_Ed448 = 0x006,
} np_mls_benchmark_algorithm;

typedef struct {
  char *name;
  char *id;
  int num_clients_per_node;
  int packet_byte_size;
  int message_send_num;
  np_mls_benchmark_topology topology;
  np_mls_benchmark_algorithm benchmark_algorithm;
  bool has_sender;
  arraylist *results;
  pthread_mutex_t *lock;
  char *result_url_endpoint;
  bool finished;
} np_mls_benchmark;

typedef struct {
  char *client_id;
  hashtable *values;
  hashtable *units;
  arraylist *keys;
  bool is_sender;
  pthread_mutex_t *lock;
} np_mls_benchmark_result;

typedef struct {
  clock_t cpu_time_start;
  clock_t cpu_time_end;
  double cpu_time_used;
  struct timespec wall_time_start;
  struct timespec wall_time_stop;
  double wall_time_used;
} np_mls_clock;

typedef struct {
  np_mls_benchmark *benchmark;
  np_mls_benchmark_result *result;
} benchmark_userdata;

// function typedefs
typedef void (*np_mls_benchmark_run)(np_mls_benchmark *benchmark);

// init
np_mls_benchmark* np_mls_create_benchmark(char *name,
                                          char *id,
                                          int num_clients_per_node,
                                          int packet_byte_size,
                                          int message_send_num,
                                          np_mls_benchmark_topology topology,
                                          np_mls_benchmark_algorithm benchmark_algortihm,
                                          bool has_sender,
                                          char *result_url_endpoint);

bool np_mls_benchmark_start(np_mls_benchmark *benchmark,
                            np_mls_benchmark_run benchmark_run_cb);
np_mls_benchmark_result* np_mls_create_benchmark_results(char *client_id, bool is_sender);
// destroy
bool np_mls_destroy_benchmark(np_mls_benchmark *benchmark);
bool np_mls_destroy_benchmark_result(np_mls_benchmark_result *result);
// adding of results
bool np_mls_add_result_to_benchmark(np_mls_benchmark *benchmark, np_mls_benchmark_result *result);
bool np_mls_add_int_value_to_result(char *key, int value, char *unit, np_mls_benchmark_result *result);
bool np_mls_add_double_value_to_result(char *key, double value, char *unit, np_mls_benchmark_result *result);
bool np_mls_add_list_to_result(char *key, arraylist *list, char *unit, np_mls_benchmark_result *result);
bool np_mls_add_value_to_result(char *key, void *value, size_t value_size, char *unit, np_mls_benchmark_result *result);
bool np_mls_add_int_to_list_result(char *key, int value, np_mls_benchmark_result *result);
bool np_mls_add_double_to_list_result(char *key, double value, np_mls_benchmark_result *result);
bool np_mls_add_value_to_list_result(char *key, void *value, size_t value_size, np_mls_benchmark_result *result);
// retrieval of results
char* np_mls_get_unit_from_result(char *key, np_mls_benchmark_result *result);
int* np_mls_get_int_value_from_result(char *key, np_mls_benchmark_result *result);
double* np_mls_get_double_value_from_result(char *key, np_mls_benchmark_result *result);
arraylist* np_mls_get_list_from_result(char *key, np_mls_benchmark_result *result);
void* np_mls_get_value_from_result(char *key, np_mls_benchmark_result *result);
// free
bool np_mls_free_list_items_from_result(char *key, np_mls_benchmark_result *result);
// measuring time
np_mls_clock* np_mls_clock_start();
void np_mls_clock_stop(np_mls_clock *my_clock);
bool np_mls_clock_destroy(np_mls_clock *clock);
// utility
char* generateUUID();
char* str_concat(const char *s1, const char *s2);
double np_mls_get_double_average(char *key, np_mls_benchmark_result *result);
double np_mls_get_int_average(char *key, np_mls_benchmark_result *result);
/**
   TODO: List for benchmarking
   1.(✓) Datastructure for the benchmark data itself
   2.(✓) Thread Safe datastructure for saving benchmark data associated with a string as key/value pair
   3.(✓) Way to save those benchmarks in the benchmark datastructure
   4.(✓) Way to conveniently measure cpu time and wall clock time in a local way
        - (✓) start specific measurement and create reference
        - (✓) stop specific measurement with reference created beforehand and return measured time
   5.( ) Think about getting the values in a convenient way
 */