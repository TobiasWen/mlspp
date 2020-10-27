#pragma once
#include "arraylist.h"
#include "hashtable.h"
#include "mlspp_wrapper.h"
#include "neuropil.h"
#include <np_types.h>

typedef enum {
  NP_MLS_PACKAGE_UNKNOWN = 0x000,
  NP_MLS_PACKAGE_HELLO = 0x001,
  NP_MLS_PACKAGE_KEYPACKAGE_REQUEST = 0x002,
  NP_MLS_PACKAGE_KEYPACKAGE_RESPONSE = 0x003,
  NP_MLS_PACKAGE_WELCOME = 0x004,
} np_mls_package_type;

typedef struct {
  char *name;
  size_t name_size;
} np_mls_group_member;

typedef struct {
  mls_bytes group_id;
  Session *session;
  arraylist *members;
} np_mls_group_data;

typedef struct {
  bool is_grp_lead;
  bool hellos_sent;
  bool invites_sent;
  int auths_left;
  int verifications_left;
} np_mls_client_state_info;

typedef struct {
    struct np_settings cfg;
    struct np_context *context;
    np_mls_client_state_info state_info;
    char *name;
    size_t name_size;
    bool isRunning;
    pthread_t *neuropil_thread; // TODO: no pointer needed P_THREAD_INITIALIZER
    Client *mls_client;
    arraylist *groups;
} np_mls_client;

typedef struct {
  np_mls_package_type type;
  char *sender;
  size_t sender_size;
  mls_bytes data;
} np_mls_package;

bool authorize(np_context *, struct np_token *);
bool receive_personal(np_context *, struct np_message *);
bool receive_group(np_context *, struct np_message *);
np_mls_client* new_np_mls_client(char name[], size_t name_size);
void np_mls_client_join_network(np_mls_client *client, char connection_string[], unsigned int port);
void delete_np_mls_client(np_mls_client *client);
void np_mls_client_neuropil_loop(np_mls_client *client);
bool np_mls_client_subscribe(np_mls_client* client, char subject[], bool (*handle_cb)(np_context*, struct np_message*));
bool np_mls_client_send(np_mls_client* client, char subject[], const unsigned char message[], size_t message_len);
void np_mls_say_hello(np_mls_client* client, char name[], size_t name_size);
void np_mls_client_invite_client(np_mls_client* client, mls_bytes group_id, char name[], size_t name_size);
void np_mls_client_create_group(np_mls_client* client, mls_bytes group_id);
void delete_np_mls_group_data(np_mls_group_data *group_data, const char *local_name);
void np_mls_send_fresh_key_package(np_mls_client *client, char name[], size_t name_size);
np_mls_group_data* np_mls_group_find_by_id(arraylist *groups, mls_bytes group_id);
bool np_mls_bytes_equals(mls_bytes first, mls_bytes second);
mls_bytes np_mls_signal_create(np_mls_client *sender, np_mls_package_type type);
mls_bytes np_mls_packet_create(np_mls_client *sender, np_mls_package_type type, mls_bytes data);
bool np_mls_handle_message(np_mls_client *client, np_mls_package_type package_type, char *sender, size_t sender_size,  mls_bytes data);

