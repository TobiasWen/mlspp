#pragma once
#include "arraylist.h"
#include "hashtable.h"
#include "mlspp_wrapper.h"
#include "neuropil.h"

typedef enum {
  NP_MLS_PACKAGE_UNKNOWN = 0x000,
  NP_MLS_PACKAGE_USERSPACE = 0x001,
  NP_MLS_PACKAGE_KEYPACKAGE = 0x002,
  NP_MLS_PACKAGE_ADD = 0x003,
  NP_MLS_PACKAGE_UPDATE = 0x004,
  NP_MLS_PACKAGE_REMOVE = 0x005,
  NP_MLS_PACKAGE_WELCOME = 0x006,
} np_mls_packet_type;

typedef struct {
  char id[65];
} np_mls_group_member;

typedef struct {
  mls_bytes id;
  Session *local_session;
  arraylist *members;
} np_mls_group;

typedef struct {
  Client *mls_client;
  hashtable *groups;
  arraylist *group_subjects;
} np_mls_client;

/** possible actions
 * 1. void create_group(np_mls_client, subject)
 * 2. bool subscribe(ac, subject, receive_cb)
 * 3. bool unsubscribe(ac, subject)
 * 4. void update(np_mls_client, subject)
 * 5. void send(np_mls_client, ac, subject, data, data_size)
*/
// client creation/deletion
np_mls_client* np_mls_create_client(np_context *ac);
bool np_mls_delete_client(np_mls_client *client);
bool np_mls_create_group(np_mls_client *client, const char* subject, const char *local_identifier);
bool np_mls_delete_group(np_mls_group *group);

bool np_mls_subscribe(np_context *ac, const char* subject, np_receive_callback callback);
bool np_mls_unsubscribe(np_context *ac, const char* subject);
void np_mls_update(np_mls_client *client, np_context *ac, const char *subject);
void np_mls_send(np_mls_client *client, np_context *ac, const char *subject, const unsigned char* message, size_t length);