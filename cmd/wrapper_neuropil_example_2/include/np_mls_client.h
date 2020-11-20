#ifndef _TMP_CLION_CLANG_TIDY_NP_MLS_CLIENT_H
#define _TMP_CLION_CLANG_TIDY_NP_MLS_CLIENT_H

#include "arraylist.h"
#include "hashtable.h"
#include "mlspp_wrapper.h"
#include "neuropil.h"
#include "pthread.h"

static const char* NP_MLS_KP_KEY = "np.mls.kp";

typedef enum {
  NP_MLS_PACKAGE_UNKNOWN = 0x000,
  NP_MLS_PACKAGE_USERSPACE = 0x001,
  NP_MLS_PACKAGE_KEYPACKAGE = 0x002,
  NP_MLS_PACKAGE_ADD = 0x003,
  NP_MLS_PACKAGE_UPDATE = 0x004,
  NP_MLS_PACKAGE_REMOVE = 0x005,
  NP_MLS_PACKAGE_WELCOME = 0x006,
} np_mls_packet_type;

typedef enum  {
  MLS_GRP_OP_ADD = 0,
  MLS_GRP_OP_UPDATE,
  MLS_GRP_OP_REMOVE
} np_mls_group_operation;

typedef struct {
  mls_bytes id;
  Session *local_session;
  arraylist *added_clients;
  char *subject;
  bool isCreator;
  bool isInitialized;
} np_mls_group;

typedef struct {
  char id[65];
  Client *mls_client;
  hashtable *groups;
  arraylist *group_subjects;
  hashtable *pending_joins;
  arraylist *pending_subjects;
  pthread_mutex_t *lock;
} np_mls_client;

// client creation/deletion
np_mls_client* np_mls_create_client(np_context *ac);
bool np_mls_delete_client(np_mls_client *client);
bool np_mls_create_group(np_mls_client *client, const char* subject, const char *local_identifier);
bool np_mls_delete_group(np_mls_group *group);

bool np_mls_subscribe(np_mls_client *client, np_context *ac, const char* subject, np_receive_callback callback);
bool np_mls_unsubscribe(np_context *ac, const char* subject);
void np_mls_update(np_mls_client *client, np_context *ac, const char *subject);
enum np_return np_mls_send(np_mls_client *client, np_context *ac, const char *subject, const unsigned char* message, size_t length);

// network packets
mls_bytes np_mls_create_packet_userspace(np_context *ac, Session *local_session, mls_bytes data);
mls_bytes np_mls_create_packet_group_operation(np_context *ac, np_mls_group_operation op, mls_bytes data, mls_bytes commit);
mls_bytes np_mls_create_packet_welcome(np_context* ac, mls_bytes data, mls_bytes group_id, char *target_id);

// handle packets
bool np_mls_handle_message(np_mls_client *client, np_context *ac, struct np_message* message);
bool np_mls_handle_welcome(np_mls_client *client, np_context *ac, mls_bytes welcome, const char *subject, mls_bytes group_id);
bool np_mls_handle_usersprace(np_mls_client *client, np_context *ac, mls_bytes message, const char *subject);

// util
void print_bin2hex(mls_bytes bytes);
#endif
