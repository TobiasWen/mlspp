#pragma once

#include "arraylist.h"
#include "hashtable.h"
#include "mlspp_wrapper.h"
#include "neuropil.h"
#include "pthread.h"

static const char* NP_MLS_KP_KEY = "np.mls.kp";
static const char* NP_MLS_PACKAGE_TYPE = "np.mls.type";
static const char* NP_MLS_PACKAGE_DATA = "np.mls.data";
static const char* NP_MLS_PACKAGE_COMMIT = "np.mls.commit";
static const char* NP_MLS_PACKAGE_ADDED_ID = "np.mls.added.id";
static const char* NP_MLS_PACKAGE_REMOVED_ID = "np.mls.removed.id";
static const char* NP_MLS_PACKAGE_TARGET_ID = "np.mls.target.id";
static const char* NP_MLS_PACKAGE_GROUP_ID = "np.mls.group.id";

typedef enum {
  NP_MLS_PACKAGE_UNKNOWN = 0x000,
  NP_MLS_PACKAGE_USERSPACE = 0x001,
  NP_MLS_PACKAGE_ADD = 0x002,
  NP_MLS_PACKAGE_UPDATE = 0x003,
  NP_MLS_PACKAGE_REMOVE = 0x004,
  NP_MLS_PACKAGE_WELCOME = 0x005,
} np_mls_packet_type;

typedef enum  {
  MLS_GRP_OP_ADD = 0x000,
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
  char *id;
  Client *mls_client;
  hashtable *groups;
  arraylist *group_subjects;
  hashtable *ids_to_subjects;
  arraylist *ids;
  hashtable *pending_joins;
  arraylist *pending_subjects;
  pthread_mutex_t *lock;
} np_mls_client;

// client creation / deletion
np_mls_client* np_mls_create_client(np_context *ac);
bool np_mls_delete_client(np_mls_client *client);

// group creation
bool np_mls_create_group(np_mls_client *client, const char* subject, const char *local_identifier);
bool np_mls_delete_group(np_mls_group *group);

// subscribe/unsubscribe
bool np_mls_subscribe(np_mls_client *client, np_context *ac, const char* subject, np_receive_callback callback);
bool np_mls_unsubscribe(np_context *ac, const char* subject);

// authorize
bool np_mls_authorize(np_context *ac, struct np_token *id);

// update / remove
void np_mls_update(np_mls_client *client, np_context *ac, const char *subject);
void np_mls_remove(np_mls_client *client, uint32_t remove_index, np_context *ac, const char *subject, const char* removed_client_id);
void np_mls_remove_self(np_mls_client *client, np_context *ac, const char *subject);
bool np_mls_remove_from_local_group(np_mls_client *client, np_mls_group *group, const char *subject_id_str);

// send
enum np_return np_mls_send(np_mls_client *client, np_context *ac, const char *subject, const unsigned char* message, size_t length);

// get group (information)
bool np_mls_get_group_index(np_mls_client *client, const char *subject, uint32_t *index_out);
np_mls_group* np_mls_get_group_from_subject_id_str(np_mls_client *client, np_context *ac, const char *subject);

// extract kp from token
mls_bytes np_ml_extract_kp(struct np_token* id);

// network packets
mls_bytes np_mls_create_packet_userspace(np_context *ac, Session *local_session, mls_bytes data);
mls_bytes np_mls_create_packet_group_operation(np_context *ac, np_mls_group_operation op, const char* relevant_client_id, mls_bytes data, mls_bytes commit);
mls_bytes np_mls_create_packet_welcome(np_context* ac, mls_bytes data, mls_bytes group_id, char *target_id);

// handle packets
bool np_mls_handle_message(np_mls_client *client, np_context *ac, struct np_message* message);
bool np_mls_handle_welcome(np_mls_client *client, np_context *ac, mls_bytes welcome, const char *subject, mls_bytes group_id);
bool np_mls_handle_userspace(np_mls_client *client, np_context *ac, mls_bytes message, const char *subject);
bool np_mls_handle_group_operation(np_mls_client *client, np_context *ac, np_mls_group_operation operation, struct np_message *message, const char *subject);

// utility
void np_mls_print_bin2hex(mls_bytes bytes);
bool np_mls_remove_string_elem_from_array(arraylist *list, const char *s);
char* np_mls_get_id_string(char *s);
mls_bytes np_mls_create_random_bytes(uint32_t length);

