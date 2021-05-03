#include "np_mls.h"
#include "neuropil_attributes.h"
#include "np_legacy.h"
#include "np_types.h"
#include "np_util.h"
#include "sodium.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "util/np_tree.h"
#include <assert.h>
#include <core/np_comp_intent.h>
#include <np_axon.h>
#include <np_dendrit.h>
#include <np_keycache.h>
#include <np_message.h>
#include <np_serialization.h>

np_module_struct(mls) {
  np_state_t* context;
  np_mls_client *client;
};

// neuropil module functions
bool _np_mls_init(np_state_t* context) {
  np_module_malloc(mls);
  _module->client = np_mls_create_client(context);
  return true;
}

void _np_mls_destroy(np_state_t* context) {
  np_mls_client *client = np_module(mls)->client;
  if(client != NULL) {
    np_mls_delete_client(client);
  }
  np_module_free(mls);
}

void _np_mls_register_protocol_subject(np_state_t* context, const char* subject, np_msgproperty_t* property) {
    char protocol_subject[255];
    sprintf(protocol_subject, "mls_%.250s", subject);
    np_msgproperty_t* mls_protocol_property = _np_msgproperty_get_or_create(context, DEFAULT_MODE, protocol_subject);
    mls_protocol_property->mls_connected = property;
    property->mls_connected = mls_protocol_property;

    if (true == sll_contains(np_evt_callback_t, property->clb_outbound, _np_out_callback_wrapper, np_evt_callback_t_sll_compare_type))
    {   // first encrypt the payload for receiver
      sll_remove(np_evt_callback_t, property->clb_outbound, _np_out_callback_wrapper, np_evt_callback_t_sll_compare_type);
      sll_prepend(np_evt_callback_t, property->clb_outbound, _np_out_mls_callback_wrapper);
    }

    np_mls_client *mls_client = np_module(mls)->client;
    if(property->mls_is_creator) {
      np_mls_create_group(mls_client, protocol_subject, mls_client->id);
    }
    assert(np_ok == np_add_receive_cb(context, protocol_subject, np_mls_receive));
    printf("Created mls protocol subject %s!\n", protocol_subject);
}

bool _np_in_mls_callback_wrapper(np_state_t* context, np_util_event_t msg_event) {
  log_trace_msg(LOG_TRACE, "start: bool _np_in_mls_callback_wrapper(...){");

  NP_CAST(msg_event.user_data, np_message_t, msg_in);

  log_debug(LOG_MESSAGE, "(msg: %s) start mls callback wrapper",msg_in->uuid);

  bool ret = true;
  bool free_msg_subject = false;

  CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_SUBJECT, msg_subject_ele);
  CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_FROM, msg_from);

  char* msg_subject = np_treeval_to_str(msg_subject_ele, &free_msg_subject);
  np_msgproperty_t* msg_prop = _np_msgproperty_get(context, INBOUND, msg_subject);

  if (_np_msgproperty_threshold_breached(msg_prop))
  {
    ret = false;
  }
  else
  {
    log_msg(LOG_INFO, "decrypting mls message(%s/%s)", msg_prop->msg_subject, msg_in->uuid);
    // get mls client
    np_mls_client *mls_client = np_module(mls)->client;
    if(mls_client == NULL) {
      ret = false;
      printf("np_in_cb_wrapper mls client NULL\n");
    } else {
      // get group
      char *subject_id_str = np_mls_get_id_string(msg_prop->mls_connected->msg_subject);
      np_mls_group *group = np_mls_get_group_from_subject_id_str(mls_client, context, subject_id_str);
      if(group == NULL) {
        printf("np_in_cb_wrapper group NULL\n");
        ret = false;
      } else {
        printf("np_in_cb_wrapper decrypting\n");
        ret = np_mls_decrypt_payload(msg_in, group->local_session);
      }
      free(subject_id_str);
    }
  }
  __np_cleanup__:
  if (free_msg_subject) free(msg_subject);
  return ret;
}

bool _np_out_mls_callback_wrapper(np_state_t* context, const np_util_event_t event) {
  log_trace_msg(LOG_TRACE, "start: void __np_out_mls_callback_wrapper(...){");

  NP_CAST(event.user_data, np_message_t, message);
  np_dhkey_t prop_dhkey = _np_msgproperty_dhkey(OUTBOUND, _np_message_get_subject(message) );
  np_key_t*  prop_key   = _np_keycache_find(context, prop_dhkey);
  NP_CAST(sll_first(prop_key->entities)->val, np_msgproperty_t, my_property);

  bool ret = false;
  log_msg(LOG_INFO, "encrypting mls message(%s/%s)", my_property->msg_subject, message->uuid);
  // get mls client
  np_mls_client *mls_client = np_module(mls)->client;
  if(mls_client == NULL) {
    ret = false;
    printf("MLS Callback output wrapper client NULL!\n");
  } else {
    // get group
    char *subject_id_str = np_mls_get_id_string(my_property->mls_connected->msg_subject);
    np_mls_group *group = np_mls_get_group_from_subject_id_str(mls_client, context, subject_id_str);
    if(group == NULL) {
      ret = false;
      printf("MLS Callback output wrapper group NULL!\n");
    } else {
      // encrypt the message
      ret = np_mls_encrypt_payload(message, group->local_session);
      np_tree_elem_t* enc_msg_part = np_tree_find_str(message->body, NP_ENCRYPTED);
      if (NULL == enc_msg_part)
      {
        printf("couldn't find encrypted msg part in encryption method\n");
        return (false);
      }
    }
    free(subject_id_str);
  }
  return ret;
}

// client creation / deletion
np_mls_client*
np_mls_create_client(np_context* ac)
{
  unsigned char local_fingerprint[NP_FINGERPRINT_BYTES];
  np_node_fingerprint(ac, local_fingerprint);
  char *local_fingerprint_str = calloc(1, 65);
  np_id_str(local_fingerprint_str, local_fingerprint);
  np_mls_client* new_client = calloc(1, sizeof(*new_client));
  new_client->mls_client = mls_create_client(
    X25519_CHACHA20POLY1305_SHA256_Ed25519, local_fingerprint_str);
  new_client->id = local_fingerprint_str;
  new_client->groups = hashtable_create();
  new_client->group_subjects = arraylist_create();
  new_client->ids_to_subjects = hashtable_create();
  new_client->ids = arraylist_create();
  new_client->pending_joins = hashtable_create();
  new_client->pending_subjects = arraylist_create();
  new_client->lock = calloc(1, sizeof(*new_client->lock));
  pthread_mutex_init(new_client->lock, NULL);

  // add mls_client to context
  np_set_userdata(ac, new_client);
  //printf("MLS Client created!\n");
  return new_client;
}

bool
np_mls_delete_client(np_mls_client* client)
{
  if (client == NULL)
    return false;
  mls_delete_client(client->mls_client);
  for (int i = 0; i < arraylist_size(client->group_subjects); i++) {
    char* cur_subject = arraylist_get(client->group_subjects, i);
    if (cur_subject != NULL) {
      np_mls_group* group = hashtable_get(client->groups, cur_subject);
      if (group != NULL) {
        assert(np_mls_delete_group(group));
        hashtable_remove(client->groups, cur_subject);
      }
      free(cur_subject);
    }
  }

  for(int i = 0; i < arraylist_size(client->ids); i++) {
    char *cur_id = arraylist_get(client->ids, i);
    if(cur_id != NULL) {
      char *cur_subject = hashtable_get(client->ids_to_subjects, cur_id);
      if(cur_subject != NULL) {
        free(cur_subject);
      }
      free(cur_id);
    }
  }

  for (int i = 0; i < arraylist_size(client->pending_subjects); i++) {
    char* cur_subject = arraylist_get(client->pending_subjects, i);
    if (cur_subject != NULL) {
      PendingJoin* join = hashtable_get(client->pending_joins, cur_subject);
      if (join != NULL) {
        mls_delete_pending_join(join);
        hashtable_remove(client->pending_joins, cur_subject);
      }
      free(cur_subject);
    }
  }
  pthread_mutex_unlock(client->lock);
  pthread_mutex_destroy(client->lock);
  arraylist_destroy(client->group_subjects);
  hashtable_destroy(client->groups);
  hashtable_destroy(client->pending_joins);
  free(client);
  printf("MLS Client deleted!\n");
  return true;
}

bool
np_mls_create_group(np_mls_client* client,
                    const char* subject,
                    const char* local_identifier)
{
  // Convert subject to np_id
  char* subject_id_str = np_mls_get_id_string(subject);
  // Check if group already exists
  void* existing_group = hashtable_get(client->groups, subject_id_str);
  if (existing_group != NULL)
    return false;

  // Generate group id 5 values from 0 to 255
  mls_bytes group_id = np_mls_create_random_bytes(5);

  // Create new group
  Session* local_session = mls_begin_session(client->mls_client, group_id);
  np_mls_group* new_group = calloc(1, sizeof(*new_group));
  new_group->local_session = local_session;
  new_group->id = group_id;
  new_group->isCreator = true;
  new_group->isInitialized = true;
  new_group->subject = calloc(1, strlen(subject));
  new_group->added_clients = arraylist_create();

  strcpy(new_group->subject, subject);
  hashtable_set(client->groups, subject_id_str, new_group);
  arraylist_add(client->group_subjects, subject_id_str);
  printf("MLS group created!\n");
  return new_group;
}

bool
np_mls_delete_group(np_mls_group* group)
{
  mls_delete_bytes(group->id);
  mls_delete_session(group->local_session);
  for (int i = 0; i < arraylist_size(group->added_clients); i++) {
    char* client = arraylist_get(group->added_clients, i);
    if (client != NULL) {
      free(client);
    }
  }
  free(group->subject);
  free(group);
  printf("MLS group deleted!!\n");
}

bool
np_mls_subscribe(np_mls_client* client,
                 np_context* ac,
                 const char* subject,
                 np_receive_callback callback)
{
  // Add fresh kpckg to mx properties and set mx properties to enforce token
  // exchange
  struct np_mx_properties props = np_get_mx_properties(ac, subject);
  PendingJoin* join = mls_start_join(client->mls_client);
  // get np_id string of subject
  char* subject_id_str = np_mls_get_id_string(subject);
  // add subject to reverse lookup hashtable
  hashtable_set(client->ids_to_subjects, subject_id_str, subject);
  arraylist_add(client->ids, subject_id_str);
  hashtable_set(client->pending_joins, subject_id_str, join);
  arraylist_add(client->pending_subjects, subject_id_str);
  mls_bytes kp = mls_pending_join_get_key_package(join);
  np_set_mx_properties(ac, subject, props);
  np_set_mxp_attr_bin(
    ac, subject, NP_ATTR_INTENT, NP_MLS_KP_KEY, kp.data, kp.size);
  np_set_userdata(ac, client);
  // cleanup
  mls_delete_bytes(kp);
  return np_add_receive_cb(ac, subject, callback);
}

bool np_mls_receive(np_state_t* context, struct np_message* message) {
  np_mls_client *mls_client = np_module(mls)->client;
  bool ret = np_mls_handle_message(mls_client, context, message);
  return ret;
}

bool np_mls_authorize(np_state_t *context, char *subject) {
  //printf("Authorizing mls on subject %s\n", subject);

  // check if already in group for that subject
  np_mls_client *client = np_module(mls)->client;
  char *subject_id_str = np_mls_get_id_string(subject);
  np_mls_group *group = np_mls_get_group_from_subject_id_str(client, context, subject_id_str);
  if(group == NULL) {
    // check if there already exists a pending join for this subject
    if(hashtable_get(client->pending_joins, subject_id_str) != NULL) {
      return true;
    }
    // create new key package
    PendingJoin* join = mls_start_join(client->mls_client);
    // add subject to reverse lookup hashtable
    hashtable_set(client->ids_to_subjects, subject_id_str, subject);
    arraylist_add(client->ids, subject_id_str);
    hashtable_set(client->pending_joins, subject_id_str, join);
    arraylist_add(client->pending_subjects, subject_id_str);
    mls_bytes kp = mls_pending_join_get_key_package(join);
    mls_bytes key_package = np_mls_create_packet_keypackage(context, kp);
    // send key package
    np_send(context, subject, key_package.data, key_package.size);
    mls_delete_bytes(kp);
    printf("Sent Keypackage!\n");
  }
  return true;
}

void
np_mls_update(np_mls_client* client, np_context* ac, const char* subject)
{
  // get group from subject
  unsigned char* subject_id = calloc(1, NP_FINGERPRINT_BYTES);
  np_get_id(subject_id, subject, 0);
  char* subject_id_str = calloc(1, 65);
  np_id_str(subject_id_str, subject_id);
  pthread_mutex_lock(client->lock);
  np_mls_group* group = hashtable_get(client->groups, subject_id_str);
  if (group != NULL) {
    // create update
    mls_bytes update = mls_session_update(group->local_session);
    mls_bytes update_proposals[] = { update };
    mls_bytes_tuple update_commit =
      mls_session_commit(group->local_session, update_proposals, 1);
    mls_session_handle(group->local_session, update_commit.data2);
    // send update on group channel
    mls_bytes message = np_mls_create_packet_group_operation(
      ac, MLS_GRP_OP_UPDATE, "", update, update_commit.data2);
    assert(np_ok ==
           np_mls_send(client, ac, subject, message.data, message.size));
    mls_delete_bytes(update);
    mls_delete_bytes_tuple(update_commit);
    mls_delete_bytes(message);
  } else {
    printf("Received update for missing group!\n");
  }
  pthread_mutex_unlock(client->lock);
}

void
np_mls_remove(np_mls_client *client,
              uint32_t remove_index,
              np_context *ac,
              const char *subject,
              const char *removed_client_id)
{
  // get group from subject
  unsigned char* subject_id = calloc(1, NP_FINGERPRINT_BYTES);
  np_get_id(subject_id, subject, 0);
  char* subject_id_str = calloc(1, 65);
  np_id_str(subject_id_str, subject_id);
  pthread_mutex_lock(client->lock);
  np_mls_group* group = hashtable_get(client->groups, subject_id_str);
  if (group != NULL) {
    // create update
    mls_bytes remove = mls_session_remove(group->local_session, remove_index);
    mls_bytes remove_proposals[] = { remove };
    mls_bytes_tuple remove_commit =
      mls_session_commit(group->local_session, remove_proposals, 1);
    mls_session_handle(group->local_session, remove_commit.data2);
    // send update on group channel
    mls_bytes message = np_mls_create_packet_group_operation(
      ac, MLS_GRP_OP_REMOVE, removed_client_id, remove, remove_commit.data2);
    assert(np_ok ==
           np_mls_send(client, ac, subject, message.data, message.size));
    mls_delete_bytes(remove);
    mls_delete_bytes_tuple(remove_commit);
    mls_delete_bytes(message);
  }
  pthread_mutex_unlock(client->lock);
}

void np_mls_remove_self(np_mls_client *client, np_context *ac, const char *subject) {
  // get local index
  uint32_t local_index = 0;
  assert(np_mls_get_group_index(client, subject, &local_index));
  // get group from subject_id_str
  char *subject_id_str = np_mls_get_id_string(subject);
  np_mls_group *group = np_mls_get_group_from_subject_id_str(client, ac, subject_id_str);
  np_mls_remove(client, local_index, ac, subject_id_str, client->id);
  // delete group and remove from hashtable as well as array
  assert(np_mls_remove_from_local_group(client, group, subject_id_str));
}

bool np_mls_remove_from_local_group(np_mls_client *client, np_mls_group *group, const char *subject_id_str) {
  if(client != NULL && group != NULL && subject_id_str != NULL) {
    np_mls_delete_group(group);
    hashtable_remove(client->groups, subject_id_str);
    assert(np_mls_remove_string_elem_from_array(client->group_subjects, subject_id_str));
    // TODO: remove callback for subject
  }
}

enum np_return
np_mls_send(np_mls_client* client,
            np_context* ac,
            const char* subject,
            const unsigned char* message,
            size_t length)
{
  // TODO: create check if client is in grp etc.
  return np_send(ac, subject, message, length);
}

// encrypt / decrypt
bool np_mls_decrypt_payload(np_message_t *msg, Session *local_session) {
  np_ctx_memory(msg);
  np_tree_elem_t* enc_msg_part = np_tree_find_str(msg->body, NP_ENCRYPTED);
  if (NULL == enc_msg_part)
  {
    log_msg(LOG_ERROR, "couldn't find encrypted msg part");
    return (false);
  }

  mls_bytes encrypted = {.data = enc_msg_part->val.value.bin, .size = enc_msg_part->val.size };
  mls_bytes decrypted = mls_unprotect(local_session, encrypted);

  cmp_ctx_t cmp;
  cmp_init(&cmp, decrypted.data, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
  if(np_tree_deserialize( context, msg->body, &cmp) == false) {
    log_debug_msg(LOG_ERROR, "couldn't deserialize msg part after decryption");
    return false;
  }
  np_tree_del_str(msg->body, NP_ENCRYPTED);
  return true;
}

bool np_mls_encrypt_payload(np_message_t *msg, Session *local_session) {
  np_ctx_memory(msg);
  cmp_ctx_t cmp = {0};
  unsigned char msg_part_buffer[msg->body->byte_size*2];
  void* msg_part_buf_ptr = msg_part_buffer;

  cmp_init(&cmp, msg_part_buf_ptr, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
  np_tree_serialize(context, msg->body, &cmp);
  uint32_t msg_part_len = cmp.buf-msg_part_buf_ptr;

  mls_bytes plaintext = {.data = msg_part_buf_ptr, .size = msg_part_len};
  mls_bytes encrypted = mls_protect(local_session, plaintext);
  np_tree_insert_str(msg->body, NP_ENCRYPTED,
                                np_treeval_new_bin(encrypted.data, encrypted.size));
  mls_delete_bytes(encrypted);
  return true;
}

bool
np_mls_get_group_index(np_mls_client* client,
                       const char* subject,
                       uint32_t* index_out)
{
  // create np_id_str from subject
  unsigned char* subject_id = calloc(1, NP_FINGERPRINT_BYTES);
  np_get_id(subject_id, subject, 0);
  char* subject_id_str = calloc(1, 65);
  np_id_str(subject_id_str, subject_id);
  // get group for np_id_str_subject
  np_mls_group* group = hashtable_get(client->groups, subject_id_str);
  if (group != NULL && index_out != NULL) {
    index_out = mls_get_session_group_index(group->local_session);
    return true;
  }
  return false;
}

np_mls_group* np_mls_get_group_from_subject_id_str(np_mls_client *client, np_context *ac, const char *subject) {
  if(client != NULL && ac != NULL && subject != NULL) {
    return hashtable_get(client->groups, subject);
  } else {
    return NULL;
  }
}

mls_bytes
np_ml_extract_kp(struct np_token* id)
{
  mls_bytes kp = { 0 };
  // Extract data
  struct np_data_conf conf_data = { 0 };
  struct np_data_conf* conf_data_p = &conf_data;
  unsigned char* out_data = NULL;
  np_get_token_attr_bin(id, NP_MLS_KP_KEY, &conf_data_p, &out_data);
  kp.data = out_data;
  kp.size = conf_data.data_size;
  return kp;
}

// network packets
mls_bytes
np_mls_create_packet_userspace(np_context* ac,
                               Session* local_session,
                               mls_bytes data)
{
  np_tree_t* packet = np_tree_create();
  np_tree_replace_str(
    packet, NP_MLS_PACKAGE_TYPE, np_treeval_new_i(NP_MLS_PACKAGE_USERSPACE));
  // encrypt
  mls_bytes data_encrypted = mls_protect(local_session, data);
  printf("Plain data: \n");
  np_mls_print_bin2hex(data);
  printf("Encrypted data: \n");
  np_mls_print_bin2hex(data_encrypted);
  mls_bytes decrypted = mls_unprotect(local_session, data_encrypted);
  printf("Encrypted data decrypted: \n");
  np_mls_print_bin2hex(decrypted);
  np_tree_replace_str(
    packet,
    NP_MLS_PACKAGE_DATA,
    np_treeval_new_bin(data_encrypted.data, data_encrypted.size));
  mls_bytes output = { 0 };
  output.size = packet->byte_size;
  output.data = calloc(1, output.size);
  np_tree2buffer(ac, packet, output.data);
  np_tree_free(packet);
  return output;
}

mls_bytes
np_mls_create_packet_group_operation(np_context* ac,
                                     np_mls_group_operation op,
                                     const char* relevant_client_id,
                                     mls_bytes data,
                                     mls_bytes commit)
{
  np_tree_t* packet = np_tree_create();
  np_mls_packet_type type;
  switch (op) {
    case MLS_GRP_OP_ADD:
      np_tree_replace_str(
        packet, NP_MLS_PACKAGE_ADDED_ID, np_treeval_new_s(relevant_client_id));
      type = NP_MLS_PACKAGE_ADD;
      break;
    case MLS_GRP_OP_UPDATE:
      type = NP_MLS_PACKAGE_UPDATE;
      break;
    case MLS_GRP_OP_REMOVE:
      np_tree_replace_str(
        packet, NP_MLS_PACKAGE_REMOVED_ID, np_treeval_new_s(relevant_client_id));
      type = NP_MLS_PACKAGE_REMOVE;
      break;
  }
  np_tree_replace_str(packet, NP_MLS_PACKAGE_TYPE, np_treeval_new_i(type));
  np_tree_replace_str(
    packet, NP_MLS_PACKAGE_DATA, np_treeval_new_bin(data.data, data.size));
  np_tree_replace_str(
    packet, NP_MLS_PACKAGE_COMMIT, np_treeval_new_bin(commit.data, commit.size));
  mls_bytes output = { 0 };
  output.size = packet->byte_size;
  output.data = calloc(1, output.size);
  np_tree2buffer(ac, packet, output.data);
  np_tree_free(packet);
  return output;
}

mls_bytes
np_mls_create_packet_welcome(np_context* ac,
                             mls_bytes data,
                             mls_bytes group_id,
                             char* target_id)
{
  np_tree_t* packet = np_tree_create();
  np_tree_replace_str(
    packet, NP_MLS_PACKAGE_TYPE, np_treeval_new_i(NP_MLS_PACKAGE_WELCOME));
  np_tree_replace_str(packet,
                      NP_MLS_PACKAGE_GROUP_ID,
                      np_treeval_new_bin(group_id.data, group_id.size));
  np_tree_replace_str(
    packet, NP_MLS_PACKAGE_DATA, np_treeval_new_bin(data.data, data.size));
  np_tree_replace_str(packet, NP_MLS_PACKAGE_TARGET_ID, np_treeval_new_s(target_id));
  mls_bytes output = { 0 };
  output.size = packet->byte_size;
  output.data = calloc(1, output.size);
  np_tree2buffer(ac, packet, output.data);
  np_tree_free(packet);
  return output;
}

mls_bytes np_mls_create_packet_keypackage(np_state_t *context, mls_bytes data) {
  np_tree_t* packet = np_tree_create();
  np_tree_replace_str(
    packet, NP_MLS_PACKAGE_TYPE, np_treeval_new_i(NP_MLS_PACKAGE_KEYPACKAGE));
  np_tree_replace_str(
    packet, NP_MLS_PACKAGE_DATA, np_treeval_new_bin(data.data, data.size));
  mls_bytes output = { 0 };
  output.size = packet->byte_size;
  output.data = calloc(1, output.size);
  np_tree2buffer(context, packet, output.data);
  np_tree_free(packet);
  return output;
}

bool
np_mls_handle_message(np_mls_client* client,
                      np_context* ac,
                      struct np_message* message)
{
  //TODO: Return at end of function after free call and not in switch (memory leak)
  //TODO: Dont convert message->subject to np_id
  np_tree_t* tree = np_tree_create();
  np_buffer2tree(ac, message->data, tree);
  // Get Type
  np_tree_elem_t* source_type = np_tree_find_str(tree, NP_MLS_PACKAGE_TYPE);
  if (source_type == NULL) {
    printf("Couldn't find type\n");
    return true;
  }
  np_mls_packet_type type = source_type->val.value.i;
  switch (type) {
    case NP_MLS_PACKAGE_ADD: {
      np_mls_group_operation op = MLS_GRP_OP_ADD;
      char* subject_id_str = calloc(1, 65);
      np_id_str(subject_id_str, message->subject);
      np_mls_handle_group_operation(client, ac, op, message, subject_id_str);
      printf("Received add group operation packet!\n");
      break;
    }
    case NP_MLS_PACKAGE_UPDATE: {
      np_mls_group_operation op = MLS_GRP_OP_UPDATE;
      char* subject_id_str = calloc(1, 65);
      np_id_str(subject_id_str, message->subject);
      np_mls_handle_group_operation(client, ac, op, message, subject_id_str);
      printf("Received update group operation packet!\n");
      break;
    }
    case NP_MLS_PACKAGE_REMOVE: {
      np_mls_group_operation op = MLS_GRP_OP_REMOVE;
      char* subject_id_str = calloc(1, 65);
      np_id_str(subject_id_str, message->subject);
      np_mls_handle_group_operation(client, ac, op, message, subject_id_str);
      printf("Received remove group operation packet!\n");
      break;
    }
    case NP_MLS_PACKAGE_WELCOME: {
      // check if welcome packet is aimed at local client
      np_tree_elem_t* source_target =
        np_tree_find_str(tree, NP_MLS_PACKAGE_TARGET_ID);
      if (source_target == NULL) {
        printf("Couldn't find welcome target\n");
      }
      char* target_id = source_target->val.value.s;
      if (strcmp(target_id, client->id) != 0) {
        printf("Received welcome that is not targeted at this client!");
        return true;
      }
      printf("Received welcome packet!\n");
      np_tree_elem_t* source_data = np_tree_find_str(tree, NP_MLS_PACKAGE_DATA);
      if (source_data == NULL) {
        printf("Couldn't find welcome data\n");
        return true;
      }
      mls_bytes welcome = { 0 };
      size_t welcome_data_size = source_data->val.size;
      welcome.data = calloc(1, welcome_data_size);
      welcome.size = welcome_data_size;
      memcpy(welcome.data, source_data->val.value.bin, welcome_data_size);
      // get group id
      np_tree_elem_t* source_id = np_tree_find_str(tree, NP_MLS_PACKAGE_GROUP_ID);
      if (source_id == NULL) {
        printf("Couldn't find group id from welcome packet\n");
        return true;
      }
      mls_bytes group_id = { 0 };
      size_t group_id_size = source_id->val.size;
      group_id.data = calloc(1, group_id_size);
      group_id.size = group_id_size;
      memcpy(group_id.data, source_id->val.value.bin, group_id_size);
      char* subject_id_str = calloc(1, 65);
      np_id_str(subject_id_str, message->subject);
      return np_mls_handle_welcome(
        client, ac, welcome, subject_id_str, group_id);
    }
    case NP_MLS_PACKAGE_KEYPACKAGE: {
      // Extract kp from token and send welcome message
      np_tree_elem_t* source_data = np_tree_find_str(tree, NP_MLS_PACKAGE_DATA);
      if (source_data == NULL) {
        printf("Couldn't find keypackage data in received keypackage\n");
        return true;
      }
      mls_bytes kp = { 0 };
      size_t welcome_data_size = source_data->val.size;
      kp.data = calloc(1, welcome_data_size);
      kp.size = welcome_data_size;
      memcpy(kp.data, source_data->val.value.bin, welcome_data_size); //TODO: dont need memcpy

      char subject_id_str[65];
      np_id_str(subject_id_str, message->subject);
      char issuer_id_str[65];
      np_id_str(issuer_id_str, message->from);
      // add user to group if local client is group leader
      np_mls_group* group = hashtable_get(client->groups, subject_id_str);
      if (group != NULL && group->isCreator == true) {
        printf("Received Keypackage!\n");
        // check if client was already added to group
        bool client_added = false;
        for(int i = 0; i < arraylist_size(group->added_clients); i++) {
          char *added_client = arraylist_get(group->added_clients, i);
          if(strcmp(added_client, issuer_id_str) == 0) {
            client_added = true;
            break;
          }
        }
        // Lock mutex
        printf("Waiting on Mutex...\n");
        pthread_mutex_lock(client->lock);
        if(!client_added) {
          mls_bytes add = mls_session_add(group->local_session, kp);
          mls_bytes add_proposals[] = { add };
          mls_bytes_tuple welcome_commit =
            mls_session_commit(group->local_session, add_proposals, 1);
          // create and send welcome on group channel
          mls_bytes welcome_packet =
            np_mls_create_packet_welcome(ac, welcome_commit.data1, group->id, issuer_id_str);
          // add client to added_clients list
          char *client_id = calloc(1, 65);
          strcpy(client_id, issuer_id_str);
          arraylist_add(group->added_clients, client_id);
          // create and send commit encrypted on group channel
          mls_bytes add_commit = np_mls_create_packet_group_operation(
            ac, MLS_GRP_OP_ADD, issuer_id_str, add, welcome_commit.data2);
          mls_session_handle(group->local_session, welcome_commit.data2);
          np_mls_send(client, ac, group->subject, add_commit.data, add_commit.size);
          assert(
            np_ok ==
            np_mls_send(
              client, ac, group->subject, welcome_packet.data, welcome_packet.size));
          printf("Sent welcome!\n");
          // cleanup
          mls_delete_bytes(add_commit);
          mls_delete_bytes_tuple(welcome_commit);
          mls_delete_bytes(welcome_packet);
          mls_delete_bytes(add);
          sleep(1);
        }
        pthread_mutex_unlock(client->lock);
      }
      break;
    }
    case NP_MLS_PACKAGE_UNKNOWN:
      break;
    default:
      return true;
  }
  free(tree);
  return true;
}

bool
np_mls_handle_welcome(np_mls_client* client,
                      np_context* ac,
                      mls_bytes welcome,
                      const char* subject,
                      mls_bytes group_id)
{
  // lock mutex
  pthread_mutex_lock(client->lock);
  // check if already in group
  np_mls_group* group = hashtable_get(client->groups, subject);
  if (group != NULL) {
    return true;
  }
  // get pending join for subject
  PendingJoin* join = hashtable_get(client->pending_joins, subject);
  if(join != NULL) {
    Session* local_session = mls_pending_join_complete(join, welcome);
    // create group
    np_mls_group* new_group = calloc(1, sizeof(*new_group));
    new_group->local_session = local_session;
    new_group->id = group_id;
    new_group->isCreator = false;
    new_group->isInitialized = true;
    new_group->subject = hashtable_get(client->ids_to_subjects, subject);
    hashtable_set(client->groups, subject, new_group);
    printf("Successfully joined group!\n");
  } else {
    printf("No PendingJoin for welcome packet!\n");
  }
  pthread_mutex_unlock(client->lock);
  return true;
}

bool
np_mls_handle_userspace(np_mls_client* client,
                        np_context* ac,
                        mls_bytes message,
                        const char* subject)
{
  // check if already in group
  np_mls_group* group = hashtable_get(client->groups, subject);
  if (group == NULL) {
    return true;
  }
  // decrypt
  printf("Encrypted data: \n");
  np_mls_print_bin2hex(message);
  mls_bytes decrypted = mls_unprotect(group->local_session, message);
  printf("Decrypted data: \n");
  np_mls_print_bin2hex(decrypted);
  printf("Received userspace message in group with subject: %s.\n",
         group->subject);
  return true;
}

bool
np_mls_handle_group_operation(np_mls_client* client,
                              np_context* ac,
                              np_mls_group_operation operation,
                              struct np_message* message,
                              const char* subject)
{
  np_tree_t* tree = np_tree_create();
  np_buffer2tree(ac, message->data, tree);

  np_mls_group* group = hashtable_get(client->groups, subject);
  if (group == NULL) {
    printf("Received group operation for non-existing group!\n");
    return true;
  }
  // extract operation from message
  np_tree_elem_t* source_data = np_tree_find_str(tree, NP_MLS_PACKAGE_DATA);
  if (source_data == NULL) {
    printf("Couldn't find operation data\n");
    return true;
  }
  mls_bytes operation_data = { 0 };
  size_t operation_data_size = source_data->val.size;
  operation_data.data = calloc(1, operation_data_size);
  operation_data.size = operation_data_size;
  memcpy(operation_data.data, source_data->val.value.bin, operation_data_size);

  // extract commit from message
  np_tree_elem_t* commit_tree_elem = np_tree_find_str(tree, NP_MLS_PACKAGE_COMMIT);
  if (commit_tree_elem == NULL) {
    printf("Couldn't find commit data\n");
    return true;
  }
  mls_bytes commit_data = { 0 };
  size_t commit_data_size = commit_tree_elem->val.size;
  commit_data.data = calloc(1, commit_data_size);
  commit_data.size = commit_data_size;
  memcpy(commit_data.data, commit_tree_elem->val.value.bin, commit_data_size);

  switch (operation) {
    case MLS_GRP_OP_ADD: {
      // extract relevant client id
      np_tree_elem_t* client_id_tree_elem =
        np_tree_find_str(tree, NP_MLS_PACKAGE_ADDED_ID);
      if (client_id_tree_elem == NULL) {
        return true;
      }
      char* client_id = client_id_tree_elem->val.value.s;
      if (strcmp(client_id, client->id) == 0) {
        return true;
      }
      // handle add and commit
      mls_session_handle(group->local_session, operation_data);
      mls_session_handle(group->local_session, commit_data);
      break;
    }
    case MLS_GRP_OP_UPDATE:
      // handle update and commit
      mls_session_handle(group->local_session, operation_data);
      mls_session_handle(group->local_session, commit_data);
      break;
    case MLS_GRP_OP_REMOVE: {
      np_tree_elem_t* client_id_tree_elem =
        np_tree_find_str(tree, NP_MLS_PACKAGE_REMOVED_ID);
      if (client_id_tree_elem == NULL) {
        return true;
      }
      char* client_id = client_id_tree_elem->val.value.s;
      if (strcmp(client_id, client->id) == 0) {
        assert(np_mls_remove_from_local_group(client, group, subject));
        return true;
      }
      // handle remove and commit
      mls_session_handle(group->local_session, operation_data);
      mls_session_handle(group->local_session, commit_data);
      break;
    }
  }
  free(tree);
  return true;
}

void
np_mls_print_bin2hex(mls_bytes bytes)
{
  size_t hex_size = bytes.size * 2 + 1;
  char hex_buffer[hex_size];
  sodium_bin2hex(hex_buffer, hex_size, bytes.data, bytes.size);
  printf("Bin2Hex: %s\n", hex_buffer);
}

bool
np_mls_remove_string_elem_from_array(arraylist* list, const char* s)
{
  if (list == NULL || s == NULL) {
    return false;
  }
  for (int i = 0; i < arraylist_size(list); i++) {
    char* string = arraylist_get(list, i);
    if (string != NULL && strcmp(s, string) == 0)
      return true;
  }
  return false;
}

char* np_mls_get_id_string(char *s) {
  np_id subject_id;
  np_get_id(&subject_id, s, 0);
  char* subject_id_str = calloc(1, 65);
  np_id_str(subject_id_str, subject_id);
  return subject_id_str;
}

mls_bytes np_mls_create_random_bytes(uint32_t length) {
  mls_bytes output = {0};
  output.size = length;
  output.data = calloc(length, sizeof(*output.data));
  for (int i = 0; i < length; i++) {
    output.data[i] = rand() % (255 + 1);
  }
  return output;
}