#pragma once
#include "np_mls_client.h"
#include "neuropil_attributes.h"
#include "np_types.h"
#include "np_util.h"
#include "sodium.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "util/np_tree.h"
#include <assert.h>

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

bool np_mls_authorize(np_context *ac, struct np_token *id) {
  printf("Authorizing on subject %s  issuer:%s\n", id->subject, id->issuer);
  // Extract kp from token
  mls_bytes kp = np_ml_extract_kp(id);

  // get np_mls_client from context
  np_mls_client* client = np_get_userdata(ac);

  unsigned char subject_id[NP_FINGERPRINT_BYTES];
  np_get_id(subject_id, id->subject, 0);
  char subject_id_str[65];
  np_id_str(subject_id_str, subject_id);
  // add user to group if local client is group leader
  np_mls_group* group = hashtable_get(client->groups, subject_id_str);
  if (group != NULL && group->isCreator == true) {
    // check if client was already added to group
    bool client_added = false;
    for(int i = 0; i < arraylist_size(group->added_clients); i++) {
      char *client = arraylist_get(group->added_clients, i);
      if(strcmp(client, id->issuer) == 0) {
        client_added = true;
        break;
      }
    }
    // Lock mutex
    pthread_mutex_lock(client->lock);
    if(!client_added) {
      mls_bytes add = mls_session_add(group->local_session, kp);
      mls_bytes add_proposals[] = { add };
      mls_bytes_tuple welcome_commit =
        mls_session_commit(group->local_session, add_proposals, 1);
      // create and send welcome on group channel
      mls_bytes welcome_packet =
        np_mls_create_packet_welcome(ac, welcome_commit.data1, group->id, id->issuer);
      // add client to added_clients list
      char *client_id = calloc(1, 65);
      strcpy(client_id, id->issuer);
      arraylist_add(group->added_clients, client_id);
      // create and send commit encrypted on group channel
      mls_bytes add_commit = np_mls_create_packet_group_operation(
        ac, MLS_GRP_OP_ADD, id->issuer, add, welcome_commit.data2);
      mls_session_handle(group->local_session, welcome_commit.data2);
      np_mls_send(client, ac, id->subject, add_commit.data, add_commit.size);
      assert(
        np_ok ==
        np_mls_send(
          client, ac, id->subject, welcome_packet.data, welcome_packet.size));
      printf("Sent welcome!\n");
      // cleanup
      mls_delete_bytes(add_commit);
      mls_delete_bytes_tuple(welcome_commit);
      mls_delete_bytes(welcome_packet);
      mls_delete_bytes(add);
    }
    pthread_mutex_unlock(client->lock);
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
  // ToDo: Encrypt data
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

bool
np_mls_handle_message(np_mls_client* client,
                      np_context* ac,
                      struct np_message* message)
{
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
    case NP_MLS_PACKAGE_USERSPACE: {
      char* subject_id_str = calloc(1, 65);
      np_id_str(subject_id_str, message->subject);
      np_tree_elem_t* source_data = np_tree_find_str(tree, NP_MLS_PACKAGE_DATA);
      if (source_data == NULL) {
        printf("Couldn't find userspace data\n");
        return true;
      }
      mls_bytes userdata = { 0 };
      size_t userdata_data_size = source_data->val.size;
      userdata.data = calloc(1, userdata_data_size);
      userdata.size = userdata_data_size;
      memcpy(userdata.data, source_data->val.value.bin, userdata_data_size);
      np_mls_handle_userspace(client, ac, userdata, subject_id_str);
      break;
    }
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
        printf("Couldn't find group id\n");
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
    case NP_MLS_PACKAGE_UNKNOWN:
      break;
    default:
      return true;
  }
  free(tree);
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