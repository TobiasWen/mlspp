#pragma once
#include "np_mls_client.h"
#include "neuropil_attributes.h"
#include "np_tree.h"
#include "np_types.h"
#include "np_util.h"
#include "sodium.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include <assert.h>

np_mls_client*
np_mls_create_client(np_context* ac)
{
  unsigned char local_fingerprint[NP_FINGERPRINT_BYTES];
  np_node_fingerprint(ac, local_fingerprint);
  const char local_fingerprint_str[65];
  np_id_str(local_fingerprint_str, local_fingerprint);
  np_mls_client* new_client = calloc(1, sizeof(*new_client));
  new_client->mls_client = mls_create_client(
    X25519_CHACHA20POLY1305_SHA256_Ed25519, local_fingerprint_str);
  new_client->groups = hashtable_create();
  new_client->group_subjects = arraylist_create();
  new_client->pending_joins = hashtable_create();
  new_client->pending_subjects = arraylist_create();
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
  unsigned char *subject_id = calloc(1, NP_FINGERPRINT_BYTES);
  np_get_id(subject_id, subject, 0);
  // Check if group already exists
  void* existing_group = hashtable_get(client->groups, subject_id);
  if (existing_group != NULL)
    return false;

  // Generate group id 5 values from 0 to 255
  mls_bytes group_id = { 0 };
  group_id.size = 5;
  group_id.data = calloc(5, sizeof(uint8_t));
  for (int i = 0; i < 5; i++) {
    group_id.data[i] = rand() % (255 + 1);
  }

  // Create new group
  Session* local_session = mls_begin_session(client->mls_client, group_id);
  np_mls_group* new_group = calloc(1, sizeof(*new_group));
  new_group->local_session = local_session;
  new_group->id = group_id;
  new_group->isCreator = true;
  new_group->isInitialized = true;
  new_group->subject = calloc(1, NP_FINGERPRINT_BYTES);
  strcpy(new_group->subject, subject);
  hashtable_set(client->groups, subject_id, new_group);
  arraylist_add(client->group_subjects, subject_id);
  return new_group;
}

bool
np_mls_delete_group(np_mls_group* group)
{
  mls_delete_bytes(group->id);
  mls_delete_session(group->local_session);
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
  hashtable_set(client->pending_joins, subject, join);
  arraylist_add(client->pending_subjects, subject);
  mls_bytes kp = mls_pending_join_get_key_package(join);
  print_bin2hex(kp);
  np_set_mx_properties(ac, subject, props);
  np_set_mxp_attr_bin(
    ac, subject, NP_ATTR_INTENT, NP_MLS_KP_KEY, kp.data, kp.size);
  np_set_userdata(ac, client);
  // cleanup
  mls_delete_bytes(kp);
  return np_add_receive_cb(ac, subject, callback);
}

bool
np_mls_unsubscribe(np_context* ac, const char* subject);
void
np_mls_update(np_mls_client* client, np_context* ac, const char* subject);

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

// network packets
mls_bytes
np_mls_create_packet_userspace(np_context* ac, mls_bytes data)
{
  np_tree_t* packet = np_tree_create();
  np_tree_replace_int(
    packet, "np.mls.type", np_treeval_new_i(NP_MLS_PACKAGE_USERSPACE));
  // ToDo: Encrypt data
  np_tree_replace_str(
    packet, "np.mls.data", np_treeval_new_bin(data.data, data.size));
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
                                     mls_bytes data,
                                     mls_bytes commit)
{
  np_tree_t* packet = np_tree_create();
  np_mls_packet_type type;
  switch (op) {
    case MLS_GRP_OP_ADD:
      type = NP_MLS_PACKAGE_ADD;
      break;
    case MLS_GRP_OP_UPDATE:
      type = NP_MLS_PACKAGE_UPDATE;
      break;
    case MLS_GRP_OP_REMOVE:
      type = NP_MLS_PACKAGE_REMOVE;
      break;
  }
  np_tree_replace_str(packet, "np.mls.type", np_treeval_new_i(type));
  // ToDo: Encrypt data
  np_tree_replace_str(
    packet, "np.mls.data", np_treeval_new_bin(data.data, data.size));
  np_tree_replace_str(
    packet, "np.mls.commit", np_treeval_new_bin(commit.data, commit.size));
  mls_bytes output = { 0 };
  output.size = packet->byte_size;
  output.data = calloc(1, output.size);
  np_tree2buffer(ac, packet, output.data);
  np_tree_free(packet);
  return output;
}

mls_bytes
np_mls_create_packet_welcome(np_context* ac, mls_bytes data, mls_bytes group_id)
{
  np_tree_t* packet = np_tree_create();
  np_tree_replace_str(
    packet, "np.mls.type", np_treeval_new_i(NP_MLS_PACKAGE_WELCOME));
  np_tree_replace_str(packet, "np.mls.group.id", np_treeval_new_bin(group_id.data, group_id.size));
  np_tree_replace_str(
    packet, "np.mls.data", np_treeval_new_bin(data.data, data.size));
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
  np_tree_elem_t* source_type = np_tree_find_str(tree, "np.mls.type");
  if (source_type == NULL) {
    printf("Couldn't find type\n");
    return false;
  }
  np_mls_packet_type type = source_type->val.value.i;
  switch (type) {
    case NP_MLS_PACKAGE_USERSPACE:
      // handleUserSpacePacket
      printf("Received userspace packet!\n");
      break;
    case NP_MLS_PACKAGE_ADD:
      // type = Add
    case NP_MLS_PACKAGE_UPDATE:
      // type = UPDATE
    case NP_MLS_PACKAGE_REMOVE:
      // type = Remove
      // handleGroupOperation(type)
      printf("Received group operation packet!\n");
      break;
    case NP_MLS_PACKAGE_WELCOME:
      printf("Received welcome packet!\n");
      np_tree_elem_t *source_data = np_tree_find_str(tree, "np.mls.data");
      if (source_data == NULL) {
        printf("Couldn't find welcome data\n");
        return false;
      }
      mls_bytes welcome = { 0 };
      size_t welcome_data_size = np_tree_get_byte_size(source_data);
      welcome.data = calloc(1, welcome_data_size);
      welcome.size = welcome_data_size;
      memcpy(welcome.data, source_data->val.value.bin, welcome_data_size);
      // get group id
      np_tree_elem_t *source_id = np_tree_find_str(tree, "np.mls.group.id");
      if(source_id == NULL) {
        printf("Couldn't find group id\n");
        return false;
      }
      mls_bytes group_id = { 0 };
      size_t group_id_size = np_tree_get_byte_size(source_id);
      group_id.data = calloc(1, group_id_size);
      group_id.size = group_id_size;
      memcpy(group_id.data, source_id->val.value.bin, group_id_size);
      // TODO Possible problem passing subject here?
      return np_mls_handle_welcome(client, ac, welcome, message->subject, group_id);
    case NP_MLS_PACKAGE_UNKNOWN:
      break;
    default:
      return false;
  }
}

bool
np_mls_handle_welcome(np_mls_client* client, np_context* ac, mls_bytes welcome, const char *subject, mls_bytes group_id)
{
  // check if already in group
  np_mls_group* group = hashtable_get(client->groups, subject);
  if (group != NULL) {
    return false;
  }
  // get pending join for subject
  PendingJoin *join = hashtable_get(client->pending_joins, subject);
  Session *local_session = mls_pending_join_complete(join, welcome);
  // create group
  np_mls_group* new_group = calloc(1, sizeof(*new_group));
  new_group->local_session = local_session;
  new_group->id = group_id; // TODO(tobias): Get group id (from welcome itself or send it with welcome)
  new_group->isCreator = false;
  new_group->isInitialized = true;
  hashtable_set(client->groups, subject, new_group);
  printf("Successfully joined group!\n");
  return true;
}

void
print_bin2hex(mls_bytes bytes)
{
  size_t hex_size = bytes.size * 2 + 1;
  char hex_buffer[hex_size];
  sodium_bin2hex(hex_buffer, hex_size, bytes.data, bytes.size);
}
