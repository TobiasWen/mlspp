#include "np_mls_client.h"
#include "assert.h"
#include "stdlib.h"
#include <np_tree.h>
#include <np_types.h>
#include <np_util.h>
#include <string.h>
#include <unistd.h>

bool authorize(np_context *context, struct np_token *id) {
  np_mls_client *client = np_get_userdata(context);
  if(client->state_info.is_grp_lead) {
    client->state_info.auths_left--;
  }
  printf("[%s] authz %s from %s: %02X%02X%02X%02X%02X%02X%02X...\n",client->name, id->subject, id->issuer, id->public_key[0], id->public_key[1], id->public_key[2], id->public_key[3], id->public_key[4], id->public_key[5], id->public_key[6]);
  return true;
}

bool receive_personal(np_context *context, struct np_message *message) {
  np_mls_client *client = np_get_userdata(context);
  np_tree_t *packet = np_tree_create();
  np_buffer2tree(context, message->data, packet);
  // Get Type
  np_tree_elem_t *source_type = np_tree_find_str(packet, "np.mls.type");
  if(source_type == NULL) {
    return false;
  }
  bool source_str_free = false;
  np_mls_package_type type = np_treeval_i(source_type->val);
  // Get Sender
  np_tree_elem_t *source_sender = np_tree_find_str(packet, "np.mls.sender");
  if(source_sender == NULL) {
    return false;
  }
  char *sender = np_treeval_to_str(source_sender->val, &source_str_free);
  printf("[%s] received from %s: %.*s\n",client->name, sender, message->data_length, message->data);
  mls_bytes data = {0};
  data.data = message->data;
  data.size = message->data_length;
  return np_mls_handle_message(client, type, sender, np_treeval_get_byte_size(source_sender->val), data);
}

bool receive_group(np_context *context, struct np_message *message) {
  np_mls_client *client = np_get_userdata(context);
  printf("[%s] received: %.*s\n",client->name, message->data_length, message->data);
  return true;
}

np_mls_client*
new_np_mls_client(char name[], size_t name_size)
{
  np_mls_client *client = calloc(1, sizeof(np_mls_client));
  client->name = calloc(1, name_size);
  client->neuropil_thread = calloc(1, sizeof(pthread_t));
  for (int i = 0; i < name_size; i++) {
    client->name[i] = name[i];
  }
  client->name_size = name_size;
  np_default_settings(&client->cfg);
  client->context = np_new_context(&client->cfg);
  client->groups = arraylist_create();
  client->mls_client = mls_create_client(X25519_CHACHA20POLY1305_SHA256_Ed25519, name);
  np_set_userdata(client->context, client);
  return client;
}

void np_mls_client_join_network(np_mls_client *client, char connection_string[], unsigned int port) {
  assert(np_ok == np_listen(client->context, "udp4", "localhost", port));
  assert(np_ok == np_join(client->context, connection_string));
  assert(np_ok == np_set_authorize_cb(client->context, authorize));
  // subscribe to personal channel
  char prefix[] = "mls/inbox/";
  size_t subject_size = sizeof(prefix) + client->name_size;
  char subject[subject_size + 1];
  strncpy(subject, prefix, subject_size);
  strncat(subject, client->name, subject_size);
  printf("Subscribing on subject: \"%s\"\n", subject);
  assert(np_ok == np_add_receive_cb(client->context, subject, receive_personal));
  // start neuropil thread
  client->isRunning = true;
  pthread_create(client->neuropil_thread, NULL, np_mls_client_neuropil_loop, client);
}

bool
np_mls_client_subscribe(np_mls_client* client,
                        char subject[],
                        bool (*handle_cb)(np_context*, struct np_message*))
{
  if(client) {
    assert(np_ok == np_add_receive_cb(client->context, subject, handle_cb));
    return true;
  } else {
    return false;
  }
}

bool np_mls_client_send(np_mls_client* client, char subject[], const unsigned char message[], size_t message_len) {
  if(client != NULL) {
    np_send(client->context, subject, message, message_len);
    return true;
  } else {
    return false;
  }
}

void np_mls_say_hello(np_mls_client* client, char name[], size_t name_size) {
  mls_bytes request_data = np_mls_signal_create(client, NP_MLS_PACKAGE_HELLO);
  char prefix[] = "mls/inbox/";
  size_t subject_size = sizeof(prefix) + name_size;
  char subject[subject_size + 1];
  strncpy(subject, prefix, subject_size);
  strncat(subject, name, subject_size);
  struct np_mx_properties props = np_get_mx_properties(client->context, subject);
  props.ackmode = NP_MX_ACK_NONE;
  props.message_ttl = 40.0;
  np_set_mx_properties(client->context, subject, props);
  assert(np_mls_client_send(client, subject, request_data.data, request_data.size));
}

void
delete_np_mls_client(np_mls_client *client)
{
  np_destroy(client->context, true);
  mls_delete_client(client->mls_client);
  size_t size = arraylist_size(client->groups);
  for(int i = 0; i < size; i++) {
    np_mls_group_data *group = arraylist_get(client->groups, i);
    delete_np_mls_group_data(group, client->name);
  }
  arraylist_destroy(client->groups);
  free(client->name);
  free(client);
}

void np_mls_client_neuropil_loop(np_mls_client *client) {
  // Run neuropil event loop
  printf("Starting neuropil loop on %s...\n", client->name);
  enum np_return status;
  do status = np_run(client->context, 5);
  while (np_ok == status && client->isRunning);
  printf("End of neuropil loop on %s...\n", client->name);
  pthread_exit(NULL);
}

void delete_np_mls_group_data(np_mls_group_data *group_data, const char *local_name) {
    mls_delete_bytes(group_data->group_id);
    for(int i = 0; i < arraylist_size(group_data->members); i++) {
      np_mls_group_member *member = arraylist_get(group_data->members, i);
      free(member->name);
    }
    arraylist_destroy(group_data->members);
    mls_delete_session(group_data->session);
    free(group_data);
}

void np_mls_send_fresh_key_package(np_mls_client *client, char name[], size_t name_size) {
  mls_bytes join = mls_pending_join_get_key_package(mls_start_join(client->mls_client));
  mls_bytes key_package_data = np_mls_packet_create(client, NP_MLS_PACKAGE_KEYPACKAGE_RESPONSE, join);
  char prefix[] = "mls/inbox/";
  size_t subject_size = sizeof(prefix) + name_size;
  char subject[subject_size + 1];
  strncpy(subject, prefix, subject_size);
  strncat(subject, name, subject_size);
  struct np_mx_properties props = np_get_mx_properties(client->context, subject);
  props.ackmode = NP_MX_ACK_NONE;
  props.message_ttl = 40.0;
  np_set_mx_properties(client->context, subject, props);
  assert(np_mls_client_send(client, subject, key_package_data.data, key_package_data.size));
}

void np_mls_client_invite_client(np_mls_client *client, mls_bytes group_id, char name[], size_t name_size) {
  // Request KeyPackage from client
  mls_bytes request_data = np_mls_signal_create(client, NP_MLS_PACKAGE_KEYPACKAGE_REQUEST);
  char prefix[] = "mls/inbox/";
  size_t subject_size = sizeof(prefix) + name_size;
  char subject[subject_size + 1];
  strncpy(subject, prefix, subject_size);
  strncat(subject, name, subject_size);
  //printf("Sending client invititation un subject: \"%s\"\n", subject);
  struct np_mx_properties props = np_get_mx_properties(client->context, subject);
  props.ackmode = NP_MX_ACK_NONE;
  props.message_ttl = 40.0;
  np_set_mx_properties(client->context, subject, props);
  assert(np_mls_client_send(client, subject, request_data.data, request_data.size));
  mls_delete_bytes(request_data);
}

void np_mls_client_create_group(np_mls_client *client, mls_bytes group_id) {
    Session* new_session = mls_begin_session(client->mls_client, group_id);
    np_mls_group_data *new_group = calloc(1, sizeof(np_mls_group_data));
    new_group->session = new_session;
    new_group->group_id = group_id;
    new_group->members = arraylist_create();
    np_mls_group_member *local_client = calloc(1, sizeof(*local_client));
    local_client->name = calloc(client->name_size, sizeof(*local_client->name));
    strcpy(local_client->name, client->name);
    local_client->name_size = client->name_size;
    arraylist_add(new_group->members, client->name);
    arraylist_add(client->groups, new_group);
}


np_mls_group_data* np_mls_group_find_by_id(arraylist *groups, mls_bytes group_id) {
  np_mls_group_data *group = NULL;
  for(int i = 0; i < arraylist_size(groups); i++) {
    np_mls_group_data *current_group = arraylist_get(groups, i);
    if(np_mls_bytes_equals(group_id, current_group->group_id)) {
      group = current_group;
    }
  }
  return group;
}

bool np_mls_bytes_equals(mls_bytes first, mls_bytes second) {
  if(first.size != second.size) {
    return false;
  }
  for(int i = 0; i < first.size; i++) {
    if(first.data[i] != second.data[i]) {
      return false;
    }
  }
  return true;
}

mls_bytes np_mls_signal_create(np_mls_client *sender, np_mls_package_type type) {
  np_tree_t *packet = np_tree_create();
  np_tree_replace_str(packet, "np.mls.type", np_treeval_new_i(type));
  np_tree_replace_str(packet, "np.mls.sender", np_treeval_new_s(sender->name));
  mls_bytes output = {0};
  output.size = packet->byte_size;
  output.data = calloc(1, output.size);
  np_tree2buffer((np_state_t*)sender->context, packet, output.data);
  np_tree_free(packet);
  return output;
}

mls_bytes np_mls_packet_create(np_mls_client *sender, np_mls_package_type type, mls_bytes data) {
  np_tree_t *packet = np_tree_create();
  np_tree_replace_int(packet, "np.mls.type", np_treeval_new_i(type));
  np_tree_replace_str(packet, "np.mls.sender", np_treeval_new_s(sender->name));
  np_tree_replace_str(packet, "np.mls.data", np_treeval_new_bin(data.data, data.size));
  mls_bytes output = {0};
  output.size = packet->byte_size;
  output.data = calloc(1, output.size);
  np_tree2buffer((np_state_t*)sender->context, packet, output.data);
  np_tree_free(packet);
  return output;
}

bool np_mls_handle_message(np_mls_client *client, np_mls_package_type package_type, char *sender, size_t sender_size, mls_bytes data) {
  switch(package_type) {
    case NP_MLS_PACKAGE_UNKNOWN:
      return true;
    case NP_MLS_PACKAGE_HELLO:
      printf("[%s] Got a Hello!\n", client->name);
      break;
    case NP_MLS_PACKAGE_KEYPACKAGE_REQUEST:
      printf("[%s] Got a Key Package Request!\n", client->name);
      np_mls_send_fresh_key_package(client, sender, sender_size);
      return true;
    case NP_MLS_PACKAGE_KEYPACKAGE_RESPONSE:
      printf("[%s] Got a Key Package Response!\n", client->name);
      return true;
    case NP_MLS_PACKAGE_WELCOME:
      printf("[%s] Got a Welcome message!\n", client->name);
      return true;
  }
  return false;
}


