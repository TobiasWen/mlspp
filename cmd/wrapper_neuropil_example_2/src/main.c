//
// neuropil is copyright 2016-2020 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file
// for details
//

// Example: receiving messages.
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "neuropil.h"
#include "neuropil_attributes.h"
#include "np_key.h"
#include "np_mls_client.h"

bool
authorize(np_context*, struct np_token*);

bool
receive(np_context*, struct np_message*);

mls_bytes
extract_kp(struct np_token* id);

int
main(int argc, char* argv[])
{
  struct np_settings cfg;
  np_default_settings(&cfg);
  np_context* ac = np_new_context(&cfg);

  assert(np_ok == np_listen(ac, "udp4", "localhost", 3456));
  assert(np_ok == np_join(ac, "*:udp4:localhost:2345"));
  assert(np_ok == np_set_authorize_cb(ac, authorize));

  np_mls_client* mls_client = np_mls_create_client(ac);

  // add mls_client to context
  np_set_userdata(ac, mls_client);

  unsigned char local_fingerprint[NP_FINGERPRINT_BYTES];
  np_node_fingerprint(ac, local_fingerprint);
  np_id_str(mls_client->id, local_fingerprint);
  printf("Local Address: %s\n", mls_client->id);

  unsigned char subject_id[NP_FINGERPRINT_BYTES];
  np_get_id(subject_id, "mysubject", 0);
  char subject_id_str[65];
  np_id_str(subject_id_str, subject_id);
  //np_mls_create_group(mls_client, "mysubject", mls_client->id);
  assert(np_ok == np_mls_subscribe(mls_client, ac, "mysubject", receive));
  enum np_return status;

  // neuropil loop
  do {
    status = np_run(ac, 5.0);
    unsigned char subject_id[NP_FINGERPRINT_BYTES];
    np_get_id(subject_id, "mysubject", 0);
    char subject_id_str[65];
    np_id_str(subject_id_str, subject_id);
    // add user to group if local client is group leader
    np_mls_group* group = hashtable_get(mls_client->groups, subject_id_str);
    if (group != NULL && group->isCreator == true) {
      mls_bytes test_data = { 0 };
      test_data.data = calloc(1, 5);
      test_data.size = 5;
      test_data.data[0] = 1;
      test_data.data[1] = 2;
      test_data.data[2] = 3;
      test_data.data[3] = 4;
      test_data.data[4] = 5;

      mls_bytes packet = np_mls_create_packet_userspace(ac, group->local_session, test_data);
      np_mls_send(mls_client, ac, "mysubject", packet.data, packet.size);
      mls_delete_bytes(packet);
      mls_delete_bytes(test_data);
      np_mls_update(mls_client, ac, "mysubject");
      printf("Send testdata userspace message!\n");
    }
  } while (np_ok == status);

  // remove self from group
  uint32_t local_index = 0;
  assert(np_mls_get_group_index(mls_client, "mysubject", &local_index));
  np_mls_remove(mls_client, local_index, ac, "mysubject");

  return status;
}

bool
authorize(np_context* ac, struct np_token* id)
{
  printf("Authorizing on subject %s  issuer:%s\n", id->subject, id->issuer);
  // Extract kp from token
  mls_bytes kp = extract_kp(id);

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

mls_bytes
extract_kp(struct np_token* id)
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

bool
receive(np_context* ac, struct np_message* message)
{
  printf("Received: %.*s\n", (int)message->data_length, message->data);
  np_mls_client* mls_client = np_get_userdata(ac);
  return np_mls_handle_message(mls_client, ac, message);
}
