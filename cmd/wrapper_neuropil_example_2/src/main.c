//
// neuropil is copyright 2016-2020 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

// Example: receiving messages.

#include "np_mls_client.h"
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "np_key.h"

#include "neuropil.h"
#include "neuropil_attributes.h"

bool authorize (np_context *, struct np_token *);

bool receive (np_context *, struct np_message *);

mls_bytes extract_kp(struct np_token *id);

int main (int argc, char* argv[])
{
  struct np_settings cfg;
  np_default_settings(&cfg);
  np_context *ac = np_new_context(&cfg);

  assert(np_ok == np_listen(ac, "udp4", "localhost", 1234));
  assert(np_ok == np_join(ac, "*:udp4:localhost:2345"));
  assert(np_ok == np_set_authorize_cb(ac, authorize));

  np_mls_client *mls_client = np_mls_create_client(ac);

  // add mls_client to context
  np_set_userdata(ac, mls_client);

  unsigned char local_fingerprint[NP_FINGERPRINT_BYTES];
  np_node_fingerprint(ac, local_fingerprint);
  np_id_str(mls_client->id, local_fingerprint);
  printf("Local Address: %s\n", mls_client->id);

  unsigned char subject_id[NP_FINGERPRINT_BYTES];
  np_get_id(subject_id, "mysubject", 0);
  // TODO:: Maybe all the subjects has to be string too instead of id? Yes they do!
  np_mls_create_group(mls_client, subject_id, local_fingerprint);
  assert(np_ok == np_mls_subscribe(mls_client, ac, "mysubject", receive));
  enum np_return status;

  // neuropil loop
  do status = np_run(ac, 5.0); while (np_ok == status);

  return status;
}

bool authorize (np_context *ac, struct np_token *id)
{
  // TODO:: Prepare for multiple authorizations
  printf("Authorizing on subject %s  issuer:%s\n", id->subject, id->issuer);
  // Extract kp from token
  mls_bytes kp = extract_kp(id);

  print_bin2hex(kp);
  // get np_mls_client from context
  np_mls_client *client = np_get_userdata(ac);

  unsigned char subject_id[NP_FINGERPRINT_BYTES];
  np_get_id(subject_id, id->subject, 0);
  // add user to group if local client is group leader
  np_mls_group *group = hashtable_get(client->groups, subject_id);
  if(group != NULL && group->isCreator == true) {
    mls_bytes add = mls_session_add(group->local_session, kp);
    mls_bytes add_proposals[] = { add };
    mls_bytes_tuple welcome_commit = mls_session_commit(group->local_session, add_proposals, 1);
    // create and send welcome on group channel
    mls_bytes welcome_packet = np_mls_create_packet_welcome(ac, welcome_commit.data1, group->id);
    assert(np_ok == np_mls_send(client, ac, id->subject, welcome_packet.data, welcome_packet.size));
    // create and send commit encrypted on group channel
    mls_bytes add_commit = np_mls_create_packet_group_operation(ac, MLS_GRP_OP_ADD, add, welcome_commit.data2);
    np_mls_send(client, ac, id->subject, add_commit.data, add_commit.size);
    printf("Sent welcome!\n");
    // cleanup
    mls_delete_bytes(add_commit);
    mls_delete_bytes_tuple(welcome_commit);
    mls_delete_bytes(welcome_packet);
    mls_delete_bytes(add);
  }
  return true;
}

mls_bytes extract_kp(struct np_token *id) {
  mls_bytes kp = {0};
  // Extract data
  struct np_data_conf conf_data = {0};
  struct np_data_conf *conf_data_p = &conf_data;
  unsigned char *out_data = NULL;
  np_get_token_attr_bin(id, NP_MLS_KP_KEY, &conf_data_p, &out_data);
  kp.data = out_data;
  kp.size = conf_data.data_size;
  return kp;
}

bool receive (np_context* ac, struct np_message* message)
{
  printf("Received: %.*s\n", (int)message->data_length, message->data);
  np_mls_client *mls_client = np_get_userdata(ac);
  return np_mls_handle_message(mls_client, ac, message);
}
