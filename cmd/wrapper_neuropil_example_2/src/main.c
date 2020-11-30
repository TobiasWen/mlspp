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

  assert(np_ok == np_listen(ac, "udp4", "localhost", 4567));
  assert(np_ok == np_join(ac, "*:udp4:localhost:2345"));
  assert(np_ok == np_set_authorize_cb(ac, authorize));

  np_mls_client* mls_client = np_mls_create_client(ac);

  printf("Local Address: %s\n", mls_client->id);

  char *subject_id_str = get_np_id_string("mysubject");
  //np_mls_create_group(mls_client, "mysubject", mls_client->id);
  assert(np_ok == np_mls_subscribe(mls_client, ac, "mysubject", receive));
  enum np_return status;

  // neuropil loop
  do {
    status = np_run(ac, 5.0);
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
  np_mls_remove_self(mls_client, ac, "mysubject");
  free(subject_id_str);
  return status;
}

bool
authorize(np_context* ac, struct np_token* id)
{
  assert(np_mls_authorize(ac, id));
  return true;
}

bool
receive(np_context* ac, struct np_message* message)
{
  printf("Received: %.*s\n", (int)message->data_length, message->data);
  np_mls_client* mls_client = np_get_userdata(ac);
  return np_mls_handle_message(mls_client, ac, message);
}
