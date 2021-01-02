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
#include <string.h>

#include "neuropil.h"
#include "libbenchmark.h"

bool
authorize(np_context*, struct np_token*);

bool
receive(np_context*, struct np_message*);

int
main(int argc, char* argv[])
{
  struct np_settings cfg;
  np_default_settings(&cfg);
  np_context* ac = np_new_context(&cfg);
  np_mls_benchmark *benchmark =
    np_mls_create_benchmark("MyBenchmark",
                            "ba4a8c4c-3f91-11eb-b378-0242ac130002",
                            4,
                            NP_MLS_BENCHMARK_MESH_TOPOLOGY,
                            true);
  np_set_userdata(ac, benchmark);

  assert(np_ok == np_listen(ac, "udp4", "localhost", 6789));
  assert(np_ok == np_join(ac, "*:udp4:localhost:2345"));
  assert(np_ok == np_set_authorize_cb(ac, authorize));


  // set mls encryption
  struct np_mx_properties props = np_get_mx_properties(ac, "mysubject");
  //props.encryption_algorithm = MLS_ENCRYPTION;
  //props.mls_is_creator = true;
  np_set_mx_properties(ac, "mysubject", props);

  assert(np_ok == np_add_receive_cb(ac, "mysubject", receive));
  enum np_return status;


  // neuropil loop
  do {
    status = np_run(ac, 0);

    char message[100];
    printf("Enter message (max 100 chars): ");
    fgets(message, 200, stdin);
    // Remove trailing newline
    if ((strlen(message) > 0) && (message[strlen (message) - 1] == '\n'))
      message[strlen (message) - 1] = '\0';
    size_t message_len = strlen(message);
    np_send(ac, "mysubject", message, message_len);
    printf("Sent: %s\n", message);
  } while (np_ok == status);
  return status;
}

bool
authorize(np_context* ac, struct np_token* id)
{
  //printf("Authorizing on subject %s issuer:%s\n", id->subject, id->issuer);
  return true;
}

bool
receive(np_context* ac, struct np_message* message)
{
  printf("Received: %.*s\n", (int)message->data_length, message->data);
  return true;
}
