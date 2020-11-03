//
// neuropil is copyright 2016-2020 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

// Example: receiving messages.

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "np_mls_client.h"

#include "neuropil.h"
#include "neuropil_attributes.h"

bool authorize (np_context *, struct np_token *);

bool receive (np_context *, struct np_message *);

int main (void)
{
  struct np_settings cfg;
  np_default_settings(&cfg);
  np_context *ac = np_new_context(&cfg);
  np_mls_client *mls_client = np_mls_create_client(ac);
  assert(np_ok == np_listen(ac, "udp4", "localhost", 3456));
  assert(np_ok == np_join(ac, "*:udp4:localhost:2345"));
  assert(np_ok == np_set_authorize_cb(ac, authorize));
  // Add fresh kpckg to mx properties and set mx properties to enfore token exchange
  struct np_mx_properties props = np_get_mx_properties(ac, "mysubject");
  uint8_t kp[4] = {0, 1, 2, 3};
  np_set_mxp_attr_bin(ac, "mysubject", NP_ATTR_USER_MSG, "np.mls.kp", kp, 4);
  np_set_mx_properties(ac, "mysubject", props);
  // Add receive callback to "mysubject"
  assert(np_ok == np_add_receive_cb(ac, "mysubject", receive));

  enum np_return status;

  // neuropil loop
  do status = np_run(ac, 5.0); while (np_ok == status);

  return status;
}

bool authorize (np_context *ac, struct np_token *id)
{
  return true;
}

bool receive (np_context* ac, struct np_message* message)
{
  printf("Received: %.*s\n", (int)message->data_length, message->data);
  return true;
}
