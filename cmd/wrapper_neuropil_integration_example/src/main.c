//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

// Example: sending messages.

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "neuropil.h"

bool authorize (np_context *, struct np_token *);

int main (void)
{

  struct np_settings cfg;
  np_default_settings(&cfg);

  np_context* ac = np_new_context(&cfg);
  assert(np_ok == np_listen(ac, "udp4", "localhost", 1234));
  np_run(ac, 0);
  assert(np_ok == np_join(ac, "*:udp4:localhost:2345"));
  assert(np_ok == np_set_authorize_cb(ac, authorize));

  enum np_return status;
  do {
    status = np_run(ac, 0);
    char message[100];
    printf("Enter message (max 100 chars): ");
    fgets(message, 200, stdin);
    // Remove trailing newline
    if ((strlen(message) > 0) && (message[strlen(message) - 1] == '\n'))
      message[strlen(message) - 1] = '\0';
    size_t message_len = strlen(message);
    np_send(ac, "mysubject", message, message_len);
    printf("Sent: %s\n", message);
  } while (np_ok == status);

  return status;
}

bool authorize (np_context *ac, struct np_token *id)
{
  // TODO: Make sure that id->public_key is the intended recipient!
  return true;
}
