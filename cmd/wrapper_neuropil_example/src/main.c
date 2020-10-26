#include "mlspp_wrapper.h"
#include "neuropil.h"
#include "np_mls_client.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef enum
{
  NP_MLS_STATE_BOOTSTRAP = 0x000,
  NP_MLS_STATE_CREATION = 0x001,
  NP_MLS_STATE_ADDITION = 0x002,
  NP_MLS_STATE_UPDATE = 0x003,
  NP_MLS_STATE_REMOVE = 0x004,
  NP_MLS_STATE_CLEANUP = 0x005,
} np_mls_api_example_sm;

void
handle_sigint();

bool isRunning;

int
main()
{
  ////////// DRAMATIS PERSONAE ///////////
  np_mls_client* alice = NULL;
  np_mls_client* bob = NULL;
  np_mls_client* charlie = NULL;

  np_mls_api_example_sm current_state = NP_MLS_STATE_BOOTSTRAP;
  isRunning = true;
  while (isRunning) {
    switch (current_state) {
      case NP_MLS_STATE_BOOTSTRAP: {
        // Create Clients
        alice = new_np_mls_client("alice", 5);
        bob = new_np_mls_client("bob", 3);
        charlie = new_np_mls_client("charlie", 7);
        // Join neuropil network
        np_mls_client_join_network(alice, "*:udp4:localhost:2345", 1234);
        np_mls_client_join_network(bob, "*:udp4:localhost:2345", 3456);
        np_mls_client_join_network(charlie, "*:udp4:localhost:2345", 4567);
        // Transition to Creation state
        current_state = NP_MLS_STATE_CREATION;
        break;
      }
      case NP_MLS_STATE_CREATION: {
        mls_bytes group_id = {};
        group_id.data = (uint8_t*)calloc(4, sizeof(uint8_t));
        group_id.size = 4;
        group_id.data[0] = 0;
        group_id.data[1] = 1;
        group_id.data[2] = 2;
        group_id.data[3] = 3;
        np_mls_client_create_group(alice, group_id);
        // Transition to Addition State
        current_state = NP_MLS_STATE_ADDITION;
        break;
      }
      case NP_MLS_STATE_ADDITION: {
        // Say Hello
        // Wait for authorize
        // Request Key Package
        // Send Welcome Message
        // Wait for verification
        break;
      }
      case NP_MLS_STATE_UPDATE: {
        break;
      }
      case NP_MLS_STATE_REMOVE: {
        break;
      }
      case NP_MLS_STATE_CLEANUP: {
        break;
      }
    }
    sleep(1);
  }
  /*////////// DRAMATIS PERSONAE ///////////
  // Create Clients
  np_mls_client* alice = new_np_mls_client("alice", 5);
  np_mls_client* bob = new_np_mls_client("bob", 3);
  np_mls_client* charlie = new_np_mls_client("charlie", 7);
  // Join neuropil network
  np_mls_client_join_network(alice, "*:udp4:localhost:2345", 1234);
  np_mls_client_join_network(bob, "*:udp4:localhost:2345", 3456);
  np_mls_client_join_network(charlie, "*:udp4:localhost:2345", 4567);

  ////////// ACT I: CREATION ////////////
  mls_bytes group_id = {};
  group_id.data = (uint8_t*)calloc(4, sizeof(uint8_t));
  group_id.size = 4;
  group_id.data[0] = 0;
  group_id.data[1] = 1;
  group_id.data[2] = 2;
  group_id.data[3] = 3;

  np_mls_client_create_group(alice, group_id);*/

  sleep(5);
  ////////// ACT II: ADDITION ///////////
  // say hello
  np_mls_say_hello(alice, "bob", 3);
  np_mls_say_hello(alice, "charlie", 7);
  sleep(5);
  np_mls_client_invite_client(alice, group_id, "bob", 3);
  np_mls_client_invite_client(alice, group_id, "charlie", 7);
  ////////// ACT V: Cleanup ///////////
  signal(SIGINT, handle_sigint);
  while (isRunning) {
    sleep(1);
  }
  alice->isRunning = false;
  bob->isRunning = false;
  charlie->isRunning = false;
  pthread_join(*alice->neuropil_thread, NULL);
  pthread_join(*bob->neuropil_thread, NULL);
  pthread_join(*charlie->neuropil_thread, NULL);
  return 0;
}

void
handle_sigint()
{
  isRunning = false;
}