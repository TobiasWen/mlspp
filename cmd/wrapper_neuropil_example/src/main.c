#include "mlspp_wrapper.h"
#include "neuropil.h"
#include "np_mls_client.h"
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

void handle_sigint();

bool isRunning;

int
main()
{
  isRunning = true;
  ////////// DRAMATIS PERSONAE ///////////
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
  group_id.data = (uint8_t*)malloc(sizeof(uint8_t) * 4);
  group_id.size = 4;
  group_id.data[0] = 0;
  group_id.data[1] = 1;
  group_id.data[2] = 2;
  group_id.data[3] = 3;

  np_mls_client_create_group(alice, group_id);

  sleep(5);


  ////////// ACT V: Cleanup ///////////
  signal(SIGINT, handle_sigint);
  while(isRunning) {
    ////////// ACT II: ADDITION ///////////
    np_mls_client_invite_client(alice, group_id, "bob", 3);
    np_mls_client_invite_client(alice, group_id, "charlie", 7);
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

void handle_sigint() {
  isRunning = false;
}