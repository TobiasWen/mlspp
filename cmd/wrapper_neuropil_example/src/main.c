#include "mlspp_wrapper.h"
#include "neuropil.h"
#include "np_mls_client.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void handle_sigint();

bool isRunning;

int
main()
{
  isRunning = true;

  // group subject
  char *subject = "mygroup";
  size_t subject_size = 7;

  // leader subject
  char *leader_subject = "mygroup_leader";
  size_t leader_subject_size = 14;

  ////////// DRAMATIS PERSONAE ///////////
  // Create Clients
  np_mls_client* alice = new_np_mls_client("alice", 5);
  np_mls_client* bob = new_np_mls_client("bob", 3);
  np_mls_client* charlie = new_np_mls_client("charlie", 7);
  // Join neuropil network
  np_mls_client_join_network(alice, "*:udp4:localhost:2345", 1234);
  np_mls_client_join_network(bob, "*:udp4:localhost:2345", 3456);
  np_mls_client_join_network(charlie, "*:udp4:localhost:2345", 4567);
  sleep(5);
  // Say hello
  np_mls_say_hello(alice, "bob", 3);
  np_mls_say_hello(alice, "charlie", 7);
  np_mls_say_hello(bob, "alice", 5);
  np_mls_say_hello(charlie, "alice", 5);
  np_mls_say_hello_subject(alice, subject, subject_size);
  np_mls_say_hello_subject(bob, subject, subject_size);
  np_mls_say_hello_subject(charlie, subject, subject_size);
  np_mls_say_hello_subject(alice, leader_subject, leader_subject_size);
  np_mls_say_hello_subject(bob, leader_subject, leader_subject_size);
  np_mls_say_hello_subject(charlie, leader_subject, leader_subject_size);
  sleep(5);
  ////////// ACT I: CREATION ////////////
  mls_bytes group_id = {};
  group_id.data = (uint8_t*)calloc(4, sizeof(uint8_t));
  group_id.size = 4;
  group_id.data[0] = 0;
  group_id.data[1] = 1;
  group_id.data[2] = 2;
  group_id.data[3] = 3;

  np_mls_client_create_group(alice, group_id);
  ////////// ACT II: SUBSCRIBE ///////////

  ////////// ACT III: UNSUBSCRIBE //////

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