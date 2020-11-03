#pragma once
#include "np_mls_client.h"
#include "stdlib.h"
#include "time.h"
#include "string.h"

np_mls_client* np_mls_create_client(np_context *ac) {
  //TODO:: Get id and keys from context and insert it to the mls_client (replace dummy)
  np_mls_client *new_client = calloc(1, sizeof(*new_client));
  new_client->mls_client = mls_create_client(X25519_CHACHA20POLY1305_SHA256_Ed25519, "dummy");
  new_client->groups = hashtable_create();
  new_client->group_subjects = arraylist_create();
  return new_client;
}

bool np_mls_delete_client(np_mls_client *client) {
  if(client == NULL) return false;
  mls_delete_client(client->mls_client);
  for(int i = 0; i < arraylist_size(client->group_subjects); i++) {
    char *cur_subject = arraylist_get(client->group_subjects, i);
    np_mls_group *group = hashtable_get(client->groups, cur_subject);
    if(group != NULL) {
      np_mls_delete_group(group);
      hashtable_remove(client->groups, cur_subject);
    }
    if(cur_subject != NULL) {
      free(cur_subject);
    }
  }
  arraylist_destroy(client->group_subjects);
  hashtable_destroy(client->groups);
  free(client);
  return true;
}

bool np_mls_create_group(np_mls_client *client, const char *subject, const char *local_identifier) {
  // Check if group already exists
  void *existing_group = hashtable_get(client->groups, subject);
  if(existing_group != NULL) return false;

  // Generate group id 5 values from 0 to 255
  uint8_t random_nums[5];
  for(int i = 0; i < random_nums; i++) {
    random_nums[i] = rand()%(255 + 1);
  }

  // Create new group
  mls_bytes group_id = { .size = 5, .data = random_nums };
  Session *local_session = mls_begin_session(client->mls_client, group_id);
  np_mls_group *new_group = calloc(1, sizeof(*new_group));
  new_group->members = arraylist_create();
  new_group->local_session = local_session;
  new_group->id = group_id;
  np_mls_group_member *local_member = calloc(1, sizeof(*local_member));
  strcpy(local_member->id, local_identifier);
  arraylist_add(new_group->members, local_member);
  return new_group;
}

bool np_mls_delete_group(np_mls_group *group) {
  mls_delete_bytes(group->id);
  mls_delete_session(group->local_session);
  for(int i = 0; i < arraylist_size(group->members); i++) {
    np_mls_group_member *member = arraylist_get(group->members, i);
    if(member != NULL) {
      free(member);
    }
  }
  free(group);
}

bool np_mls_subscribe(np_context *ac, const char* subject, np_receive_callback callback);
bool np_mls_unsubscribe(np_context *ac, const char* subject);
void np_mls_update(np_mls_client *client, np_context *ac, const char *subject);
void np_mls_send(np_mls_client *client, np_context *ac, const char *subject, const unsigned char* message, size_t length);