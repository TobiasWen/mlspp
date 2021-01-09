#include "libbenchmark.h"
#include "neuropil.h"
#include <assert.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <np_mls.h>
#include <unistd.h>

struct benchmark_thread_args {
    np_context **nodes;
    np_mls_benchmark *benchmark;
};

unsigned char *gen_rdm_bytestream(size_t num_bytes);

void send_thread(struct benchmark_thread_args *args);

void run_benchmark(np_mls_benchmark *benchmark);

bool
authenticate(np_context *, struct np_token *);

bool
authorize(np_context *, struct np_token *);

bool
receive(np_context *, struct np_message *);

int
main() {
    np_mls_benchmark *benchmark =
            np_mls_create_benchmark("MyBenchmark",
                                    "ba4a8c4c-3f91-11eb-b378-0242ac130002",
                                    9,
                                    500000,
                                    5,
                                    NP_MLS_BENCHMARK_MESH_TOPOLOGY,
                                    NP_MLS_ENCRYPTION_X25519_CHACHA20POLY1305_SHA256_Ed25519,
                                    true);

    /*np_mls_clock* my_clock = np_mls_clock_start();
    for (int i = 0; i < 2100000000; i++) {
      int a = 0;
      a += i;
      a *= a;
    }
    np_mls_clock_stop(my_clock);
    printf("My UUID: %s\n", generateUUID());
    np_mls_benchmark_result *result = np_mls_create_benchmark_results("f3a6dd78-919d-486b-84c8-9dcd87ad5c76", true);
    np_mls_add_double_value_to_result("TestKey1", my_clock->wall_time_used, "s", result);
    np_mls_add_double_value_to_result("TestKey2", my_clock->cpu_time_used, "s", result);
    printf("--------------------------------------\n");
    printf("Benchmark Results:\n");
    printf("--------------------------------------\n");
    printf("Wall clock time spent: %.9fs\n", *np_mls_get_double_value_from_result("TestKey1", result));
    printf("       CPU time spent: %.9fs\n", *np_mls_get_double_value_from_result("TestKey2", result));
    printf("--------------------------------------\n");
    np_mls_clock_destroy(my_clock);
    np_mls_destroy_benchmark(benchmark);*/
    run_benchmark(benchmark);
    return 0;
}

void run_benchmark(np_mls_benchmark *benchmark) {
    printf("Running benchmark \"%s\"(%s) with %d clients...\n", benchmark->name, benchmark->id,
           benchmark->num_clients_per_node);
    // basic config
    int port = 4000;
    int controller_port = port;
    int num_threads_per_node = 3;
    // start controller
    struct np_settings ctrl_cfg;
    np_default_settings(&ctrl_cfg);
    np_context *ctrL_ac = np_new_context(&ctrl_cfg);
    assert(np_ok == np_listen(ctrL_ac, "udp4", "localhost", port));
    np_run(ctrL_ac, 0);
    // start nodes
    np_context **nodes = calloc(benchmark->num_clients_per_node, sizeof(np_context *));
    for (int i = 0; i < benchmark->num_clients_per_node; i++) {
        //sleep(1);
        port += 1;
        struct np_settings cfg;
        struct np_settings *settings = np_default_settings(&cfg);
        settings->n_threads = num_threads_per_node;
        nodes[i] = np_new_context(settings);
        char *join_method = NULL;
        if (benchmark->topology == NP_MLS_BENCHMARK_MESH_TOPOLOGY) {
            join_method = "udp4";
        } else {
            join_method = "pas4";
        }
        // join network
        assert(np_ok == np_listen(nodes[i], "udp4", "localhost", port));
        char *wildcard = "*:";
        char *address = ":localhost:";
        char port_str[12];
        sprintf(port_str, "%d", controller_port);
        char *wildcard_join_method = str_concat(wildcard, join_method);
        char *address_port = str_concat(address, port_str);
        char *connection_string = str_concat(wildcard_join_method, address_port);
        assert(np_ok == np_join(nodes[i], connection_string));
        assert(np_ok == np_set_authorize_cb(nodes[i], authorize));

        // get local fingerprint
        unsigned char local_fingerprint[NP_FINGERPRINT_BYTES];
        np_node_fingerprint(nodes[i], local_fingerprint);
        char *local_fingerprint_str = calloc(1, 65); //TODO FREE
        np_id_str(local_fingerprint_str, local_fingerprint);

        benchmark_userdata *userdata = calloc(1, sizeof(benchmark_userdata)); //TODO FREE
        userdata->benchmark = benchmark;
        userdata->result = np_mls_create_benchmark_results(local_fingerprint_str, benchmark->has_sender && i == 0);
        np_set_userdata(nodes[i], userdata);
        // set mls encryption
        struct np_mx_properties props = np_get_mx_properties(nodes[i], "mysubject");
        if (benchmark->benchmark_algorithm != NP_MLS_JSON_ENCRYPTION) {
            //props.intent_ttl = 10.0;
            props.encryption_algorithm = MLS_ENCRYPTION;
            props.message_ttl = 5;
            props.mls_is_creator = benchmark->has_sender && i == 0;
        }
        np_set_mx_properties(nodes[i], "mysubject", props);
        assert(np_ok == np_add_receive_cb(nodes[i], "mysubject", receive));

        free(wildcard_join_method);
        free(address_port);
        free(connection_string);
    }
    // wait 60s until everyone is joined into the group and ready for benchmark
    // [ ] measure start timestamp
    // [ ] measure end timestamp after every message is sent or received
    bool isinitialized = false;
    while (!benchmark->finished) {
        // run event loop
        // controller
        if (np_ok != np_run(ctrL_ac, 0)) {
            printf("Error in np_run on ctrl node\n");
        }
        // nodes
        int is_ready_count = 0;
        int is_initialized_count = 0;
        for (int i = 0; i < benchmark->num_clients_per_node; i++) {
            np_mls_client *client = np_mls_get_client_from_module(nodes[i]);
            if (np_mls_is_everyone_authorized(client, "mysubject", benchmark->num_clients_per_node)) {
                is_ready_count++;
            }
            for (int l = 0; l < arraylist_size(client->group_subjects); l++) {
                int groupcount = 0;
                char *subject = arraylist_get(client->group_subjects, l);
                if (subject) {
                    np_mls_group *group = hashtable_get(client->groups, subject);
                    if (group && group->isInitialized) {
                        groupcount++;
                    }
                }
                if (groupcount == arraylist_size(client->group_subjects)) {
                    is_initialized_count++;
                }
            }
            /*if (i == 0) {
                np_send(nodes[0], "mysubject", "Hallo Welt!", 12);
                printf("Sent!\n");
            }*/
            if (np_ok != np_run(nodes[i], 0)) {
                printf("Error in np_run on node nr:%d\n", i);
            }
        }
        if (is_ready_count == benchmark->num_clients_per_node && !benchmark->ready) {
            printf("Benchmark is ready to go! Fire!\n");
            benchmark->ready = true;
        } else if (benchmark->ready && is_initialized_count == benchmark->num_clients_per_node && !benchmark->isRunning) {
            benchmark->isRunning = true;
            struct benchmark_thread_args args;
            args.benchmark = benchmark;
            args.nodes = nodes;
            // Create & start user input thread
            pthread_t input_thread;
            pthread_create(&input_thread, NULL, send_thread, &args);
        } else if(benchmark->finished) {
            printf("Finished Benchmark Successfull!\n");
            break;
        }
    }
    printf("Benchmark \"%s\"(%s) finished!\n", benchmark->name, benchmark->id);
}

void send_thread(struct benchmark_thread_args *args) {
    // generate bytes
    unsigned char *bytes = gen_rdm_bytestream(args->benchmark->packet_byte_size);
    printf("Benchmarking...\n");
    // TODO:
    // Add total bytes sent/receivedr
    // Sender should start Benchmark when sending first packet and stop when last packet was sent
    // Receiver should start Benchmark on receiving the first message and stop when received the last message
    np_mls_clock *my_clock = np_mls_clock_start();
    // benchmark routine between here
    for(int i = 0; i < args->benchmark->message_send_num; i++) {
        np_send(args->nodes[0], "mysubject", bytes, args->benchmark->packet_byte_size);
    }
    // ------------------------------
    np_mls_clock_stop(my_clock);
    np_mls_benchmark_result *result = np_mls_create_benchmark_results(generateUUID(), false);
    np_mls_add_double_value_to_result(NP_BENCHMARK_TIME_WALL, my_clock->wall_time_used, "s", result);
    np_mls_add_double_value_to_result(NP_BENCHMARK_TIME_CPU, my_clock->cpu_time_used, "s", result);
}

unsigned char *gen_rdm_bytestream(size_t num_bytes) {
    unsigned char *stream = malloc(num_bytes);
    size_t i;
    srand((unsigned int) time (NULL));
    for (i = 0; i < num_bytes; i++) {
        stream[i] = rand();
    }

    return stream;
}

bool authenticate(np_context *ac, struct np_token *id) {
    return true;
}

bool
authorize(np_context *ac, struct np_token *id) {
    unsigned char local_fingerprint[NP_FINGERPRINT_BYTES];
    np_node_fingerprint(ac, local_fingerprint);
    char *local_fingerprint_str = calloc(1, 65);
    np_id_str(local_fingerprint_str, local_fingerprint);
    printf("[%s] Authorizing on subject %s issuer:%s\n", local_fingerprint_str, id->subject, id->issuer);
    free(local_fingerprint_str);
    return true;
}

bool
receive(np_context *ac, struct np_message *message) {
    unsigned char local_fingerprint[NP_FINGERPRINT_BYTES];
    np_node_fingerprint(ac, local_fingerprint);
    char *local_fingerprint_str = calloc(1, 65);
    np_id_str(local_fingerprint_str, local_fingerprint);
    printf("[%s] received: %.*s\n", local_fingerprint_str, (int) message->data_length, message->data);
    free(local_fingerprint_str);
    return true;
}