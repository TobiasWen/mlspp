#include "libbenchmark.h"
#include "neuropil.h"
#include <assert.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <neuropil_attributes.h>
#include <np_mls.h>

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
                                    3,
                                    50,
                                    5,
                                    NP_MLS_BENCHMARK_MESH_TOPOLOGY,
                                    NP_MLS_ENCRYPTION_X25519_CHACHA20POLY1305_SHA256_Ed25519,
                                    true,
                                    "http://localhost:3333");

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
    /*struct np_settings ctrl_cfg;
    np_default_settings(&ctrl_cfg);
    np_context *ctrL_ac = np_new_context(&ctrl_cfg);
    assert(np_ok == np_listen(ctrL_ac, "udp4", "localhost", port));
    np_run(ctrL_ac, 0);*/
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
            /*if (np_data_ok == np_set_mxp_attr_bin(
                    nodes[i], "mysubject", NP_ATTR_INTENT, NP_MLS_IS_CREATOR, &local_fingerprint,
                    NP_FINGERPRINT_BYTES)) {
                printf("Set creator flag for userspace!\n");
            } else {
                printf("Couldn't set creator flag for userspace!\n");
            }*/

            props.intent_ttl = 10.0;
            props.encryption_algorithm = MLS_ENCRYPTION;
            bool is_creator = benchmark->has_sender && i == 0;
            unsigned char creator_char = (unsigned char) (is_creator ? '1' : '0');
            props.mls_is_creator = is_creator;



            printf("[%s] Added creator flag to token for subject 'mysubject'.\n", local_fingerprint_str);

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
    while (!benchmark->finished) {
        // run event loop
        uint16_t tmp;
        // controller
        /*if (np_ok != (tmp = np_run(ctrL_ac, 0))) {
          printf("Error in np_run on ctrl node\n");
        }*/
        // nodes
        for (int i = 0; i < benchmark->num_clients_per_node; i++) {
            if (i == 0) {
                sleep(3);
                np_send(nodes[0], "mysubject", "Hallo Welt!", 12);
                printf("Sent!\n");
            }
            if (np_ok != np_run(nodes[i], 0)) {
                printf("Error in np_run on node nr:%d\n", i);
            }
        }
    }
    printf("Benchmark \"%s\"(%s) finished!\n", benchmark->name, benchmark->id);
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