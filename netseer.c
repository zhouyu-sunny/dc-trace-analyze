#include <stdio.h>
#include "netseer.h"
#include "hash.h"
#include "congestion.h"

#define BULK_NUM 1024 * 1
#define CONTAINER_NUM  512 //(1024 * BULK_NUM / 6)
#define LATENCY_SHIFT 24
typedef struct ns_key {
    uint32_t sip;
    uint32_t dip;
    uint8_t proto;
    uint16_t sport;
    uint16_t dport;
    uint32_t dev_id;
    uint16_t port_id;
} ns_key_t;

#define NS_KEY_SIZE sizeof(ns_key_t)

static uint8_t ns_event_record[65536 * 8];
static uint32_t ns_flow_record[65536 *8][16];
static uint32_t ns_event_cnt = 0;
static uint32_t ns_flow_cnt = 0;
static uint32_t ns_pkt_cnt = 0;
static uint32_t ns_fp_cnt = 0;
static uint32_t ns_fn_cnt = 0;
uint64_t ns_byte_cnt = 0;
uint64_t ns_int_byte_cnt = 0;

typedef struct ns_container_t {
    ns_key_t key;
    uint16_t flow_digest;
    uint16_t pkt_cnt;
    uint16_t ts;
    uint16_t valid;
} ns_container_t;
ns_container_t ns_containers[CONTAINER_NUM];


int fp_cnt = 0;
void record_netseer_event(packet_t *p) {
    int i, j, flag = 0;
    if (p->event_cnt == 0) {
        return;
    }
    for (i = 0; i < p ->event_cnt ; i++) {
        ns_key_t key = {
                .dport = p->flow.dport,
                .sport = p->flow.sport,
                .proto = p->flow.proto,
                .dip = p->flow.dip,
                .sip = p->flow.sip,
                //.dev_id = p->flow_id,
                .port_id = (uint16_t) (p->event_id[i] % 1000)
                //.dev_id = p->dev_id[i],
                //.port_id = p->port_id[i]
        };
        uint32_t flow_idx = hash_crc32(&key, NS_KEY_SIZE, CRC32Q) % CONTAINER_NUM;
        uint16_t flow_digest = (uint16_t) (hash_crc32(&key, NS_KEY_SIZE, CRC32C) % 65536);
        ns_container_t *container = &ns_containers[flow_idx];
        // printf("idx %d %d\n", flow_idx, flow_digest);
        if (container->flow_digest == flow_digest) {
            if (key_compare(&key, &container->key, NS_KEY_SIZE) == 1) {
                ns_fn_cnt ++;
            } else {
                uint16_t ts = (uint16_t)(p->ts.nsec >> LATENCY_SHIFT);

                if (ts > container->ts) {
                    //container->ts = ts;
                    flag = 1;
                    if (ns_event_record[p->event_id[i]] == 0) {
                        ns_event_cnt++;
                        ns_flow_cnt++;
                        ns_event_record[p->event_id[i]]++;
                        ns_flow_record[p->event_id[i]][0] = p->flow_id;
                    } else {
                        for (j = 0; j < ns_event_record[p->event_id[i]]; j++) {
                            if (ns_flow_record[p->event_id[i]][j] == p->flow_id) {
                                break;
                            }
                        }
                        if (j == ns_event_record[p->event_id[i]]) {
                            ns_flow_record[p->event_id[i]][j] = p->flow_id;
                            ns_event_record[p->event_id[i]]++;
                            ns_flow_cnt++;
                        } else {
                           //printf("-- %d\n", fp_cnt++);
                        }
                    }
                }
                container->ts = ts;
            }
            container->pkt_cnt++;
        } else {
            // printf("%d\n", container->pkt_cnt);
            container->pkt_cnt = 1;
            container->key = key;
            container->flow_digest = flow_digest;
            container->ts  =(uint16_t) (p->ts.nsec >> LATENCY_SHIFT);
            flag = 1;
            if (ns_event_record[p->event_id[i]] == 0) {
                ns_event_cnt++;
                ns_flow_cnt++;
                ns_event_record[p->event_id[i]]++;
                ns_flow_record[p->event_id[i]][0] = p->flow_id;
            } else {
                for (j = 0; j < ns_event_record[p->event_id[i]]; j++) {
                    if (ns_flow_record[p->event_id[i]][j] == p->flow_id) {
                        break;
                    }
                }
                if (j == ns_event_record[p->event_id[i]]) {
                    ns_flow_record[p->event_id[i]][j] = p->flow_id;
                    ns_event_record[p->event_id[i]]++;
                    ns_flow_cnt++;
                } else {
//                    printf("%d\n", fp_cnt++);
                }
            }
            /*
            if (ns_event_record[p->event_id[i]] == 0) {
                ns_event_cnt++;
                ns_event_record[p->event_id[i]] = 1;
                ns_flow_cnt ++;
            } else {
                if (ns_event_record[p->event_id[i]] < (uint8_t) p->flow_cnt[i]) {
                    ns_flow_cnt ++;
                    ns_event_record[p->event_id[i]] = (uint8_t) p->flow_cnt[i];
                }
            }
             */
        }
    }
    if (flag == 1) {
        ns_pkt_cnt++;
        ns_byte_cnt += p->packet_length;
        ns_int_byte_cnt += p->int_pkt_len;
    }
}

void netseer_print() {
    printf("NS\t%u\t%u\t%u\t%lu\t%lu\n", ns_pkt_cnt, ns_flow_cnt, ns_event_cnt, ns_byte_cnt, ns_int_byte_cnt
            //get_congestion_flow_num() - ns_flow_cnt,
            //get_congestion_event_num() - ns_event_cnt
            );
}


void record_netseer_flow(packet_t *p) {
    ns_pkt_cnt ++;
    ns_key_t key = {
            .dport = p->flow.dport,
            .sport = p->flow.sport,
            .proto = p->flow.proto,
            .dip = p->flow.dip,
            .sip = p->flow.sip,
    };
    uint32_t flow_idx = hash_crc32(&key, NS_KEY_SIZE, CRC32Q) % CONTAINER_NUM;
    // printf("%d\n", CONTAINER_NUM);
    uint16_t flow_digest = (uint16_t) (hash_crc32(&key, NS_KEY_SIZE, CRC32C) % 65536);
    ns_container_t *container = &ns_containers[flow_idx];
    if (container->flow_digest == flow_digest) {
        if (key_compare(&key, &container->key, NS_KEY_SIZE) == 1) {
            ns_fn_cnt ++;
        }
        container->pkt_cnt++;
    } else {
        if (container->valid == 0) {
            ns_flow_cnt ++;
        } else {
            ns_fp_cnt ++;
        }
        container->pkt_cnt = 0;
        container->key = key;
        container->flow_digest = flow_digest;
        container->valid = 1;
    }
}


void netseer_flow_print() {
    printf("%u\t%u\t%u\t%u\t%lu\t%lu\n", ns_pkt_cnt, ns_flow_cnt, ns_fp_cnt, ns_fn_cnt, ns_byte_cnt, ns_int_byte_cnt);
}

uint32_t get_ns_pkt_cnt() {
    return ns_pkt_cnt;
}
uint32_t get_ns_int_byte_cnt() {
    return ns_int_byte_cnt;
}