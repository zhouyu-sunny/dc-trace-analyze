#include <stdio.h>
#include "netseer.h"
#include "hash.h"

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

static uint8_t ns_record[65536 * 8];
static uint32_t ns_event_cnt = 0;
static uint32_t ns_flow_cnt = 0;
static uint32_t ns_pkt_cnt = 0;
// static uint32_t fp_cnt = 0;
static uint32_t ns_fn_cnt = 0;

typedef struct ns_container_t {
    ns_key_t key;
    uint16_t flow_digest;
    uint16_t pkt_cnt;
    uint16_t ts;
} ns_container_t;

#define BULK_NUM 16
#define CONTAINER_NUM 90112 * BULK_NUM

ns_container_t containers[CONTAINER_NUM];

void record_netseer_event(packet_t *p) {
    int i, flag = 0;
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
                .dev_id = p->dev_id[i],
                .port_id = p->port_id[i]
        };
        uint32_t flow_idx = hash_crc32(&key, NS_KEY_SIZE, CRC32Q) % CONTAINER_NUM;
        uint16_t flow_digest = (uint16_t) (hash_crc32(&key, NS_KEY_SIZE, CRC32C) % 65536);
        ns_container_t *container = &containers[flow_idx];
        // printf("idx %d %d\n", flow_idx, flow_digest);
        if (container->flow_digest == flow_digest) {
            if (key_compare(&key, &container->key, NS_KEY_SIZE) == 1) {
                ns_fn_cnt ++;
            } else {
                printf("1\n");
            }
            container->pkt_cnt++;
        } else {
            container->pkt_cnt = 0;
            container->key = key;
            container->flow_digest = flow_digest;
            container->ts = 
            flag = 1;
            for (i = 0; i < p->event_cnt; i++) {
                if (ns_record[p->event_id[i]] == 0) {
                    ns_event_cnt++;
                    ns_record[p->event_id[i]] = 1;
                    ns_flow_cnt ++;
                } else {
                    if (ns_record[p->event_id[i]] < (uint8_t) p->flow_cnt[i]) {
                        ns_flow_cnt ++;
                        ns_record[p->event_id[i]] = (uint8_t) p->flow_cnt[i];
                    }
                }
            }
        }
    }
    if (flag == 1) {
        ns_pkt_cnt++;
    }
}

void netseer_print() {
    printf("NS\t%u\t%u\t%u\t%u\n", ns_pkt_cnt, ns_flow_cnt, ns_event_cnt, ns_fn_cnt);
}