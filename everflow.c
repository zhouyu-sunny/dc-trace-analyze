#include <stdio.h>
#include <stdlib.h>
#include "everflow.h"
#include "congestion.h"

static uint8_t ef_event_record[65536 * 8];
static uint8_t ef_flow_record[65536 * 8];
static uint32_t ef_event_cnt = 0;
static uint32_t ef_flow_cnt = 0;
static uint32_t ef_pkt_cnt = 0;

uint64_t ef_byte_cnt = 0;
uint64_t ef_int_byte_cnt = 0;

typedef struct ef_key_t {
    uint32_t sip;
    uint32_t dip;
    uint8_t proto;
    uint16_t sport;
    uint16_t dport;
} ef_key_t;

typedef struct ef_container_t {
    ef_key_t key;
    int current_id;
    uint32_t flow_id;
} ef_container_t;

ef_container_t ns_containers[1024];
int congestion_container_cnt = 0;
uint32_t flow_id;

static int cmp_key(ef_key_t * key, flow_t * flow) {
    if (key->dport != flow->dport) {
        return 1;
    }
    if (key->sport != flow->sport) {
        return 1;
    }
    if (key->sip != flow->sip) {
        return 1;
    }
    if (key->dip != flow->dip) {
        return 1;
    }
    return 0;
}



void record_everflow_event(packet_t *p) {
    int i;
    ef_container_t * container = NULL;
    for (i = 0; i < congestion_container_cnt; i++) {
        if (cmp_key(&ns_containers[i].key, &p->flow) == 0) {
            container = &ns_containers[i];
            break;
        }
    }
    if (container == NULL) {
        container = &ns_containers[congestion_container_cnt++];
        container->key.dport = p->flow.dport;
        container->key.sport = p->flow.sport;
        container->key.proto = p->flow.proto;
        container->key.sip = p->flow.sip;
        container->key.dip = p->flow.dip;
        container->flow_id = flow_id++;
        container->current_id = 0;
    }
    if (congestion_container_cnt > 1000) {
        exit(1);
    }

    if (p->int_valid == 1) {
        if (is_signal_pkt(p)) {
            // printf("%d %d\n", p->tcp_hdr_len, p->packet_length);
            ef_pkt_cnt ++;
            ef_byte_cnt += p->packet_length;
            ef_int_byte_cnt += p->int_pkt_len;
            container->current_id ++;
            container->flow_id = flow_id++;
            for (i = 0; i < p->event_cnt; i++) {
                if (ef_event_record[p->event_id[i]] == 0) {
                    ef_event_cnt++;
                    ef_event_record[p->event_id[i]] = 1;
                }
            }
            if (p->event_cnt > 0) {
                if (ef_flow_record[container->flow_id] == 0) {
                    ef_flow_cnt += p->event_cnt;
                    ef_flow_record[container->flow_id] = 1;
                }
            }
        }
    }
    p->flow.sport += container->current_id;
    p->flow.dport += container->current_id;
    // p->flow_id = container->flow_id;
}

void everflow_print() {
    printf("EF\t%u\t%u\t%u\t%lu\t%lu\n", ef_pkt_cnt, ef_flow_cnt, ef_event_cnt,ef_byte_cnt, ef_int_byte_cnt);
}

int get_flow_num() {
    return ef_pkt_cnt;
}