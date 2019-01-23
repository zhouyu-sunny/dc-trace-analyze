#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include "congestion.h"
#include "hash.h"

uint32_t congestion_event_count = 0;
uint32_t congestion_flow_count = 0;
static uint32_t congestion_threshold = 20000;
static uint32_t congestion_delay = 3;
static uint32_t flow_id = 0;
static uint32_t congestion_pkt_count = 0;

static uint64_t congestion_byte_count = 0;
static uint64_t congestion_int_byte_count = 0;
typedef struct congestion_key_t {
    uint32_t sip;
    uint32_t dip;
    uint8_t proto;
    uint16_t sport;
    uint16_t dport;
    uint32_t flow_id;
} congestion_key_t;

typedef struct congestion_event {
    uint32_t dev_id;
    uint16_t port_id;
    uint32_t event_id;
    uint32_t flow_count;
    uint32_t pkt_count;
    uint32_t valid;
    uint16_t queue_len;
    congestion_key_t flows[128];
    uint32_t flow_pkt_count[128];
    uint32_t flow_id[128];
    ts_t start_ts;
    ts_t end_ts;
} congestion_event_t;

congestion_event_t event_records [16][156];


typedef struct congestion_container_t {
    flow_t key;
    uint32_t flow_id;
} congestion_container_t;

static congestion_container_t ns_containers[1024];
static int congestion_container_cnt = 0;

int is_signal_pkt(packet_t * p) {
    /*
    int len = 34;
    len += p->tcp_hdr_len;
    if (p->int_valid) {
        len += 28;
        len += p->probe_hdr->hop_count * 32;
    }
     */

    if ((p->tcp_flag & 0x8) != 0) {
        return 1;
    }
    return 0;
    //return (p->packet_length - len) == 8;
}

static inline int cmp_congestion_key(const congestion_key_t * arg1, const congestion_key_t * arg2) {
    if (arg1->dport  != arg2->dport) {
        return 1;
    }
    if (arg1->sport  != arg2->sport) {
        return 1;
    }
    if (arg1->dip  != arg2->dip) {
        return 1;
    }
    if (arg1->sip  != arg2->sip) {
        return 1;
    }

    if (arg1->flow_id != arg2->flow_id) {
        return 1;
    }
    return 0;
}


congestion_event_t * get_event_record(uint32_t dev_id, uint32_t port_id) {
    return &event_records[dev_id][port_id];
}

static congestion_event_t * do_record_congestion_event(congestion_key_t* flow, const struct int_md_hdr * md, ts_t* ts) {
    uint32_t dev_id = SWAP32(md->switch_id);
    uint32_t port_id = md->egress_id;
    uint32_t latency = (SWAP32(md->tx_ts_nsec)) - (SWAP32(md->rx_ts_nsec));
    // printf("%d\n", latency);
    congestion_event_t * event = get_event_record(dev_id, port_id);
    int i;

    if (event->valid > 0) {
        event->queue_len = event->queue_len > SWAP16(md->egress_utilization) ? event->queue_len : SWAP16(md->egress_utilization);
        for (i = 0; i < event->flow_count; i ++) {
            if (cmp_congestion_key(&event->flows[i], flow) == 0) {
                break;
            }
        }
        if (i == event->flow_count) {
            event->flow_count++;
            event->flows[i] = *flow;
            event->flow_pkt_count[i] = 1;
        }
        event->pkt_count ++;
        if (latency > congestion_threshold) {
            event->valid = congestion_delay;
        } else {
            if (event->valid == 1) {
#if ENABLE_PRINT_EVENT
                uint32_t duration = ts->nsec > event->start_ts.nsec ? ts->nsec - event->start_ts.nsec :  event->start_ts.nsec - ts->nsec;
                printf("%u %u %u %u %u\n", dev_id, port_id, event->flow_count, event->pkt_count, duration);
#endif
                congestion_flow_count += event->flow_count;
                // memset(event, 0 , sizeof(congestion_event_t));
                event->valid = 0;
            } else {
                event->valid--;
            }
        }
        return event;
    } else {
        if (latency > congestion_threshold) {
            event->valid = congestion_delay;
            event->dev_id =dev_id;
            event->port_id = (uint16_t)port_id;
            event->flows[0] = *flow;
            event->flow_count = 1;
            event->start_ts.nsec = SWAP32(md->rx_ts_nsec);
            event->start_ts.sec = SWAP32(md->rx_ts_sec);
            event->pkt_count ++;
            event->flow_pkt_count[0] ++;
            congestion_event_count++;
            event->event_id = congestion_event_count;
            event->queue_len = SWAP16(md->egress_utilization);
            return event;
        }
    }
    return NULL;
}

void record_congestion_event(packet_t *p) {
    int i;
    congestion_container_t * container = NULL;
    for (i = 0; i < congestion_container_cnt; i++) {
        if (key_compare(&ns_containers[i].key, &p->flow, sizeof(flow_t)) == 0) {
            container = &ns_containers[i];
            break;
        }
    }
    if (container == NULL) {
        container = &ns_containers[congestion_container_cnt++];
        container->key = p->flow;
        container->flow_id = flow_id++;
    }
    if (congestion_container_cnt > 1000) {
        printf("132\n");
        exit(1);
    }

    if (is_signal_pkt(p)) {
        container->flow_id = flow_id++;
    }
    p->flow_id = container->flow_id;

    if (p->int_valid) {
        int flag = 0;
        for (i = 0; i < p->probe_hdr->hop_count; i++) {
            ts_t ts = {
                    .sec = SWAP32(p->md_hdrs[i]->rx_ts_sec),
                    .nsec = SWAP32(p->md_hdrs[i]->rx_ts_nsec),
            };

            congestion_key_t flow = {
                    .sport = p->flow.sport,
                    .dport = p->flow.dport,
                    .proto = p->flow.proto,
                    .sip = p->flow.sip,
                    .dip = p->flow.dip,
                    .flow_id = p->flow_id
            };

            congestion_event_t * event = do_record_congestion_event(&flow, p->md_hdrs[i], &ts);
            if (event != NULL) {
                p->event_id[p->event_cnt] = event->event_id;
                p->flow_cnt[p->event_cnt] = event->flow_count;
                p->dev_id[p->event_cnt] = event->dev_id;
                p->port_id[p->event_cnt++] = event->port_id;
                flag = 1;
            }
        }
        if (flag) {
            congestion_pkt_count ++;
            congestion_byte_count += p->packet_length;
            congestion_int_byte_count += p->int_pkt_len;
        }
    }
}

void congestion_print() {
    printf("T\t%u\t%u\t%u\t%lu\t%lu\n", congestion_pkt_count, congestion_flow_count, congestion_event_count, congestion_byte_count, congestion_int_byte_count);
}

int get_congestion_pkt_num() {
    return congestion_pkt_count;
}


int get_congestion_flow_num() {
    return congestion_flow_count;
}

int get_congestion_event_num() {
    return congestion_event_count;
}

uint32_t get_congestion_pkt_cnt() {
    return congestion_pkt_count;
}

uint32_t get_congestion_int_byte_cnt() {
    return congestion_int_byte_count;
}