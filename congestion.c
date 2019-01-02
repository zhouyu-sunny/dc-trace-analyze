#include <memory.h>
#include <stdio.h>
#include "congestion.h"

uint32_t congestion_event_count = 0;
uint32_t congestion_flow_count = 0;

static uint32_t congestion_threshold = 20000;
static uint32_t congestion_delay = 3;
static uint32_t congestion_pkt_count = 0;
static uint32_t pkt_count;

typedef struct congestion_event {
    uint32_t event_id;
    uint32_t flow_count;
    uint32_t pkt_count;
    uint32_t valid;
    uint16_t queue_len;
    flow_t flow[128];
    uint32_t flow_pkt_count[128];
    ts_t start_ts;
    ts_t end_ts;
} congestion_event_t;

congestion_event_t event_records [16][156];

congestion_event_t * get_event_record(uint32_t dev_id, uint32_t port_id) {
    return &event_records[dev_id][port_id];
}
static congestion_event_t * do_record_congestion_event(const flow_t* flow, const struct int_md_hdr * md, ts_t* ts) {
    uint32_t dev_id = SWAP32(md->switch_id);
    uint32_t port_id = md->egress_id;
    uint32_t latency = (SWAP32(md->tx_ts_nsec)) - (SWAP32(md->rx_ts_nsec));
    // printf("%d\n", latency);
    congestion_event_t * event = get_event_record(dev_id, port_id);
    int i;
    pkt_count ++;
    congestion_pkt_count++;
    if (event->valid > 0) {
        event->queue_len = event->queue_len > SWAP16(md->egress_utilization) ? event->queue_len : SWAP16(md->egress_utilization);
        for (i = 0; i < event->flow_count; i ++) {
            if (cmp_flow(&event->flow[i], flow) == 0) {
                break;
            }
        }
        if (i == event->flow_count) {
            event->flow_count++;
            event->flow[i] = *flow;
            event->flow_pkt_count[i] = 1;

        }
        event->pkt_count ++;
        if (latency > congestion_threshold) {
            event->valid = congestion_delay;
        } else {
            if (event->valid == 1) {
                uint32_t duration = ts->nsec > event->start_ts.nsec ? ts->nsec - event->start_ts.nsec :  event->start_ts.nsec - ts->nsec;
                if (event->pkt_count > 10) {
                    printf("%u %u %u %u\n", pkt_count, congestion_pkt_count, congestion_event_count, congestion_flow_count);
                }
                congestion_flow_count += event->flow_count;
                memset(event, 0 , sizeof(congestion_event_t));
            } else {
                event->valid--;
            }
        }
        return event;
    } else {
        if (latency > congestion_threshold) {
            event->valid = congestion_delay;
            event->flow[0] = *flow;
            event->flow_count = 1;
            event->start_ts.nsec = SWAP32(md->rx_ts_nsec);
            event->start_ts.sec = SWAP32(md->rx_ts_sec);
            event->pkt_count ++;
            event->flow_pkt_count[0] ++;
            congestion_event_count++;
            event->event_id = congestion_event_count;
            event->queue_len = SWAP16(md->egress_utilization);
            return event;
        } else {
            congestion_pkt_count--;
        }
    }
    return NULL;
}

void record_congestion_event(packet_t *p) {
    if (p->int_valid) {
        int i;
        for (i = 0; i < p->probe_hdr->hop_count; i++) {
            ts_t ts = {
                    .sec = SWAP32(p->md_hdrs[i]->rx_ts_sec),
                    .nsec = SWAP32(p->md_hdrs[i]->rx_ts_nsec),
            };
            congestion_event_t * event = do_record_congestion_event(&p->flow, p->md_hdrs[i], &ts);
            if (event != NULL) {
                p->event_id[p->event_cnt] = event->event_id;
                p->flow_cnt[p->event_cnt++] = event->flow_count;
            }
        }
    }
}

