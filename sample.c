#include <stdio.h>
#include "sample.h"

uint8_t sample_record[65536 * 8];
uint32_t sample_event_cnt = 0;
uint32_t sample_flow_cnt = 0;
uint32_t sample_pkt_cnt = 0;



int record_sample_event(packet_t *p) {
    int i;
    sample_pkt_cnt ++;

    for (i = 0; i < p->event_cnt; i++) {
        if (p->event_id[i] > 68838 *8 - 8) {
            return -1;
        }
        if (sample_record[p->event_id[i]] == 0) {
            sample_event_cnt++;
            sample_record[p->event_id[i]] = (uint8_t) p->flow_cnt[i];
            sample_flow_cnt += p->flow_cnt[i];
        } else {
            if (sample_record[p->event_id[i]] < (uint8_t) p->flow_cnt[i]) {
                sample_flow_cnt += p->flow_cnt[i] - sample_record[p->event_id[i]];
                sample_record[p->event_id[i]] = (uint8_t) p->flow_cnt[i];

            }
        }
    }
    return 0;
}


void sample_print() {
    printf("Sample: pkt %u, flow %u, event %u\n ", sample_pkt_cnt, sample_flow_cnt, sample_event_cnt);
}