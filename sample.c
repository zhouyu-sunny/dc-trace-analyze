#include <stdio.h>
#include "sample.h"

uint8_t sample_record[65536 * 8];
uint32_t sample_event_cnt = 0;
uint32_t sample_flow_cnt = 0;

void record_sample_event(packet_t *p) {
    int i;
    for (i = 0; i < p->event_cnt; i++) {
        if (sample_record[p->event_id[i]] == 0) {
            sample_event_cnt++;
            sample_record[p->event_id[i]] = (uint8_t) p->flow_cnt[i];
            sample_flow_cnt += p->flow_cnt[i];
        } else {
            if (sample_record[p->event_id[i]] < (uint8_t) p->flow_cnt[i]) {
                sample_flow_cnt += p->flow_cnt[i] - sample_record[p->event_id[i]];
                sample_record[p->event_id[i]] = (uint8_t) p->flow_cnt[i];
            }
            printf("sample %u %u \n", sample_event_cnt, sample_flow_cnt);
        }
    }
}