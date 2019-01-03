#include <stdio.h>
#include "sample.h"

uint32_t sample10_flow_record[65536 * 8][16];
uint32_t sample10_event_record[65536 * 8];
uint32_t sample10_event_cnt = 0;
uint32_t sample10_flow_cnt = 0;
uint32_t sample10_pkt_cnt = 0;



int record_sample10_event(packet_t *p) {
    int i, j;
    sample10_pkt_cnt ++;

    for (i = 0; i < p->event_cnt; i++) {
        if (p->event_id[i] > 68838 *8 - 8) {
            return -1;
        }

        if (sample10_event_record[p->event_id[i]] == 0) {
            sample10_event_cnt++;
            sample10_flow_cnt ++;
            sample10_event_record[p->event_id[i]]++;
            sample10_flow_record[p->event_id[i]][0] = p->flow_id;
        }

        for (j = 0; j < sample10_event_record[p->event_id[i]]; j++) {
            if (sample10_flow_record[p->event_id[i]][j] == p->flow_id) {
                break;
            }
        }

        if (j == sample10_event_record[p->event_id[i]]) {
            sample10_flow_record[p->event_id[i]][j] = p->flow_id;
            sample10_event_record[p->event_id[i]]++;
            sample10_flow_cnt ++;
        }
    }
    return 0;
}

uint8_t sample100_event_record[65536 * 8];
uint32_t sample100_flow_record[65536 * 8][16];
uint32_t sample100_event_cnt = 0;
uint32_t sample100_flow_cnt = 0;
uint32_t sample100_pkt_cnt = 0;

int record_sample100_event(packet_t *p) {
    int i, j;
    sample100_pkt_cnt ++;
    for (i = 0; i < p->event_cnt; i++) {
        if (p->event_id[i] > 68838 *8 - 8) {
            return -1;
        }

        if (sample100_event_record[p->event_id[i]] == 0) {
            sample100_event_cnt++;
            sample100_flow_cnt ++;
            sample100_event_record[p->event_id[i]]++;
            sample100_flow_record[p->event_id[i]][0] = p->flow_id;
        }

        for (j = 0; j < sample100_event_record[p->event_id[i]]; j++) {
            if (sample100_flow_record[p->event_id[i]][j] == p->flow_id) {
                break;
            }
        }

        if (j == sample100_event_record[p->event_id[i]]) {
            sample100_flow_record[p->event_id[i]][j] = p->flow_id;
            sample100_event_record[p->event_id[i]]++;
            sample100_flow_cnt ++;
        }
    }

    return 0;
}

void sample_print() {
    printf("S10\t%u\t%u\t%u\n", sample10_pkt_cnt, sample10_flow_cnt, sample10_event_cnt);
    printf("S100\t%u\t%u\t%u\n", sample100_pkt_cnt, sample100_flow_cnt, sample100_event_cnt);
}