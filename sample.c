#include <stdio.h>
#include "sample.h"

uint32_t sample10_flow_record[65536 * 8][16];
uint32_t sample10_event_record[65536 * 8];
uint32_t sample10_event_cnt = 0;
uint32_t sample10_flow_cnt = 0;
uint32_t sample10_pkt_cnt = 0;
uint64_t sample10_byte_cnt = 0;
uint64_t sample10_int_byte_cnt = 0;


int record_sample10_event(packet_t *p) {
    int i, j;
    sample10_pkt_cnt ++;
    sample10_byte_cnt += p->packet_length;
    sample10_int_byte_cnt += p->int_pkt_len;

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
uint64_t sample100_byte_cnt = 0;
uint64_t sample100_int_byte_cnt = 0;


int record_sample100_event(packet_t *p) {
    int i, j;
    sample100_pkt_cnt ++;
    sample100_byte_cnt += p->packet_length;
    sample100_int_byte_cnt += p->int_pkt_len;
    for (i = 0; i < p->event_cnt; i++) {
        if (p->event_id[i] > 65536 *8 - 2) {
            return -1;
        }
        if (sample100_event_record[p->event_id[i]] == 0) {
            sample100_event_cnt++;
            sample100_flow_cnt ++;
            sample100_event_record[p->event_id[i]]++;
            sample100_flow_record[p->event_id[i]][0] = p->flow_id;
        } else {
            for (j = 0; j < sample100_event_record[p->event_id[i]]; j++) {
                if (sample100_flow_record[p->event_id[i]][j] == p->flow_id) {
                    break;
                }
            }
            if (j == sample100_event_record[p->event_id[i]]) {
                sample100_flow_record[p->event_id[i]][j] = p->flow_id;
                sample100_event_record[p->event_id[i]]++;
                sample100_flow_cnt++;
            }
        }
    }

    return 0;
}

uint8_t sample1000_event_record[65536 * 8];
uint32_t sample1000_flow_record[65536 * 8][16];
uint32_t sample1000_event_cnt = 0;
uint32_t sample1000_flow_cnt = 0;
uint32_t sample1000_pkt_cnt = 0;
uint64_t sample1000_byte_cnt = 0;
uint64_t sample1000_int_byte_cnt = 0;

int record_sample1000_event(packet_t *p) {
    int i, j;
    sample1000_pkt_cnt ++;
    sample1000_int_byte_cnt+= p->int_pkt_len;
    sample1000_byte_cnt += p->packet_length;

    for (i = 0; i < p->event_cnt; i++) {
        if (p->event_id[i] > 65536 *8 - 2) {
            return -1;
        }
        if (sample1000_event_record[p->event_id[i]] == 0) {
            sample1000_event_cnt++;
            sample1000_flow_cnt ++;
            sample1000_event_record[p->event_id[i]]++;
            sample1000_flow_record[p->event_id[i]][0] = p->flow_id;
        } else {
            for (j = 0; j < sample1000_event_record[p->event_id[i]]; j++) {
                if (sample1000_flow_record[p->event_id[i]][j] == p->flow_id) {
                    break;
                }
            }
            if (j == sample1000_event_record[p->event_id[i]]) {
                sample1000_flow_record[p->event_id[i]][j] = p->flow_id;
                sample1000_event_record[p->event_id[i]]++;
                sample1000_flow_cnt++;
            }
        }
    }

    return 0;
}

void sample_print() {
    printf("S10\t%u\t%u\t%u\t%lu\t%lu\n", sample10_pkt_cnt, sample10_flow_cnt, sample10_event_cnt, sample10_byte_cnt, sample10_int_byte_cnt);
    printf("S100\t%u\t%u\t%u\t%lu\t%lu\n", sample100_pkt_cnt, sample100_flow_cnt, sample100_event_cnt, sample100_byte_cnt, sample100_int_byte_cnt);
    printf("S1000\t%u\t%u\t%u\t%lu\t%lu\n", sample1000_pkt_cnt, sample1000_flow_cnt, sample1000_event_cnt, sample1000_byte_cnt, sample1000_int_byte_cnt);
}