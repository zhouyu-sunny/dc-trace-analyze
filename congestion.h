//
// Created by ZhouYu on 2019/1/2.
//

#ifndef ANALYZE_CONGESTION_H
#define ANALYZE_CONGESTION_H

#include "packet.h"

#define ENABLE_PRINT_EVENT 0

void record_congestion_event(packet_t *p);

void congestion_print(void);

int get_congestion_event_num(void);

int get_congestion_flow_num(void);

int is_signal_pkt(packet_t * p);

uint32_t get_congestion_int_byte_cnt(void);

uint32_t get_congestion_pkt_cnt();

#endif //ANALYZE_CONGESTION_H
