//
// Created by ZhouYu on 2019/1/3.
//

#ifndef ANALYZE_EVERFLOW_H
#define ANALYZE_EVERFLOW_H

#include "packet.h"



void record_everflow_event(packet_t *p);

void everflow_print();

int get_flow_num();

#endif //ANALYZE_EVERFLOW_H
