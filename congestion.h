//
// Created by ZhouYu on 2019/1/2.
//

#ifndef ANALYZE_CONGESTION_H
#define ANALYZE_CONGESTION_H

#include "packet.h"

#define ENABLE_PRINT_EVENT 0

void record_congestion_event(packet_t *p);

void congestion_print();

#endif //ANALYZE_CONGESTION_H
