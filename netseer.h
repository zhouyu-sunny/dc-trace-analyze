#ifndef ANALYZE_NETSEER_H
#define ANALYZE_NETSEER_H

#include "packet.h"

void record_netseer_event(packet_t *p);

void netseer_print();

void record_netseer_flow(packet_t *p);
void netseer_flow_print();

#endif //ANALYZE_NETSEER_H
