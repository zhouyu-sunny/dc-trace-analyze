#ifndef ANALYZE_SAMPLE_H
#define ANALYZE_SAMPLE_H

#include "packet.h"

int record_sample10_event(packet_t *p);
int record_sample100_event(packet_t *p);

void sample_print();

#endif //ANALYZE_SAMPLE_H
