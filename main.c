#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "packet.h"
#include "congestion.h"
#include "sample.h"
#include "everflow.h"
#include "netseer.h"

int main(int argc, char ** argv) {
    pcap_t *pcap[16];
    struct pcap_pkthdr hdr[16];
    int i;
    argc --;
    for (i = 0; i < argc; i++) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap[i] = pcap_open_offline(argv[i + 1], errbuf);
    }
    const u_char *buf[16] = {NULL};
    packet_t packet[16];
    int flag = 0;
    int min = 0;
    int pkt_cnt = 0, flow_cnt = 0;
    do {
        flag = 0;
        min = -1;
        for (i = 0; i < argc; i++) {
            if (buf[i] == NULL) {
                buf[i] = pcap_next(pcap[i], &hdr[i]);
            }
            if (buf[i] != NULL) {
                flag ++;
                extract_packet(&packet[i], buf[i], hdr->len);
                // printf("i %d\n", i);
                if (packet[i].int_valid == 0) {
                    buf[i] = NULL;
                    flag --;
                } else {
                    if (min < 0) {
                        min = i;
                    } else {
                        if (packet[i].int_valid) {
                            if (packet[i].ts.sec < packet[min].ts.sec) {
                                min = i;
                            } else if (packet[i].ts.sec == packet[min].ts.sec) {
                                if (packet[i].ts.nsec < packet[min].ts.nsec) {
                                    min = i;
                                }
                            }
                        }
                    }
                }
            }
        }
        if (min < 0) {
            break;
        }
        buf[min] = NULL;
        pkt_cnt++;
        record_congestion_event(&packet[min]);
        record_everflow_event(&packet[min]);
        record_netseer_event(&packet[min]);
        if (pkt_cnt % 10 == 1) {
            int ret = record_sample10_event(&packet[min]);
            if (ret < 0) {
                break;
            }
        }
        if (pkt_cnt % 100 == 1) {
            int ret = record_sample100_event(&packet[min]);
            if (ret < 0) {
                break;
            }
        }
        if (packet[min].flow.tcp_flag == 0x02) {
            flow_cnt++;
        }
        if (pkt_cnt % 1000000 == 0) {
            printf("%d \n", pkt_cnt);
        }
        if (pkt_cnt > 2000000) {
            break;
        }
    } while(flag > 0);

    printf("%d\t%d\n", pkt_cnt, flow_cnt);

    congestion_print();
    sample_print();
    everflow_print();
    netseer_print();

    for (i = 0; i < argc; i++) {
        pcap_close(pcap[i]);
    }
    return 0;
}