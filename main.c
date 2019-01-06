#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "packet.h"
#include "congestion.h"
#include "sample.h"
#include "everflow.h"
#include "netseer.h"
#include "hash.h"

typedef struct flow_container_t {
    struct flow_container_t * next;
    flow_t flow;
} flow_container_t;

#define FLOW_CONTAINER_NUM 65536

flow_container_t* flow_containers[FLOW_CONTAINER_NUM] = {NULL};
#define FLOW_SIZE sizeof(flow_t)

int flow_lookup(flow_t * flow) {
    int idx = hash_crc32(flow, FLOW_SIZE, CRC32C) % FLOW_CONTAINER_NUM;
    flow_container_t * container = flow_containers[idx];
    while (container != NULL) {
        if (key_compare(flow, &container->flow, FLOW_SIZE) != 0) {
            container = container->next;
        } else {
            break;
        }
    }
    if (container != NULL) {
        return 1;
    } else {
        container = malloc(sizeof(flow_container_t));
        container->flow = *flow;
        container->next = flow_containers[idx];
        flow_containers[idx] = container;
        return 0;
    }
}

void fb_test() {
    FILE * list_file = fopen("list.txt", "r");
    char str_name[512];
    int pkt_cnt = 0;
    int threshold = 2;
    while (!feof(list_file)) {
        fgets(str_name, 512, list_file);
        str_name[strlen(str_name) - 1] = '\0';
        FILE * file  = fopen(str_name, "r");
        char data[512];
        int i;
        packet_t p;

        //int pkt_cnt = 0;
        while(!feof(file)) {
            fgets(data, 512, file);
            i = 0;
            while(data[i++]!= '\t');
            while(data[i++]!= '\t');
            p.flow.dip = 0;
            while(data[i]!= '\t') {
                p.flow.dip <<= 4;
                p.flow.dip ^= data[i];
                i++;
            }
            i++;
            p.flow.sip = 0;
            while(data[i]!= '\t') {
                p.flow.sip <<= 4;
                p.flow.sip ^= data[i];
                i++;
            }
            i++;
            p.flow.sport = 0;
            while(data[i]!= '\t') {
                p.flow.sport <<= 4;
                p.flow.sport ^= data[i];
                i++;
            }
            i++;
            p.flow.dport = 0;
            while(data[i]!= '\t') {
                p.flow.dport <<= 4;
                p.flow.dport ^= data[i];
                i++;
            }
            i++;
            while(data[i]!= '\t') {
                p.flow.proto = (uint8_t) (data[i] - 'a');
                i++;
            }

            if (flow_lookup(&p.flow) == 1) {
                continue;
            }

            record_netseer_flow(&p);
            pkt_cnt++;

            if (pkt_cnt >= threshold) {
                // printf("X %d\n", threshold);
                netseer_flow_print();
                threshold += threshold;
            }

            if (pkt_cnt > 1024 * 1024 * 16) {
                return;
            }
        }
        fclose(file);
    }

    fclose(list_file);
}


int main(int argc, char ** argv) {
    pcap_t *pcap[16];
    struct pcap_pkthdr hdr[16];
    int i;
    argc --;
    if (argc <= 0) {
        fb_test();
    }
    else {
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
                    flag++;
                    extract_packet(&packet[i], buf[i], hdr->len);
                    // printf("i %d\n", i);
                    if (packet[i].int_valid == 0) {
                        buf[i] = NULL;
                        flag--;
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
            /*
            if (pkt_cnt % 10 == 1) {
                int ret = record_sample10_event(&packet[min]);
                if (ret < 0) {
                    break;
                }
            }
             */
            /*
            if (pkt_cnt % 100 == 1) {
                int ret = record_sample100_event(&packet[min]);
                if (ret < 0) {
                    break;
                }
            }
            if (pkt_cnt % 1000 == 1) {
                int ret = record_sample1000_event(&packet[min]);
                if (ret < 0) {
                    break;
                }
            }
             */

            if (packet[min].tcp_flag == 0x02) {
                flow_cnt++;
            }

            if (pkt_cnt % 10000000 == 0) {
                // printf("%d \n", pkt_cnt);
            }

            if (pkt_cnt > 200000000) {
                break;
            }
        } while (flag > 0);

        printf("ALL\t%d\t%d\t%d\n", pkt_cnt, get_congestion_flow_num(), get_congestion_event_num());

        congestion_print();
        //sample_print();
        //everflow_print();
        netseer_print();

        for (i = 0; i < argc; i++) {
            pcap_close(pcap[i]);
        }
    }
    return 0;
}