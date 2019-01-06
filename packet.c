#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include "packet.h"
#include "hash.h"

void
extract_packet(packet_t * p, const uint8_t * buf, uint32_t length)
{
    int i = 0;
    if (unlikely(p == NULL)) {
        printf("The packet should not be null!");
        exit(1);
    }
    // Clear the packet structure
    p->int_valid = 0;
    p->event_cnt = 0;
    p->packet_length = length;
    int offset = 14;
    const ethernet_t * ethernet = mtod(buf, ethernet_t*);
    const ipv4_t * ipv4;
    const tcp_t * tcp;
    if (SWAP16(ethernet->eth_type) == ETHER_TYPE_IPv4) {
        ipv4 = mtod_offset(buf, ipv4_t *, offset);
        offset += IPv4_HDR_SIZE;
        p->flow.dip = ipv4->dst_ip;
        p->flow.sip = ipv4->src_ip;
        p->flow.proto = ipv4->proto;
        p->ip_len = SWAP16(ipv4->tot_len);
        if (ipv4->proto == IPPROTO_TCP) {
            tcp = mtod_offset(buf, tcp_t *, offset);
            p->tcp_flag = tcp->ctrl;
            p->flow.sport = tcp->src_port;
            p->flow.dport = tcp->dst_port;
            p->tcp_hdr_len = tcp->flag >> 2;
            offset += TCP_HDR_SIZE;
            p->probe_hdr = mtod_offset(buf, int_probe_hdr_t *, offset);
            if (p->probe_hdr->marker1 == 0xaaaaaaaa && p->probe_hdr->marker2 == 0xbbbbbbbb) {
                offset += INT_PROBE_HDR_SIZE;
                for (i = 0; i < p->probe_hdr->hop_count; i++) {
                    p->md_hdrs[i] = mtod_offset(buf, int_md_hdr_t *, offset);
                    offset += INT_MD_HDR_SIZE;
                }
                p->int_valid = 1;
                p->ts.nsec = SWAP32(p->md_hdrs[p->probe_hdr->hop_count - 1]->rx_ts_nsec);
                p->ts.sec = SWAP32(p->md_hdrs[p->probe_hdr->hop_count - 1]->rx_ts_sec);
            } else {
                printf("%x %x\n", p->probe_hdr->marker2, p->probe_hdr->marker1);
            }
        }
    }
}