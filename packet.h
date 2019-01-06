
#ifndef DPDK_PCAP_FLOW_H
#define DPDK_PCAP_FLOW_H

#include <stdint.h>
#include "protocol.h"

#define SWAP16(v) \
	(uint16_t) ((((uint16_t)(v) & UINT16_C(0x00ff)) << 8) | \
	 (((uint16_t)(v) & UINT16_C(0xff00)) >> 8))

#define SWAP32(v) \
	((((uint32_t)(v) & UINT32_C(0x000000ff)) << 24) | \
	 (((uint32_t)(v) & UINT32_C(0x0000ff00)) <<  8) | \
	 (((uint32_t)(v) & UINT32_C(0x00ff0000)) >>  8) | \
	 (((uint32_t)(v) & UINT32_C(0xff000000)) >> 24))

#define SWAP64(v) \
	((((uint64_t)(v) & UINT64_C(0x00000000000000ff)) << 56) | \
	 (((uint64_t)(v) & UINT64_C(0x000000000000ff00)) << 40) | \
	 (((uint64_t)(v) & UINT64_C(0x0000000000ff0000)) << 24) | \
	 (((uint64_t)(v) & UINT64_C(0x00000000ff000000)) <<  8) | \
	 (((uint64_t)(v) & UINT64_C(0x000000ff00000000)) >>  8) | \
	 (((uint64_t)(v) & UINT64_C(0x0000ff0000000000)) >> 24) | \
	 (((uint64_t)(v) & UINT64_C(0x00ff000000000000)) >> 40) | \
	 (((uint64_t)(v) & UINT64_C(0xff00000000000000)) >> 56))

	 typedef struct ts_t {
    uint32_t sec;
    uint32_t nsec;
} ts_t;

typedef struct flow_t {
	uint32_t sip;
	uint32_t dip;
	uint8_t proto;
	uint16_t sport;
	uint16_t dport;
} flow_t;
typedef struct packet_t {
	int packet_length;
	int tcp_hdr_len;
	int ip_len;
	flow_t flow;
	uint8_t tcp_flag;
    const int_probe_hdr_t * probe_hdr;
    const int_md_hdr_t * md_hdrs[5];
    ts_t ts;
    uint8_t int_valid;
    uint32_t event_id[16];
    uint32_t event_cnt;
    uint32_t flow_id;
    uint32_t flow_cnt[16];
    uint16_t port_id[16];
    uint32_t dev_id[16];
} packet_t;

static inline int cmp_flow(const flow_t * arg1, const flow_t * arg2) {
    if (arg1->dport  != arg2->dport) {
        return 1;
    }
    if (arg1->sport  != arg2->sport) {
        return 1;
    }
    if (arg1->dip  != arg2->dip) {
        return 1;
    }
    if (arg1->sip  != arg2->sip) {
        return 1;
    }
    return 0;
}


/**
 *
 * @param length
 */
void extract_packet(packet_t * , const uint8_t *, uint32_t length);

/**
 *
 * @param dst
 * @param src
 */
static inline void
copy_eth_addr(uint8_t* dst, const uint8_t* src)
{
	((uint32_t*) dst)[0] = ((const uint32_t*) src)[0];
	((uint32_t*) (dst + 2))[0] = ((const uint32_t*) (src + 2))[0];
}

#define mtod_offset(m, t, o)	\
	((t)((char *)(m) + (o)))

#define mtod(m, t) mtod_offset(m, t, 0)

#endif //DPDK_PCAP_FLOW_H
