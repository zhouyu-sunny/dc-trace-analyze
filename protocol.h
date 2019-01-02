#ifndef DPDK_PCAP_PROTOCOL_H
#define DPDK_PCAP_PROTOCOL_H

#define ETHER_TYPE_IPv4 0x0800 /**< IPv4 Protocol. */
#define ETHER_TYPE_IPv6 0x86DD /**< IPv6 Protocol. */
#define ETHER_TYPE_ARP  0x0806 /**< Arp Protocol. */
#define ETHER_TYPE_RARP 0x8035 /**< Reverse Arp Protocol. */
#define ETHER_TYPE_VLAN 0x8100 /**< IEEE 802.1Q VLAN tagging. */
#define ETHER_TYPE_QINQ 0x88A8 /**< IEEE 802.1ad QinQ tagging. */
#define ETHER_TYPE_1588 0x88F7 /**< IEEE 802.1AS 1588 Precise Time Protocol. */
#define ETHER_TYPE_SLOW 0x8809 /**< Slow protocols (LACP and Marker). */
#define ETHER_TYPE_TEB  0x6558 /**< Transparent Ethernet Bridging. */
#define ETHER_TYPE_LLDP 0x88CC /**< LLDP Protocol. */

typedef struct ethernet_t {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
} ethernet_t;

#define IPPROTO_ICMP 1
#define IPPROTO_UDP 17
#define IPPROTO_TCP 6

typedef struct ipv4_t {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tot_en;
    uint16_t ipid;
    uint16_t frag;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ipv4_t;
#define IPv4_HDR_SIZE sizeof(ipv4_t)

typedef struct tcp_t {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t  ack;
    uint8_t flag;
    uint8_t ctrl;
    uint16_t rwnd;
    uint16_t checksum;
    uint16_t ptr;
} tcp_t;
#define TCP_HDR_SIZE sizeof(tcp_t)

typedef struct udp_t {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_t;

typedef struct int_probe_hdr {
    uint32_t marker1;
    uint32_t marker2 ;
    uint8_t version;
    uint8_t msg_type;
    uint16_t flags;
    uint32_t req_vec;
    uint8_t hop_limit;
    uint8_t hop_count;
    uint16_t zero;
    uint16_t max_len;
    uint16_t current_len;
    uint16_t sender_handle;
    uint16_t seq_no;
} __attribute__((__packed__)) int_probe_hdr_t;

#define INT_PROBE_HDR_SIZE sizeof(int_probe_hdr_t)

typedef struct int_md_hdr {
    uint32_t  switch_id : 32;
    uint8_t  template_id: 3, congestion : 5;
    uint8_t  egress_drop_uppper : 8;
    uint8_t  ttl : 8;
    uint8_t queue_id : 8;
    uint16_t resv : 16;
    uint32_t  rx_ts_sec: 32;
    uint32_t rx_ts_nsec: 32;
    uint32_t tx_ts_nsec: 32;
    uint16_t egress_utilization: 16;
    uint8_t ingress_module : 8;
    uint8_t ingress_id : 8;
    uint8_t egress_module : 8;
    uint8_t egress_id  : 8;
    uint32_t egress_drop_cnt : 32;
}__attribute__((__packed__)) int_md_hdr_t;

#define INT_MD_HDR_SIZE sizeof(int_md_hdr_t)

#endif //DPDK_PCAP_PROTOCOL_H
