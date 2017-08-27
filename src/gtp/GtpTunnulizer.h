//
// Created by dima on 14/08/17.
//

#ifndef TREX_CORE_GTPTUNNULIZER_H
#define TREX_CORE_GTPTUNNULIZER_H

#include <cstdint>
#include <../src/common/erf_reader.h>
#include <../src/common/Network/Packet/IPHeader.h>
#include <common/Network/Packet/IPv6Header.h>

typedef struct __attribute__((__packed__)) gtp_header_ {
    uint8_t gtp_flags; // (byte) flags: 32 means gtp version 1 with
    uint8_t gtp_message_type; //(byte) message type 0xff is PDU.
    uint16_t gtp_message_len; //(short) len of GTP header and payload
    uint32_t gtp_tunnel_Id; // (int) le TEID..
    uint32_t gtp_sequence_number; // (int) sequence number goes here - we don't use it.
} gtp_header_t;

class GtpTunnulizer {

public:
    enum Direction{
        UP_DIR = 0,
        DOWN_DIR = 1
    };
    void init_flow_args(uint32_t gtp_client_ip,
                        uint32_t gtp_client_tid,
                        uint32_t gtp_server_ip,
                        uint32_t gtp_server_tid);

    void init_flow_args_ipv6(const uint16_t *gtp_client_v6_addr,
                             uint32_t  gtp_client_v6_addr_lsb,
                             uint32_t gtp_client_tid,
                             const uint16_t *gtp_server_v6_addr,
                             uint32_t  gtp_server_v6_addr_lsb,
                             uint32_t gtp_server_tid);

    bool tunnulize_next_packet(CCapPktRaw &raw_packet);

    bool set_last_packet_direction(Direction direction);

    uint32_t get_last_packet_gtp_header_offset();

private:
    uint32_t gtp_client_ip;
    uint32_t gtp_client_tid;
    uint32_t gtp_server_ip;
    uint32_t gtp_server_tid;
    uint16_t gtp_client_seq = 1;
    uint16_t gtp_server_seq = 1;
    gtp_header_t * gtp_header_in_last_packet;
    IPHeader * last_packet_in_gtp_ip_header_v4;
    IPv6Header * last_packet_in_gtp_ip_header_v6;
    uint32_t gtp_header_offset_in_last_packet;

    bool in_gtp_is_ipv6 = false;
    uint16_t  gtp_client_v6_addr[8];
    uint16_t  gtp_server_v6_addr[8];
};


#endif //TREX_CORE_GTPTUNNULIZER_H
