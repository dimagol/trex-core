//
// Created by dima on 14/08/17.
//

//#include <../src/dpdk/lib/librte_net/rte_udp.h>
#include <cstring>
//#include <../src/dpdk/lib/librte_net/rte_ip.h>
#include <../src/common/Network/Packet/EthernetHeader.h>
//#include <src/common/Network/Packet/IPHeader.h>
#include "GtpTunnulizer.h"

#ifndef _RTE_UDP_H_
#define _RTE_UDP_H_

/**
 * @file
 *
 * UDP-related defines
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * UDP Header
 */
struct udp_hdr_s {
	uint16_t src_port;    /**< UDP source port. */
	uint16_t dst_port;    /**< UDP destination port. */
	uint16_t dgram_len;   /**< UDP datagram length */
	uint16_t dgram_cksum; /**< UDP datagram checksum */
} __attribute__((__packed__));

#ifdef __cplusplus
}
#endif

#endif /* RTE_UDP_H_ */



#ifndef _RTE_IP_H_
#define _RTE_IP_H_
/**
 * IPv4 Header
 */
struct ipv4_hdr_s {
    uint8_t  version_ihl;		/**< version and header length */
    uint8_t  type_of_service;	/**< type of service */
    uint16_t total_length;		/**< length of packet */
    uint16_t packet_id;		/**< packet ID */
    uint16_t fragment_offset;	/**< fragmentation offset */
    uint8_t  time_to_live;		/**< time to live */
    uint8_t  next_proto_id;		/**< protocol ID */
    uint16_t hdr_checksum;		/**< header checksum */
    uint32_t src_addr;		/**< source address */
    uint32_t dst_addr;		/**< destination address */
} __attribute__((__packed__));

/**
 * IPv6 Header
 */
struct ipv6_hdr_s {
    uint32_t vtc_flow;     /**< IP version, traffic class & flow label. */
    uint16_t payload_len;  /**< IP packet length - includes sizeof(ip_header). */
    uint8_t  proto;        /**< Protocol, next header. */
    uint8_t  hop_limits;   /**< Hop limits. */
    uint8_t  src_addr[16]; /**< IP address of source host. */
    uint8_t  dst_addr[16]; /**< IP address of destination host(s). */
} __attribute__((__packed__));

#endif

#ifndef GTPv1_HDR_LEN
#define GTPv1_HDR_LEN 40
#endif

#ifndef GTPV1_FLAGS
#define GTPV1_FLAGS 0x32
#endif

#ifndef GTPV1_TPDU_MESSAGE_TYPE
#define GTPV1_TPDU_MESSAGE_TYPE 0xff
#endif

#ifndef SIZE_OF_GTPV1_OPTIONAL_FIELDS
#define SIZE_OF_GTPV1_OPTIONAL_FIELDS 4
#endif
#ifndef SIZE_OF_GTPV1_HEADER
#define SIZE_OF_GTPV1_HEADER 12
#endif
#ifndef SIZE_OF_UDP_HEADER
#define SIZE_OF_UDP_HEADER 8
#endif
#ifndef GTP_PORTS
#define GTP_PORTS 2152
#endif

#ifndef IP_UDP_PROTO
#define IP_UDP_PROTO 0X11 //17 UDP
#endif

#ifndef IP_MAX_TTL
#define IP_MAX_TTL 0XFF //255
#endif

#ifndef IP_NO_FRAGMENTATION
#define IP_NO_FRAGMENTATION 0x4000
#endif

#ifndef IP_NO_PACKET_ID
#define IP_NO_PACKET_ID 0x00
#endif

#ifndef IP_NO_SERVICE
#define IP_NO_SERVICE 0x00
#endif

#ifndef IP4_20_BYTES_HEADER_START
#define IP4_20_BYTES_HEADER_START 0x45
#endif

class HeaderCreator{
public:
    static void create_ipv4(ipv4_hdr_s *  ipv4_hdr,
                            uint16_t payload_len,
                            uint8_t next_proto,
                            uint32_t src_ip,
                            uint32_t dst_ip){
        memset(ipv4_hdr,0,sizeof(ipv4_hdr_s));
        ipv4_hdr->version_ihl = IP4_20_BYTES_HEADER_START;
        ipv4_hdr->type_of_service = IP_NO_SERVICE;
        ipv4_hdr->total_length = htobe16(sizeof(ipv4_hdr_s) + payload_len);
        ipv4_hdr->packet_id = IP_NO_PACKET_ID;
        ipv4_hdr->fragment_offset = htobe16(IP_NO_FRAGMENTATION);
        ipv4_hdr->time_to_live = IP_MAX_TTL;
        ipv4_hdr->next_proto_id = next_proto;
        ipv4_hdr->src_addr = htobe32(src_ip);
        ipv4_hdr->dst_addr = htobe32(dst_ip);
        ipv4_hdr->hdr_checksum = htobe16(pkt_InetChecksum((uint8_t *)(ipv4_hdr), sizeof(ipv4_hdr_s)));

    }

    static void create_ipv6(ipv6_hdr_s *ipv6_hdr,
                            uint16_t payload_len,
                            uint8_t next_proto,
                            uint16_t *src_ip,
                            uint16_t *dst_ip);

    static void create_udp(udp_hdr_s * udp_hdr, uint16_t payload_len){
        memset(udp_hdr,0,sizeof(udp_hdr_s));
        udp_hdr->src_port = htobe16(GTP_PORTS);
        udp_hdr->dst_port = htobe16(GTP_PORTS);
        udp_hdr->dgram_len = htobe16(sizeof(udp_hdr_s) + payload_len);
        udp_hdr->dgram_cksum = 0;

    }

    static void create_gtp(gtp_header_t * gtp_header, uint16_t payload_len){
        memset(gtp_header,0,sizeof(gtp_header_t));
        gtp_header->gtp_flags = GTPV1_FLAGS;
        gtp_header->gtp_message_type = GTPV1_TPDU_MESSAGE_TYPE;
        gtp_header->gtp_message_len = htobe16(payload_len + 4);
        gtp_header->gtp_tunnel_Id = htobe32(0);
    }

};

void HeaderCreator::create_ipv6(ipv6_hdr_s *ipv6_hdr,
                                uint16_t payload_len,
                                uint8_t next_proto,
                                uint16_t *src_ip,
                                uint16_t *dst_ip) {
    memset(ipv6_hdr,0,sizeof(ipv6_hdr_s));
    ipv6_hdr->vtc_flow = 0x60;
    ipv6_hdr->payload_len =  htobe16(payload_len);
    ipv6_hdr->proto = next_proto;
    ((IPv6Header *) ipv6_hdr)->setSourceIpv6(src_ip);
    ((IPv6Header *) ipv6_hdr)->setDestIpv6(dst_ip);

}

bool GtpTunnulizer::tunnulize_next_packet(CCapPktRaw &raw_packet) {

    uint32_t ip_header_offset = 0xFFFFFFFF;
    uint16_t ip_payload_len = 0;
    uint16_t ip_header_len = 0;
    uint8_t ip_next_proto = 0;

    bool in_packet_is_ipv6 = false;
    uint32_t ip4_src = 0;
    uint32_t ip4_dst = 0;
    uint16_t  ip6_src[20];
    uint16_t  ip6_dst[20];

    IPv6Header * in_packet_ipv6_hdr = nullptr;
    switch( ((EthernetHeader *)(raw_packet.raw))->getNextProtocol() ) {
        case EthernetHeader::Protocol::IP:
            ip_header_offset = 14;
            ip_header_len = (((ipv4_hdr_s *)(raw_packet.raw + ip_header_offset))->version_ihl & 0x0F) * 4;
            ip_payload_len =  htobe16(((ipv4_hdr_s *)(raw_packet.raw + ip_header_offset))->total_length) - ip_header_len;
            ip_next_proto = ((ipv4_hdr_s *)(raw_packet.raw + ip_header_offset))->next_proto_id;
            ((ipv4_hdr_s *)(raw_packet.raw + ip_header_offset))->src_addr = htobe32(this->gtp_client_ip);
            ((ipv4_hdr_s *)(raw_packet.raw + ip_header_offset))->dst_addr = htobe32(this->gtp_server_ip);
            ip4_src = ((ipv4_hdr_s *)(raw_packet.raw + ip_header_offset))->src_addr;
            ip4_dst = ((ipv4_hdr_s *)(raw_packet.raw + ip_header_offset))->dst_addr;
            break;
        case EthernetHeader::Protocol::IPv6:
            ip_header_offset = 14;
            in_packet_is_ipv6 = true;
            ip_payload_len = htobe16(((ipv6_hdr_s *)(raw_packet.raw + ip_header_offset))->payload_len);
            ip_header_len = sizeof(ipv6_hdr_s);
            ip_next_proto = ((ipv6_hdr_s *)(raw_packet.raw + ip_header_offset))->proto;

            in_packet_ipv6_hdr = ((IPv6Header *)(raw_packet.raw + ip_header_offset));
            in_packet_ipv6_hdr->getDestIpv6(ip6_dst);
            in_packet_ipv6_hdr->getSourceIpv6(ip6_src);
            break;
        case EthernetHeader::Protocol::VLAN:
            switch (((EthernetHeader *)(raw_packet.raw))->getVlanProtocol()){
                case EthernetHeader::Protocol::IP :
                    ip_header_offset = 18;
                    ip_header_len = (((ipv4_hdr_s *)(raw_packet.raw + ip_header_offset))->version_ihl & 0x0F) * 4;
                    ip_payload_len =  htobe16(((ipv4_hdr_s *)(raw_packet.raw + ip_header_offset))->total_length) - ip_header_len;
                    ip_next_proto = ((ipv4_hdr_s *)(raw_packet.raw + ip_header_offset))->next_proto_id;
                    ((ipv4_hdr_s *)(raw_packet.raw + ip_header_offset))->src_addr = htobe32(this->gtp_client_ip);
                    ((ipv4_hdr_s *)(raw_packet.raw + ip_header_offset))->dst_addr = htobe32(this->gtp_server_ip);
                    ip4_src = ((ipv4_hdr_s *)(raw_packet.raw + ip_header_offset))->src_addr;
                    ip4_dst = ((ipv4_hdr_s *)(raw_packet.raw + ip_header_offset))->dst_addr;
                    break;
                case EthernetHeader::Protocol::IPv6:
                    in_packet_is_ipv6 = true;
                    ip_header_offset = 18;
                    ip_payload_len = htobe16(((ipv6_hdr_s *)(raw_packet.raw + ip_header_offset))->payload_len);
                    ip_next_proto = ((ipv6_hdr_s *)(raw_packet.raw + ip_header_offset))->proto;
                    ip_header_len = sizeof(ipv6_hdr_s);
                    in_packet_ipv6_hdr = ((IPv6Header *)(raw_packet.raw + ip_header_offset));
                    in_packet_ipv6_hdr->getDestIpv6(ip6_dst);
                    in_packet_ipv6_hdr->getSourceIpv6(ip6_src);
                    break;
                default:
                    // not ip proto
                    break;
            }
            break;
        default:
            // not ip proto
            break;
    }

//    eth_end_of_packet_len = raw_packet.pkt_len - ip_header_offset - ip_header_len - ip_payload_len+3;

    //prepare headers
    if (ip_header_offset == 0xFFFFFFFF){
        // bad packet
        return false;
    }

    ipv6_hdr_s external_ipv6_hdr = {};
    ipv4_hdr_s external_ipv4_hdr = {};
    ipv6_hdr_s internal_ipv6_hdr = {};
    ipv4_hdr_s internal_ipv4_hdr = {};

    udp_hdr_s udphdr = {};
    gtp_header_t gtp_header = {};

    if (in_packet_is_ipv6){
        if(this->in_gtp_is_ipv6){
            // in gtp and the external ip is 6
            HeaderCreator::create_ipv6(&external_ipv6_hdr,
                                       ip_payload_len + sizeof(gtp_header_t) + sizeof(udp_hdr_s) + sizeof(ipv6_hdr_s),
                                       IP_UDP_PROTO,
                                       ip6_src,
                                       ip6_dst);

            HeaderCreator::create_ipv6(&internal_ipv6_hdr,
                                       ip_payload_len,
                                       ip_next_proto,
                                       gtp_client_v6_addr,
                                       gtp_server_v6_addr);

            HeaderCreator::create_udp(&udphdr, ip_payload_len + sizeof(gtp_header) + sizeof(ipv6_hdr_s));
            HeaderCreator::create_gtp(&gtp_header,ip_payload_len + sizeof(ipv6_hdr_s));

        }else{
            // in gtp is 4 external is 6
            HeaderCreator::create_ipv6(&external_ipv6_hdr,
                                       ip_payload_len + sizeof(gtp_header_t) + sizeof(udp_hdr_s) + sizeof(ipv4_hdr_s),
                                       IP_UDP_PROTO,
                                       ip6_src,
                                       ip6_dst);
            HeaderCreator::create_ipv4(&internal_ipv4_hdr,
                                       ip_payload_len,
                                       ip_next_proto,
                                       gtp_client_ip,
                                       gtp_server_ip);
            HeaderCreator::create_udp(&udphdr, ip_payload_len + sizeof(gtp_header) + sizeof(ipv4_hdr_s));
            HeaderCreator::create_gtp(&gtp_header,ip_payload_len + sizeof(ipv4_hdr_s));
        }

    } else{
        if(this->in_gtp_is_ipv6){
            // in gtp is 6 external is 4
            HeaderCreator::create_ipv4(&external_ipv4_hdr,
                                       ip_payload_len + sizeof(gtp_header_t) + sizeof(udp_hdr_s) + sizeof(ipv6_hdr_s),
                                       IP_UDP_PROTO,
                                       ip4_src,
                                       ip4_dst);
            HeaderCreator::create_ipv6(&internal_ipv6_hdr,
                                       ip_payload_len,
                                       ip_next_proto,
                                       gtp_client_v6_addr,
                                       gtp_server_v6_addr);
            HeaderCreator::create_udp(&udphdr, ip_payload_len + sizeof(gtp_header) + sizeof(ipv6_hdr_s));
            HeaderCreator::create_gtp(&gtp_header,ip_payload_len + sizeof(ipv6_hdr_s));

        } else{
            // in gtp and the external ip is 4
            HeaderCreator::create_ipv4(&external_ipv4_hdr,
                                       ip_payload_len + sizeof(gtp_header_t) + sizeof(udp_hdr_s) + sizeof(ipv4_hdr_s),
                                       IP_UDP_PROTO,
                                       ip4_src,
                                       ip4_dst);
            HeaderCreator::create_ipv4(&internal_ipv4_hdr,
                                       ip_payload_len,
                                       ip_next_proto,
                                       gtp_client_ip,
                                       gtp_server_ip);
            HeaderCreator::create_udp(&udphdr, ip_payload_len + sizeof(gtp_header) + sizeof(ipv4_hdr_s));
            HeaderCreator::create_gtp(&gtp_header,ip_payload_len + sizeof(ipv4_hdr_s));
        }

    }


    char temp_buff[sizeof(ipv4_hdr_s) + sizeof(udp_hdr_s) + sizeof(gtp_header_t) + MAX_PKT_SIZE];
    memset(temp_buff,0,sizeof(external_ipv4_hdr) + sizeof(udp_hdr_s) + sizeof(gtp_header_t) + MAX_PKT_SIZE);

    // copy eth
    uint16_t next_proto_offset = 0;
    memcpy(temp_buff,raw_packet.raw, ip_header_offset);
    next_proto_offset += ip_header_offset;

    if (in_packet_is_ipv6){
        memcpy(temp_buff + next_proto_offset , ((uint8_t *)&(external_ipv6_hdr)) , sizeof(ipv6_hdr_s));
        next_proto_offset += sizeof(ipv6_hdr_s);
    } else{
        memcpy(temp_buff + next_proto_offset, ((uint8_t *)&(external_ipv4_hdr)), sizeof(ipv4_hdr_s));
        next_proto_offset += sizeof(ipv4_hdr_s);
    }

    memcpy(temp_buff + next_proto_offset, ((uint8_t *)&(udphdr)), sizeof(udp_hdr_s));
    next_proto_offset += sizeof(udp_hdr_s);

    memcpy(temp_buff + next_proto_offset, ((uint8_t *)&(gtp_header)), sizeof(gtp_header_t));
    gtp_header_offset_in_last_packet = next_proto_offset;

    next_proto_offset += sizeof(gtp_header_t);

    if(this->in_gtp_is_ipv6){
        memcpy(temp_buff + next_proto_offset, ((uint8_t *)&(internal_ipv6_hdr)) , sizeof(ipv6_hdr_s));
        last_packet_in_gtp_ip_header_v6 = (IPv6Header*)(raw_packet.raw + next_proto_offset);
        next_proto_offset += sizeof(ipv6_hdr_s);
    } else{
        memcpy(temp_buff + next_proto_offset, ((uint8_t *)&(internal_ipv4_hdr)), sizeof(ipv4_hdr_s));
        last_packet_in_gtp_ip_header_v4 = (IPHeader *)(raw_packet.raw + next_proto_offset);
        next_proto_offset += sizeof(ipv4_hdr_s);
    }

    memcpy(temp_buff + next_proto_offset, raw_packet.raw + ip_header_len + ip_header_offset, ip_payload_len);
    next_proto_offset += ip_payload_len;
    memcpy(raw_packet.raw, temp_buff, next_proto_offset );
    memset(raw_packet.raw + next_proto_offset,0,4); //eth crc
    raw_packet.pkt_len = next_proto_offset;
    gtp_header_in_last_packet = (gtp_header_t *)(raw_packet.raw + gtp_header_offset_in_last_packet);

    return true;
}

bool GtpTunnulizer::set_last_packet_direction(GtpTunnulizer::Direction direction) {
    if(!in_gtp_is_ipv6){

        if (direction == UP_DIR){
            gtp_header_in_last_packet->gtp_sequence_number = htobe16(this->gtp_client_seq++);
            last_packet_in_gtp_ip_header_v4->myDestination = htobe32(gtp_server_ip);
            last_packet_in_gtp_ip_header_v4->mySource = htobe32(gtp_client_ip);
        }
        else {
            gtp_header_in_last_packet->gtp_sequence_number = htobe16(this->gtp_server_seq++);
            last_packet_in_gtp_ip_header_v4->myDestination = htobe32(gtp_client_ip);
            last_packet_in_gtp_ip_header_v4->mySource = htobe32(gtp_server_ip);
        }
    } else{
        if (direction == UP_DIR){
            gtp_header_in_last_packet->gtp_sequence_number = htobe16(this->gtp_client_seq++);
            last_packet_in_gtp_ip_header_v6->setDestIpv6(gtp_server_v6_addr);
            last_packet_in_gtp_ip_header_v6->setSourceIpv6(gtp_client_v6_addr);

            last_packet_in_gtp_ip_header_v6->updateLSBIpv6Dst(gtp_server_ip);
            last_packet_in_gtp_ip_header_v6->updateLSBIpv6Src(gtp_client_ip);
        }
        else {
            gtp_header_in_last_packet->gtp_sequence_number = htobe16(this->gtp_server_seq++);
            last_packet_in_gtp_ip_header_v6->setDestIpv6(gtp_client_v6_addr);
            last_packet_in_gtp_ip_header_v6->setSourceIpv6(gtp_server_v6_addr);
            last_packet_in_gtp_ip_header_v6->updateLSBIpv6Dst(gtp_client_ip);
            last_packet_in_gtp_ip_header_v6->updateLSBIpv6Src(gtp_server_ip);
        }
    }

    return true;
}

void
GtpTunnulizer::init_flow_args_ipv6(const uint16_t *gtp_client_v6_addr,
                                   uint32_t  gtp_client_v6_addr_lsb,
                                   const uint16_t *gtp_server_v6_addr,
                                   uint32_t  gtp_server_v6_addr_lsb) {
    this->in_gtp_is_ipv6 = true;
    this->gtp_client_ip = gtp_client_v6_addr_lsb;
    this->gtp_server_ip = gtp_server_v6_addr_lsb;
    for(int i = 0; i < 6; i++){
        this->gtp_client_v6_addr[i] = gtp_client_v6_addr[i];
        this->gtp_server_v6_addr[i] = gtp_server_v6_addr[i];
    }
}

void GtpTunnulizer::init_flow_args(uint32_t gtp_client_ip, uint32_t gtp_server_ip){
    this->gtp_client_ip = gtp_client_ip;
    this->gtp_server_ip = gtp_server_ip;
}


uint32_t GtpTunnulizer::get_last_packet_gtp_header_offset() {
    return this->gtp_header_offset_in_last_packet;
}


