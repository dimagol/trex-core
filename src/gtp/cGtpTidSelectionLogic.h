//
// Created by dima on 17/08/17.
//

#ifndef TREX_CORE_CGTPTIDSELECTIONLOGIC_H
#define TREX_CORE_CGTPTIDSELECTIONLOGIC_H


#include <cstdint>
#include <cstdio>
#include <zconf.h>

class cGtpTidSelectionLogic {
public:
    cGtpTidSelectionLogic(uint32_t m_gtp_server_ip_start,
                          uint32_t m_gtp_client_ip_start,
                          uint32_t m_in_gtp_server_ip_start,
                          uint32_t m_in_gtp_client_ip_start,
                          uint32_t m_gtp_tid_server_start,
                          uint32_t m_gtp_tid_client_start,
                          uint32_t gtp_number_of_servers_behind_gtp,
                          uint32_t gtp_number_of_clients_behind_gtp)
            : m_gtp_server_ip_start(m_gtp_server_ip_start),
              m_gtp_client_ip_start(m_gtp_client_ip_start),
              m_in_gtp_server_ip_start(m_in_gtp_server_ip_start),
              m_in_gtp_client_ip_start(m_in_gtp_client_ip_start),
              m_gtp_tid_server_start(m_gtp_tid_server_start),
              m_gtp_tid_client_start(m_gtp_tid_client_start),
              m_gtp_number_of_servers_behind_gtp(gtp_number_of_servers_behind_gtp),
              m_gtp_number_of_clients_behind_gtp(gtp_number_of_clients_behind_gtp)
    {}

    uint32_t get_tid_client_to_server(uint32_t ip_src_ip, uint32_t gtp_src_ip,
                                      uint32_t ip_dst_ip, uint32_t gtp_dst_ip);
    uint32_t get_tid_server_to_client(uint32_t ip_src_ip, uint32_t gtp_src_ip,
                                      uint32_t ip_dst_ip, uint32_t gtp_dst_ip);


private:
    uint32_t m_gtp_server_ip_start;
    uint32_t m_gtp_client_ip_start;
    uint32_t m_in_gtp_server_ip_start;
    uint32_t m_in_gtp_client_ip_start;
    uint32_t m_gtp_tid_server_start;
    uint32_t m_gtp_tid_client_start;
    uint32_t m_gtp_number_of_servers_behind_gtp;
    uint32_t m_gtp_number_of_clients_behind_gtp;

};


#endif //TREX_CORE_CGTPTIDSELECTIONLOGIC_H
