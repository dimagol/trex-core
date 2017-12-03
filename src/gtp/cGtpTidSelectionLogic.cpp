//
// Created by dima on 17/08/17.
//

#include "cGtpTidSelectionLogic.h"


uint32_t cGtpTidSelectionLogic::get_tid_client_to_server(uint32_t ip_src_ip, uint32_t gtp_src_ip,
                                                         uint32_t ip_dst_ip, uint32_t gtp_dst_ip){

    return m_gtp_tid_server_start + (gtp_src_ip - m_in_gtp_client_ip_start) +
        m_gtp_number_of_clients_behind_gtp * (ip_src_ip - m_gtp_client_ip_start);

}

uint32_t cGtpTidSelectionLogic::get_tid_server_to_client(uint32_t ip_src_ip, uint32_t gtp_src_ip,
                                                         uint32_t ip_dst_ip, uint32_t gtp_dst_ip) {
    print_ip1(gtp_dst_ip);
    print_ip1(m_in_gtp_client_ip_start);
    print_ip1(ip_src_ip);
    print_ip1(m_gtp_client_ip_start);

    return m_gtp_tid_client_start + (gtp_dst_ip - m_in_gtp_client_ip_start) +
            m_gtp_number_of_clients_behind_gtp * (ip_src_ip - m_gtp_client_ip_start) ;
}

