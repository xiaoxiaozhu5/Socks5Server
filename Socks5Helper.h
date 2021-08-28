#pragma once
#include "Define.h"

class Socks5Helper 
{
public:
	static bool get_ip_port_from_request(SOCKS5_REQ* request, std::string &ip_out, uint16_t &port_out);
	static bool get_ip_port_from_domain(SOCKS5_REQ* request, std::string &ip_out, uint16_t &port_out);
	static void build_request(unsigned char* data, std::string ip, unsigned short port);
};
