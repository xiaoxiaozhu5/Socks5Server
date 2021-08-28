#include "Socks5Helper.h"

#include <WS2tcpip.h>


#pragma warning(disable: 4996)

bool Socks5Helper::get_ip_port_from_request(SOCKS5_REQ* request, std::string& ip_out, uint16_t& port_out)
{
	unsigned char temp[10] = {0};
	memcpy(temp, request, 10);
	ip_out.clear();
	for (int i = 4; i < 7; i++) {
		ip_out.append(std::to_string(temp[i]));
		ip_out.append(".");
	}
	ip_out.append(std::to_string(temp[7]));

	uint32_t size;
	if (1 == inet_pton(AF_INET, ip_out.c_str(), &size)) {
		char port[2];
		port[0] = temp[9];
		port[1] = temp[8];
		memcpy(&port_out, port, 2);
		return true;
	}
	else 
	{
		ip_out.clear();
		return false;
	}
}

bool Socks5Helper::get_ip_port_from_domain(SOCKS5_REQ* request, std::string& ip_out, uint16_t& port_out)
{
	auto name_len = (unsigned char)request->len;
	ip_out.assign(request->domain, name_len);
	port_out = *(uint16_t*)(request->domain + name_len);
	port_out = htons(port_out);
	return true;
}

void Socks5Helper::build_request(unsigned char* data, std::string ip, unsigned short port)
{
	static const char* split = ".";
	auto req = (SOCKS5_REQ*)data;
	req->command = 0x01;
	req->atyp = 0x01;

	char* split_res = strtok(const_cast<char*>(ip.c_str()), split);

	int pos = 4;
	while (split_res != nullptr) {
		unsigned char ip_frag = atoi(split_res);

		memcpy(&data[pos++], &ip_frag, 1);
		split_res = strtok(nullptr, split);
	}

	req->port = port;
}
