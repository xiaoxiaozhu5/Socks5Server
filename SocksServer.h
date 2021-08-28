#pragma once

#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include "NetworkIo.h"

class ServerSession;

class SocksServer : public BasicNetworkIO, public boost::enable_shared_from_this<SocksServer>
{
	using IdType = unsigned long;
public:
	using endpoint = boost::asio::ip::tcp::endpoint;
	using acceptor = boost::asio::ip::tcp::acceptor;

	bool Start(std::string ip, uint16_t port);
	void Stop();

private:
	void start_accept_coroutine();

private:
	IdType session_id_base = 1;
	std::string server_ip_;
	uint16_t server_port_;
	std::unique_ptr<acceptor> acceptor_;
	std::map<IdType, boost::weak_ptr<ServerSession>> sessionid_session_;	
};

