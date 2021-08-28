#include "SocksServer.h"
#include "ServerSession.h"

#include <boost/asio/spawn.hpp>
#include <boost/make_shared.hpp>

bool SocksServer::Start(std::string ip, uint16_t port)
{
    server_ip_ = ip;
    server_port_ = port;
	acceptor_ = std::make_unique<acceptor>(this->GetIOContext());
	auto ep = endpoint(boost::asio::ip::address::from_string(ip), port);
	boost::system::error_code ec;
	acceptor_->open(ep.protocol(), ec);
	if(ec)
	{
		LogDebug("acceptor open error: %s", ec.message().c_str());
		return false;
	}

	boost::asio::ip::tcp::acceptor::reuse_address reuse(true);
	acceptor_->set_option(reuse);

	acceptor_->bind(ep, ec);
	if(ec)
	{
		LogDebug("bind error: %s", ec.message().c_str());
		return false;
	}

	acceptor_->listen(SOMAXCONN, ec);
	if(ec)
	{
		LogDebug("listen error: %s", ec.message().c_str());
		return false;
	}

	start_accept_coroutine();

	this->RunIO();

	return true;
}

void SocksServer::Stop()
{
	boost::system::error_code ec;
	acceptor_->cancel(ec);
	if(ec)
	{
		LogDebug("acceptor cancel error: %s", ec.message().c_str());
	}
}

void SocksServer::start_accept_coroutine()
{
	auto self(shared_from_this());

	boost::asio::spawn(this->GetIOContext(), [this, self](boost::asio::yield_context yield) {

		while (true)
		{
			boost::system::error_code ec;
			IdType session_id = session_id_base++;
			auto new_session = boost::make_shared<ServerSession>(GetIOContext(), true, session_id);
			this->acceptor_->async_accept(new_session->GetSocket(), yield[ec]);

			if (ec)
			{
				LogDebug("server accept error: %s", ec.message().c_str());
				return;
			}

			sessionid_session_.insert({ session_id, new_session });
			new_session->Start();
		}
	});
}



