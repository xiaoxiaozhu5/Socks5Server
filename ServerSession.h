#include <boost/enable_shared_from_this.hpp>

#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/bind/bind.hpp>

#include "Define.h"

#include "Socks5Helper.h"

#pragma warning(disable: 4996)

#define SESSION_TIMER_TICK 35
#define SESSION_TIMEOUT_TIME 30
#define RECV_BUFFER_SIZE (1500)

class ServerSession : public boost::enable_shared_from_this<ServerSession>
{
	using IO_CONTEXT = boost::asio::io_context;
	using TCP_SOCKET = boost::asio::ip::tcp::socket;
public:
	ServerSession(IO_CONTEXT& io_context, bool resolve_dns_locally, unsigned long session_id)
		: local_socket_(io_context), timer_(io_context), session_id_(session_id), remote_socket_(io_context)
	{
		if(resolve_dns_locally)
			resolver_ = std::make_unique<boost::asio::ip::tcp::resolver>(io_context);
		last_active_time_ = time(nullptr);
	}
	~ServerSession()
	{
		LogDebug("session %u destroy", session_id_);
	}

	void Start()
	{
		if(!set_no_delay()) return;

		auto self(this->shared_from_this());

		timer_.expires_from_now(boost::posix_time::seconds(SESSION_TIMER_TICK));
		timer_.async_wait(boost::bind(&ServerSession::on_timeout, self, boost::asio::placeholders::error));

		boost::asio::spawn(local_socket_.get_executor(), [this, self](boost::asio::yield_context yield)
		{
				if (!process_method(yield)) return;
				if (!process_request(yield)) return;
				if (!process_data(yield)) return;
		});
	}

	TCP_SOCKET& GetSocket()
	{
		return local_socket_;
	}


private:
	bool set_no_delay()
	{
		boost::system::error_code ec;
		local_socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
		if(ec)
		{
			LogDebug("set no delay error: %s", ec.message().c_str());
			return false;
		}
		return true;
	}

	void on_timeout(boost::system::error_code ec)
	{
		if(ec)
		{
			LogDebug("on_timeout error: %s", ec.message().c_str());
			return;
		}

		if(time(nullptr) - last_active_time_ > SESSION_TIMEOUT_TIME)
		{
			boost::system::error_code ec;
			local_socket_.cancel(ec);
			return;
		}

		auto self(shared_from_this());
		timer_.expires_from_now(boost::posix_time::seconds(SESSION_TIMER_TICK));
		timer_.async_wait(boost::bind(&ServerSession::on_timeout, self, boost::asio::placeholders::error));
	}

	bool process_method(boost::asio::yield_context yield)
	{
		boost::system::error_code ec;
		auto bytes_read = local_socket_.async_read_some(boost::asio::buffer(local_recv_buff_, 3), yield[ec]);
		if(ec)
		{
			LogDebug("process_method read error: %s", ec.message().c_str());
			return false;
		}

		auto bytes_write = async_write(local_socket_, boost::asio::buffer({0x05, 0x00}, 2), yield[ec]);
		if(ec)
		{
			LogDebug("process_method write error: %s", ec.message().c_str());
			return false;
		}
		return true;
	}

    bool open_remote_socket(std::string ip, uint16_t port) {
	    boost::system::error_code ec;
	    remote_ep_ = boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address(ip), port);
	    remote_socket_.open(remote_ep_.protocol(), ec);
	    if(ec)
	    {
            LogDebug("open_remote_socket error: %s", ec.message().c_str());
            return false;
	    }

	    boost::asio::ip::tcp::no_delay no_delay(true);
        remote_socket_.set_option(no_delay, ec);
        if(ec)
        {
            LogDebug("open_remote_socket no delay error: %s", ec.message().c_str());
            return false;
        }

        return true;
    }

    bool connect_to_remote(boost::asio::yield_context& context) {
        boost::system::error_code ec;
        remote_socket_.async_connect(remote_ep_, context[ec]);
        if(ec)
        {
            LogDebug("connect_to_remote error: %s", ec.message().c_str());
            return false;
        }

        return true;
    }

    bool process_request(boost::asio::yield_context yield)
	{
		boost::system::error_code ec;
		auto bytes_read = local_socket_.async_read_some(boost::asio::buffer(local_recv_buff_, RECV_BUFFER_SIZE), yield[ec]);
		if(ec)
		{
			LogDebug("process_request read error: %s", ec.message().c_str());
			return false;
		}

		auto req_hdr = (SOCKS5_REQ*)local_recv_buff_;
		if(req_hdr->version != 0x05)
		{
			LogDebug("process_request socks version failed:%u", req_hdr->version);
			return false;
		}
		if(req_hdr->command != 0x01)
		{
			if(req_hdr->command == 0x03)
			{
				auto self(this->shared_from_this());
				async_write(this->local_socket_,
					boost::asio::buffer({0x05, 0x00, 0x00, 0x01, 0x0A, 0xD3, 0x37, 0x02, 0x04, 0x38}, 10),
					[this, self](const boost::system::error_code& ec, const size_t& bytes_send) 
					{
						if (ec)
						{
							LogDebug("udp reply failed: %s", ec.message().c_str());
							return;
						}
					});

				boost::system::error_code ec;
				this->local_socket_.async_read_some(boost::asio::buffer(local_recv_buff_, RECV_BUFFER_SIZE), yield[ec]);
				LogDebug("process_request socks udp associate");
			} else {
				LogDebug("process_request socks not supported cmd:%u", req_hdr->command);
			}
			return false;
		}

        auto bytes_write = async_write(local_socket_, boost::asio::buffer({0x05, 0x00, 0x00, 0x01 ,0x00 ,0x00 ,0x00, 0x00, 0x10,0x10}, 10), yield[ec]);
        if(ec)
        {
            LogDebug("process_request reply failed: %s", ec.message().c_str());
            return false;
        }

        if(req_hdr->atyp == 0x01 || req_hdr->atyp == 0x04)
		{
			std::string ip;
			uint16_t port;

			if(!Socks5Helper::get_ip_port_from_request(req_hdr, ip, port))
			{
				LogDebug("parse ip port form request failed");
				return false;
			}

			if(!open_remote_socket(ip, port)) return false;
			if(!connect_to_remote(yield)) return false;

			return true;
		}
		else if(req_hdr->atyp == 0x03)
		{
			std::string domain;
			uint16_t port;

			if(!Socks5Helper::get_ip_port_from_domain(req_hdr, domain, port))
			{
				LogDebug("parse ip port form domain failed");
				return false;
			}

			if(resolver_)
			{
				boost::system::error_code ec;
				boost::asio::ip::tcp::resolver::query query{domain, std::to_string(port), boost::asio::ip::resolver_query_base::all_matching};
				LogDebug("resolving %s:%u", domain.c_str(), port);
				auto result = resolver_->async_resolve(query, yield[ec]);
				if(ec)
				{
					LogDebug("async resolve failed:%s", ec.message().c_str());
					return false;
				}
				LogDebug("dns resolved: %s:%u", result->endpoint().address().to_string().c_str(), result->endpoint().port());

				std::string proxy_ip;
				uint16_t proxy_port = 0;
				for(auto& it : result)
				{
					auto ep = it.endpoint();
					if(ep.address().is_v4())
					{
						proxy_ip = ep.address().to_string();
						proxy_port = ep.port();
						break;
					}
				}

				if(proxy_port == 0)
				{
					LogDebug("parse dns reply failed");
					return false;
				}

				Socks5Helper::build_request(local_recv_buff_, proxy_ip, proxy_port);

				if(!open_remote_socket(proxy_ip, proxy_port)) return false;
                if(!connect_to_remote(yield)) return false;

				return true;
			}
			else
			{
				return true;
			}
		}
		else
		{
			LogDebug("unknown type:%u", req_hdr->atyp);
			return false;
		}

		//never be reach
		return false;
	}

	bool process_data(boost::asio::yield_context yield)
	{
		auto self(shared_from_this());
		boost::asio::spawn(local_socket_.get_executor(), [this, self](boost::asio::yield_context yield)
			{
				boost::system::error_code ec;
				while(true)
				{
					auto bytes_read = read_from_remote(yield);
					if(bytes_read == 0)
					{
						local_socket_.cancel();
						return;
					}

					if(!send_to_local(bytes_read, yield))
					{
                        remote_socket_.cancel();
						return;
					}
				}
			});

		boost::system::error_code ec;
		while(true)
		{
			auto bytes_read = read_from_local(yield);
			if(bytes_read == 0)
			{
                remote_socket_.cancel();
                return false;
			}
			if(!send_to_remote(bytes_read, yield))
			{
				local_socket_.cancel();
				return false;
			}
		}
		return false;
	}

	bool send_to_local(uint64_t  bytes_read, boost::asio::yield_context yield)
	{
		boost::system::error_code ec;
		auto bytes_write = async_write(local_socket_, boost::asio::buffer(remote_recv_buff_, bytes_read), yield[ec]);
		if(ec)
		{
			LogDebug("send to local failed: %s", ec.message().c_str());
			return false;
		}
		last_active_time_ = time(nullptr);
		return true;
	}

	uint64_t read_from_local(boost::asio::yield_context yield)
	{
		boost::system::error_code ec;
		auto bytes_read = local_socket_.async_read_some(boost::asio::buffer(local_recv_buff_, RECV_BUFFER_SIZE), yield[ec]);
		if(ec)
		{
			LogDebug("read from local failed: %s", ec.message().c_str());
			return 0;
		}
		return bytes_read;
	}

    bool send_to_remote(uint64_t  bytes_read, boost::asio::yield_context yield)
    {
        boost::system::error_code ec;
        auto bytes_write = async_write(remote_socket_, boost::asio::buffer(local_recv_buff_, bytes_read), yield[ec]);
        if(ec)
        {
            LogDebug("send to local failed: %s", ec.message().c_str());
            return false;
        }
        last_active_time_ = time(nullptr);
        return true;
    }

    uint64_t read_from_remote(boost::asio::yield_context yield)
    {
        boost::system::error_code ec;
        auto bytes_read = remote_socket_.async_read_some(boost::asio::buffer(remote_recv_buff_, RECV_BUFFER_SIZE), yield[ec]);
        if(ec)
        {
            LogDebug("read from local failed: %s", ec.message().c_str());
	        return 0;
	    }
	    return bytes_read;
	}

private:
	unsigned char local_recv_buff_[RECV_BUFFER_SIZE];
	unsigned char remote_recv_buff_[RECV_BUFFER_SIZE];

	unsigned long session_id_;
	TCP_SOCKET local_socket_;
	TCP_SOCKET remote_socket_;

	boost::asio::ip::tcp::endpoint remote_ep_;

	std::unique_ptr<boost::asio::ip::tcp::resolver> resolver_;

	boost::asio::deadline_timer timer_;
	time_t last_active_time_;
};
