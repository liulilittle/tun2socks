#pragma once

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <lwipstack.h>
#include <tun2socks.h>
#include <cstdio>
#include <cstring> // for memcpy
#include <map>

namespace tun2socks {
	inline std::string get_address_string(u32_t ip) {
		char buf[160];
		snprintf(buf, 16, "%d.%d.%d.%d", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
		return std::string(buf);
	}

	enum TUNSTATE {
		CLOSE = 0,
		OPEN,
		OPEN_FAILURE
	};

#ifdef __WIN32__
	struct Request {
		OVERLAPPED              overlapped;
		DWORD                   transfered;
        std::shared_ptr<pbuf>   buf;
	};
#endif
#ifdef __LINUX__
	struct Request{
	    pbuf* buf;
	    int transfered;
	};
#endif

	class TUNDevice {
		
	public:
		TUNDevice(boost::asio::io_context&, const TUNAdapter&);

		int tap_set_address();

		void start_read(const std::function<void(std::shared_ptr<Request>)>&, const std::function<void(const boost::system::error_code&)>&);

		void do_write(std::unique_ptr<u_char[]>&&, size_t, std::function<void()>, std::function<void(const boost::system::error_code&)>);


	private:
		TUNHANDLE _tun_handle;
		TUNAdapter _adapter;
		boost::asio::io_context& _ctx;
#ifdef __LINUX__
		boost::asio::posix::stream_descriptor _stream;
#endif
	};
}