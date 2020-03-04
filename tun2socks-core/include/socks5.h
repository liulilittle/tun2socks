#pragma once

#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <atomic>
#include <memory>
#include <cstdint>

#include "socks5_auth.h"

struct tcp_pcb;
struct udp_pcb;

namespace tun2socks {

	enum AUTHACTION {
		SEND = 0,
		RECV,
		SUCCESS,
		FAILURE
	};

	//TODO: Use std::array instead.
	template<typename T>
	class Buffer {
	public:
		Buffer() :_data(nullptr), _len(0) {}
		Buffer(size_t len) : _data(new T[len]), _len(len) {}
		Buffer(std::unique_ptr<T[]>&& other, size_t len) : _data(std::move(other)), _len(len) {}
		Buffer(Buffer&& ano) {
			_data = std::move(ano._data);
			_len = ano._len;
			ano._len = 0;
		}
		inline T* data() { return _data.get(); }
		inline size_t len() { return _len; }
		inline bool empty() { return _len == 0; }
		T& operator[](size_t index) { return _data.get()[index]; }
		~Buffer() {}
	private:
		Buffer(const Buffer&) {}
		Buffer& operator=(const Buffer&) {}
	private:
		std::unique_ptr<T[]> _data;
		size_t _len;
	};

	class AuthMethod {
	protected:
		AuthMethod(SOCKS5METHOD);
		SOCKS5METHOD _method;
	public:
		u_char get_method();
		virtual std::unique_ptr<u_char[]> construct_send(size_t&) = 0;
		virtual void sent() = 0;
		virtual std::unique_ptr<u_char[]> construct_receive(size_t&) = 0;
		virtual void received(const u_char*, size_t) = 0;
		virtual AUTHACTION next() = 0;
	};


	class NoAuth : public AuthMethod {
	public:
		NoAuth();
		virtual AUTHACTION next();
		virtual std::unique_ptr<u_char[]> construct_send(size_t&);
		virtual std::unique_ptr<u_char[]> construct_receive(size_t&);
		virtual void sent();
		virtual void received(const u_char*, size_t);
	};

	class PasswordAuth : public AuthMethod {
	public:
		PasswordAuth(const std::string&, const std::string&);
		PasswordAuth(const std::string&&, const std::string&&);
		PasswordAuth(PasswordAuth&&);
		virtual AUTHACTION next();
		virtual std::unique_ptr<u_char[]> construct_send(size_t&);
		virtual std::unique_ptr<u_char[]> construct_receive(size_t&);
		virtual void sent();
		virtual void received(const u_char*, size_t);
		void reset();
	private:
		AUTHACTION _next;
		std::string _username;
		std::string _password;
	};

	class Socket5Client : public std::enable_shared_from_this<Socket5Client> {

	private:
		enum COMMAND :uint8_t {
			CONNECT = 1,
			BIND = 2,
			UDP_ASSOCIATE = 3
		};

		enum ADDRESS_TYPE : uint8_t {
			IPV4 = 1,
			DOMAINNAME = 3,
			IPV6 = 4
		};

		enum REPLY : uint8_t {
			SUCCEED = 0,
			GENERAL_SERVER_FAILURE = 1,
			CONNECTION_NOT_ALLOWED = 2,
			NETWORK_UNREACHABLE = 3,
			HOST_UNREACHABLE = 4,
			CONNECTION_REFUSED = 5,
			TTL_EXPIRED = 6,
			COMMAND_NOT_SUPPORTED = 7,
			ADDRESS_TYPE_NOT_SUPPORTED = 8
		};

	public:
		typedef void SendAsyncCallback(const boost::system::error_code&, std::size_t);
		typedef void ReceiveAsyncCallback(const boost::system::error_code&, std::size_t);

		Socket5Client(boost::asio::io_context&, std::unique_ptr<AuthMethod>&&);
		bool connect(const std::string&, uint16_t);
		bool associateUDP(bool domain, void* dst_ip, int dst_iplen, uint16_t);
		bool establish(const std::string&, uint16_t);
		template<int BUFFER_SIZE>
		void async_sendto(std::shared_ptr<std::array<u_char, BUFFER_SIZE>> buffer, uint32_t dst_ip, uint16_t port, std::function<SendAsyncCallback> handler) {
			auto buf = std::make_shared<Buffer<u_char>>(std::move(_construct_udp_request(dst_ip, port, buffer->data(), buffer->size())));
			_u_socket.async_send_to(
				boost::asio::buffer(buf->data(), buf->len()),
				_u_bnd,
				_u_strand.wrap([buf, handler](const boost::system::error_code& err, std::size_t len) { handler(err, len); }));
		}
		void async_sendto(std::shared_ptr<u_char>, size_t, uint32_t, uint16_t, std::function<SendAsyncCallback>);
		void async_sendto(std::shared_ptr<u_char>, size_t, const std::string&, uint16_t, std::function<SendAsyncCallback>);
		void async_recvfrom(std::shared_ptr<u_char>, size_t, std::function<ReceiveAsyncCallback>); // depreciated
		template<int BUFFER_SIZE>
		void async_recvfrom(std::shared_ptr<std::array<u_char, BUFFER_SIZE>> buf, std::function<ReceiveAsyncCallback> handler) {
			_u_socket.async_receive_from(boost::asio::buffer(*buf), _u_bnd, handler);
		} // depreciated
		void async_recvfrom(u_char*, size_t, std::function<ReceiveAsyncCallback>);
		void sendAsync(std::shared_ptr<u_char>, size_t, std::function<SendAsyncCallback>);
		void receiveAsync(std::shared_ptr<u_char>, size_t, std::function<ReceiveAsyncCallback>);
		void close();
		void udp_close();
		void closeAsync();
		void async_udp_close();
        int handle();
        bool pollWrite();

	private:
		Buffer<uint8_t> _construct_request(COMMAND, ADDRESS_TYPE, const uint8_t*, size_t, uint16_t);
		Buffer<uint8_t> _construct_request(COMMAND, uint32_t, uint16_t);
		Buffer<uint8_t> _construct_request(COMMAND, const std::string&, uint16_t);
		Buffer<uint8_t> _construct_udp_request(ADDRESS_TYPE, const uint8_t*, size_t, uint16_t, const uint8_t*, size_t);
		Buffer<uint8_t> _construct_udp_request(uint32_t, uint16_t, const uint8_t*, size_t);
		Buffer<uint8_t> _construct_udp_request(const std::string&, uint16_t, const uint8_t*, size_t);

	private:
		std::unique_ptr<AuthMethod>			                _auth;
		boost::asio::ip::tcp::socket		                _socket;
		boost::asio::ip::udp::socket		                _u_socket;
		boost::asio::ip::tcp::resolver		                _resolver;
		boost::asio::io_service::strand		                _strand;
		boost::asio::io_service::strand		                _u_strand;
		boost::asio::io_context&			                _ctx;
		bool _connected;
		bool _closed;
		bool _relayed;
		boost::asio::ip::udp::endpoint		                _u_bnd;

	public:
		mutable std::atomic<tcp_pcb*>		                tpcb;
        mutable uint32_t                                    spts;
        mutable std::function<Socket5Client::ReceiveAsyncCallback>   srcb;
        mutable std::shared_ptr<u_char>                     srbf;
	};
}