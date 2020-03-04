#include "socks5.h"

namespace tun2socks {

	AuthMethod::AuthMethod(SOCKS5METHOD method) : _method(method){}

	u_char AuthMethod::get_method() { return _method; }

	NoAuth::NoAuth() : AuthMethod(NO_AUTH) {}

	AUTHACTION NoAuth::next() { return SUCCESS; }

	std::unique_ptr<u_char[]> NoAuth::construct_send(size_t&) { return NULL; }

	std::unique_ptr<u_char[]> NoAuth::construct_receive(size_t&) { return NULL; }

	void NoAuth::sent() {}

	void NoAuth::received(const u_char*, size_t) {}

	PasswordAuth::PasswordAuth(const std::string& username, const std::string& password)
		: AuthMethod(USERNAME_PASSWORD), _username(username), _password(password), _next(SEND) {}

	PasswordAuth::PasswordAuth(const std::string&& username,const std::string&& password)
		: AuthMethod(USERNAME_PASSWORD), _username(std::move(username)), _password(std::move(password)), _next(SEND){}

	PasswordAuth::PasswordAuth(PasswordAuth&& o) : AuthMethod(o._method) {
		_next = o._next;
		o._next = SEND;
		_username = std::move(o._username);
		_password = std::move(o._password);
	}

	AUTHACTION PasswordAuth::next() {
		return _next;
	}

	std::unique_ptr<u_char[]> PasswordAuth::construct_send(size_t& len) {
		auto l_username = _username.size();
		auto l_password = _password.size();
		if (l_username > 255 || l_password > 255) {
			_next = FAILURE;
			return NULL;
		}
		len = 3 + l_username + l_password;
		std::unique_ptr<u_char[]> p(new u_char[len]);
		p[0] = '\x01';
		p[1] = (u_char)l_username;
		memcpy(p.get() + 2, _username.c_str(), l_username);
		p[2 + l_username] = (u_char)l_password;
		memcpy(p.get() + 3 + l_username, _password.c_str(), l_password);
		return p;
	}

	std::unique_ptr<u_char[]> PasswordAuth::construct_receive(size_t& len) {
		len = 2;
		return std::unique_ptr<u_char[]>(new u_char[len]);
	}

	void PasswordAuth::sent() {
		_next = RECV;
	}

	void PasswordAuth::received(const u_char* buffer, size_t len) {
		if (len != 2) {
			_next = FAILURE;
			return;
		}
		else {
			if (buffer[0] != '\x01' || buffer[1] != '\x00')
				_next = FAILURE;
			else
				_next = SUCCESS;
			return;
		}
	}

	void PasswordAuth::reset() {
		_next = SEND;
	}

	Socket5Client::Socket5Client(boost::asio::io_context& ctx, std::unique_ptr<AuthMethod>&& auth)
		: _socket(ctx)
		, _resolver(ctx)
		, _strand(ctx)
		,  _auth(std::move(auth))
		, _connected(false)
		, _closed(true)
		, _relayed(false)
		, _ctx(ctx)
		, _u_socket(ctx)
		, _u_strand(ctx)
		, tpcb(NULL)
        , spts(0) {

	}

	bool Socket5Client::connect(const std::string& proxy_ip, uint16_t proxy_port) {
		if (!_connected) {
			boost::asio::ip::tcp::resolver::query q(proxy_ip.c_str(), std::to_string(proxy_port).c_str());
			auto results = _resolver.resolve(q);
			auto method = _auth->get_method();
			if (results.size() == 0)
				return false;
			try {
				_socket.connect(*(results.begin()));
				_closed = false;
				u_char hello_msg[3] = { '\x05', '\x01', (u_char)method };
				_socket.send(boost::asio::buffer(hello_msg, 3));
				u_char recv_msg[2];
				_socket.receive(boost::asio::buffer(recv_msg, 2));
				if (recv_msg[1] != method)
					return false;
				auto act = _auth->next();
				while (act != SUCCESS && act != FAILURE) {
					if (act == SEND) {
						size_t len;
						auto p = _auth->construct_send(len);
						_socket.send(boost::asio::buffer(p.get(), len));
						_auth->sent();
					}
					else if (act == RECV) {
						size_t len;
						auto p = _auth->construct_receive(len);
						_socket.receive(boost::asio::buffer(p.get(), len));
						_auth->received(p.get(), len);
					}
				}
				if (act == SUCCESS)
					_connected = true;
				else if (act == FAILURE)
					_connected = false;
				return _connected;
			}
			catch (std::exception& e)
			{
				printf("socks5 connecting:%s\n", e.what());
				return false;
			}
		}
		else
			return _connected;
	}

	bool Socket5Client::establish(const std::string& domain, uint16_t port) {
		if (port > 65535)
			return false;
		auto request = _construct_request(COMMAND::CONNECT, domain, htons(port));
		u_char buffer[2000];
		size_t recved;
		try {
			_socket.send(boost::asio::buffer(request.data(), request.len()));
			recved = _socket.receive(boost::asio::buffer(buffer, 2000));
		}
		catch (std::exception& e) {
			printf("socks5 connect recv:%s\n", e.what());
			return false;
		}
		if (recved >= 7 && buffer[0] == '\x05' && buffer[1] == REPLY::SUCCEED)
			return true;
		else
			return false;
	}

	void Socket5Client::sendAsync(std::shared_ptr<u_char> buffer, size_t len, std::function<SendAsyncCallback> handler) {
		_socket.async_send(boost::asio::buffer(buffer.get(), len), _strand.wrap(handler));
	}

	void Socket5Client::receiveAsync(std::shared_ptr<u_char> buffer, size_t len, std::function<ReceiveAsyncCallback> handler) {
		_socket.async_receive(boost::asio::buffer(buffer.get(), len), _strand.wrap(handler));
	}

	void Socket5Client::close() {
        try {
            boost::system::error_code ec;
            _socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        }
        catch (std::exception&) {
        }
		_socket.close();
        do {
            int ndfs = _socket.native_handle();
            if (~0 != ndfs && 0 != ndfs) {
                shutdown(ndfs, SD_BOTH);
                closesocket(ndfs);
            }
        } while (0, 0);
	}

	void Socket5Client::closeAsync() {
		if (!_closed) {
			_closed = true;
			auto self = shared_from_this();
			_strand.post([this, self]() {
				close();
			});
		}
	}

    int Socket5Client::handle() {
        return _socket.native_handle();
    }

    bool Socket5Client::pollWrite() {
        bool available = false;
        do {
            int nfds = handle();
            if (~0 == nfds || 0 == nfds) {
                break;
            }

            struct fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(nfds, &writefds);

            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 0;
            if (select(nfds + 1, NULL, &writefds, NULL, &tv) <= 0) {
                break;
            }

            available = FD_ISSET(nfds, &writefds);
        } while (0, 0);
        return available;
    }

	Buffer<uint8_t> Socket5Client::_construct_request(COMMAND cmd,ADDRESS_TYPE type, const uint8_t* address, size_t address_len, uint16_t port) {
		Buffer<uint8_t> buffer(6 + address_len);
		buffer[0] = '\x05'; // version
		buffer[1] = cmd;
		buffer[2] = '\x00'; // reserved
		buffer[3] = type;
		memcpy(buffer.data() + 4, address, address_len);
		memcpy(buffer.data() + 4 + address_len, &port, 2);
		return buffer;
	}

	Buffer<uint8_t> Socket5Client::_construct_request(COMMAND cmd, uint32_t ip, uint16_t port) {
		return _construct_request(cmd, ADDRESS_TYPE::IPV4, (uint8_t*)(&ip), 4, port);
	}

	Buffer<uint8_t> Socket5Client::_construct_request(COMMAND cmd, const std::string& address, uint16_t port) {
		auto len = address.length();
		if (len > 0xFF)
			return Buffer<uint8_t>();
		auto new_address_bytes = (char)(len) + address;
		return _construct_request(cmd, ADDRESS_TYPE::DOMAINNAME, (uint8_t*)new_address_bytes.c_str(), new_address_bytes.length(), port);
	}

	Buffer<uint8_t> Socket5Client::_construct_udp_request(ADDRESS_TYPE type, const uint8_t* address, size_t address_length, uint16_t port, const uint8_t* data, size_t data_len) {
		Buffer<uint8_t> buffer(6 + address_length + data_len);
		buffer[0] = '\x00'; // reserved
		buffer[1] = '\x00'; // reserved
		buffer[2] = '\x00'; // no fragmentation
		buffer[3] = type;
		memcpy(buffer.data() + 4, address, address_length);
		memcpy(buffer.data() + 4 + address_length, &port, 2);
		memcpy(buffer.data() + 6 + address_length, data, data_len);
		return buffer;
	}
}