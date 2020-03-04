#pragma once

#include <lwip/tcp.h>
#include <lwip/netif.h>
#include <lwip/init.h>
#include <lwip/udp.h>
#include <lwip/sys.h>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include <set>
#include <memory>
#include <thread>
#include <time.h>
#include <timeapi.h>

#include "tun2socks.h"
#include "arch/sys_arch.h"

namespace tun2socks {
	class LWIPStack {
	public:
		inline static LWIPStack& getInstance() {
			static LWIPStack _stack;
			return _stack;
		}

		inline static tcp_pcb* lwip_tcp_new() {
			return tcp_new();
		}

		inline static udp_pcb* lwip_udp_new() {
			return udp_new();
		}

		inline static err_t lwip_tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port) {
			return tcp_bind(pcb, ipaddr, port);
		}

		inline static err_t lwip_udp_bind(struct udp_pcb* pcb, const ip_addr_t *ipaddr, u16_t port) {
			return udp_bind(pcb, ipaddr, port);
		}

		inline static tcp_pcb* lwip_tcp_listen(tcp_pcb* pcb) {
			return tcp_listen(pcb);
		}

		inline static err_t lwip_udp_connect(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port) {
			return udp_connect(pcb, ipaddr, port);
		}

		inline static void lwip_tcp_arg(tcp_pcb* pcb, void* arg) {
			return tcp_arg(pcb, arg);
		}

        inline static void lwip_tcp_receive(struct tcp_pcb* pcb, std::function<std::remove_pointer<tcp_recv_fn>::type> receive) {
            if (receive == NULL) {
                tcp_err(pcb, NULL);
            }
            else {
                tcp_err(pcb, [pcb, receive](void *arg, err_t err) {
                    receive(arg, pcb, NULL, err);
                });
            }
            return tcp_recv(pcb, receive);
        }

		inline static void lwip_tcp_accept(struct tcp_pcb* pcb, tcp_accept_fn accept) {
			return tcp_accept(pcb, accept);
		}

		inline static void lwip_tcp_recved(struct tcp_pcb* pcb, u16_t len) {
			return tcp_recved(pcb, len);
		}

		inline static void lwip_udp_timeout(struct udp_pcb* pcb, std::function<std::remove_pointer_t<udp_timeout_fn>> timeout_fn) {
			return udp_timeout(pcb, timeout_fn);
		}

		inline static void lwip_udp_create(std::function<std::remove_pointer_t<udp_crt_fn>> create_fn) {
			return udp_create(create_fn);
		}

		inline static void lwip_udp_set_timeout(udp_pcb* pcb, u32_t timeout) {
			return udp_set_timeout(pcb, timeout);
		}

		inline static void lwip_udp_recv(struct udp_pcb *pcb, std::function<std::remove_pointer<udp_recv_fn>::type> recv) {
			return udp_recv(pcb, recv, NULL);
		}

		inline static void lwip_udp_remove(struct udp_pcb* pcb) {
			return udp_remove(pcb);
		}

		inline static tcp_pcb* tcp_listen_any() {
			auto pcb = lwip_tcp_new();
			auto any = ip_addr_any;
			lwip_tcp_bind(pcb, &any, 0);
			return lwip_tcp_listen(pcb);
		}

		inline static udp_pcb* udp_listen_any() {
			auto pcb = lwip_udp_new();
			auto any = ip_addr_any;
			lwip_udp_bind(pcb, &any, 0);
			return pcb;
		}

		inline static err_t lwip_tcp_write(struct tcp_pcb *pcb, std::shared_ptr<void> arg, u16_t len, u8_t apiflags) {
			void* payload = arg.get();
			return tcp_write(pcb, payload, len, apiflags);
		}

		inline static err_t lwip_udp_send(struct udp_pcb *pcb, struct pbuf *p) {
			return udp_send(pcb, p);
		}

		inline static u32_t lwip_tcp_sndbuf(tcp_pcb* pcb) {
			return tcp_sndbuf(pcb);
		}

		inline static err_t lwip_tcp_output(tcp_pcb* pcb) {
			return tcp_output(pcb);
		}

		inline static err_t lwip_tcp_close(tcp_pcb* pcb) {
            err_t err = tcp_shutdown(pcb, 1, 1) | tcp_close(pcb);
            return err;
		}

		inline void init(boost::asio::io_context& ctx, const TUN2SOCKSConfig* config) {
			lwip_init();
			_strand = new boost::asio::io_context::strand(ctx);
            netif_default = netif_list;
			_loopback = netif_list;
		}

		inline void strand_tcp_write(struct tcp_pcb *pcb, std::shared_ptr<void> arg, u16_t len, u8_t apiflags, std::function<void(err_t)> cb) {
			_strand->post([=]() {
				auto err = LWIPStack::lwip_tcp_write(pcb, arg, len, apiflags);
				if (cb != NULL)
					cb(err);
			});
		}

        inline void strand_post(std::function<void()> cb) {
            _strand->post([cb]() {
                if (cb != NULL)
                    cb();
            });
        }

		inline void strand_ip_input(pbuf* p, std::function<void(err_t)> cb) {
			_strand->post([=]() {
				auto err = _loopback->input(p, _loopback);
				if (cb != NULL)
					cb(err);
			});
		}

		inline void strand_tcp_close(tcp_pcb* pcb, std::function<void(err_t)> cb) {
			_strand->post([=]() {
				auto err = lwip_tcp_close(pcb);
				if (cb != NULL)
					cb(err);
			});
		}

		inline void strand_tcp_output(tcp_pcb* pcb, std::function<void(err_t)> cb) {
			_strand->post([=]() {
				auto err = lwip_tcp_output(pcb);
				if (cb != NULL)
					cb(err);
			});
		}

		inline void strand_udp_remove(udp_pcb* pcb) {
			_strand->post([=]() {
				LWIPStack::lwip_udp_remove(pcb);
			});
		}

		inline void strand_tcp_recved(tcp_pcb* pcb, u16_t len) {
			_strand->post([=]() {
				LWIPStack::lwip_tcp_recved(pcb, len);
			});
		}

		inline void strand_udp_send(udp_pcb* pcb, std::shared_ptr<pbuf> p, std::function<void(err_t)> cb) {
			_strand->post([=]() {
				auto err = LWIPStack::lwip_udp_send(pcb, p.get());
				if (cb != NULL)
					cb(err);
			});
		}

		inline void set_output_function(std::function<std::remove_pointer<netif_output_fn>::type> f) {
			_loopback->output = f;
		}

		inline ~LWIPStack() {
			if (_strand != NULL)
				delete _strand;
		}

	private:
        LWIPStack() : _strand(NULL), _loopback(NULL) {}

	private:
		boost::asio::io_context::strand*	_strand;
		netif*								_loopback;
	};
}