#include <cstring>
#include <memory>
#include <cstdio>
#include <thread>
#include <string>
#include <memory>
#include <cctype>
#include <array>
#include <deque>
#include <sstream>
#include <mutex>
#include <unordered_map>
#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/bind.hpp>

#include "lwip/timeouts.h"
#include "lwip/priv/tcp_priv.h"

#include "tun2socks.h"
#include "lwipstack.h"
#include "socks5.h"
#include "tuntap.h"

#define MAX_DOMAINNAME_LEN  255
#define DNS_PORT            53
#define DNS_TYPE_SIZE       2
#define DNS_CLASS_SIZE      2
#define DNS_TTL_SIZE        4
#define DNS_DATALEN_SIZE    2
#define DNS_TYPE_A          0x0001 // 1 a host address
#define DNS_TYPE_CNAME      0x0005 // 5 the canonical name for an alias
#define DNS_PACKET_MAX_SIZE (sizeof(DNSHeader) + MAX_DOMAINNAME_LEN + DNS_TYPE_SIZE + DNS_CLASS_SIZE)

struct DNSHeader
{
    uint16_t			usTransID;			// 标识符
    uint16_t			usFlags;			// 各种标志位
    uint16_t			usQuestionCount;	// Question字段个数 
    uint16_t			usAnswerCount;		// Answer字段个数
    uint16_t			usAuthorityCount;	// Authority字段个数
    uint16_t			usAdditionalCount;	// Additional字段个数
};

using namespace tun2socks;

static HANDLE g_tap_handle = INVALID_HANDLE_VALUE;
static bool to_read = true;
static const TUN2SOCKSConfig* g_config;
static std::atomic<int> g_addr2seeds;
static std::mutex g_syncdns_metex;
static std::unordered_map<u32_t, std::string> g_addr2host;
static std::unordered_map<std::string, u32_t> g_host2addr;

u32_t tun2socks_dns_alloc(const std::string& hostname) {
    g_syncdns_metex.lock();

    u32_t address = 0;
    std::unordered_map<std::string, u32_t>::iterator iter = g_host2addr.find(hostname);
    if (iter != g_host2addr.end()) {
        address = iter->second;
        goto RETN_0;
    }

    if (0 == g_addr2seeds) {
        g_addr2seeds = ntohl(inet_addr("198.18.0.0"));
    }

    address = g_addr2seeds++;
    while (0 == *(char*)&address) {
        address = g_addr2seeds++;
    }

    g_host2addr.insert(std::make_pair(hostname, address));
    g_addr2host.insert(std::make_pair(address, hostname));

RETN_0:
    g_syncdns_metex.unlock();
    return address;
}

bool tun2socks_dns_resolve(u32_t address, std::string& hostname) {
    hostname = "";

    g_syncdns_metex.lock();

    bool success = false;
    std::unordered_map<u32_t, std::string>::iterator iter = g_addr2host.find(address);
    if (iter != g_addr2host.end()) {
        success |= true;
        hostname = iter->second;
    }

    g_syncdns_metex.unlock();
    return success;
}

std::unique_ptr<AuthMethod> get_auth_method(const BaseAuth* auth) {
    auto method = auth->method;
    if (method == SOCKS5METHOD::NO_AUTH)
        return std::make_unique<NoAuth>();
    else if (method == SOCKS5METHOD::USERNAME_PASSWORD) {
        auto pw_auth = (PSOCKS5UsernamePassword)auth;
        std::string username(pw_auth->username, pw_auth->username_length);
        std::string password(pw_auth->password, pw_auth->password_length);
        return std::make_unique<PasswordAuth>(std::move(username), std::move(password));
    }
    else
        return NULL;
}

void close_on_context(const std::shared_ptr<Socket5Client>& socket) {
    if (socket != NULL) {
        tcp_pcb* tpcb = socket->tpcb.exchange(NULL);
        if (tpcb != NULL) {
            LWIPStack::lwip_tcp_receive(tpcb, NULL);
            LWIPStack::getInstance().lwip_tcp_close(tpcb);
        }
        socket->close();
        socket->srcb = NULL;
        socket->srbf = NULL;
    }
}

int tun2socks_socks5_proxy_connect_impl(std::shared_ptr<Socket5Client>& context, struct tcp_pcb *tpcb) {
    if (context == NULL || tpcb == NULL) {
        return ERR_RST;
    }

    std::string proxy_ip(g_config->socks5_address, g_config->socks5_address_length);
    if (!context->connect(proxy_ip, g_config->socks5_port)) {
        close_on_context(context);
        return ERR_ABRT;
    }

    std::string hostname = "";
    u8_t* hostaddr = NULL;
    int port = 0;

    bool domain = tun2socks_dns_resolve(ntohl(tpcb->local_ip.addr), hostname);
    if (!domain)
        hostname = get_address_string(tpcb->local_ip.addr);
    port = tpcb->local_port;
    hostaddr = (u8_t*)&tpcb->local_ip.addr;

    char connect_log[2048];
    sprintf(connect_log, "Create Tunnel %s(%d, %d, %d, %d):%d -> %s:%d .tcp",
        hostname.data(),
        hostaddr[0],
        hostaddr[1],
        hostaddr[2],
        hostaddr[3],
        port,
        g_config->socks5_address, g_config->socks5_port);
    printf("%s\n", connect_log);

    if (!context->establish(hostname, port)) {
        close_on_context(context);
        return ERR_ABRT; // ERR_RST
    }
    return ERR_OK;
}

int tun2socks_socks5_proxy_connect(std::shared_ptr<Socket5Client>& context, struct tcp_pcb *tpcb) {
    __try {
        return tun2socks_socks5_proxy_connect_impl(context, tpcb);
    }
    __except (1) {
        close_on_context(context);
        return ERR_ABRT;
    }
}

err_t tun2socks_process_tcp_on_recv(std::shared_ptr<Socket5Client> context, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    if (tpcb == NULL)
        return ERR_VAL;
    if (err != ERR_OK || p == NULL || 0 == p->len) { // p == NULL indicates EOF
        close_on_context(context);
        return ERR_OK;
    }
    auto buffer = std::shared_ptr<u_char>((u_char*)mem_malloc(p->tot_len), [](u_char* p) {
        if (p)
            mem_free(p);
    });
    auto tp = buffer.get();
    pbuf_copy_partial(p, tp, p->tot_len, 0);
    context->sendAsync(buffer, p->tot_len, [context](const boost::system::error_code& err, std::size_t sz) {
        if (err.failed()) {
            close_on_context(context);
            return;
        }
    });
    LWIPStack::getInstance().lwip_tcp_recved(tpcb, p->tot_len);
    return ERR_OK;
}

std::shared_ptr<Socket5Client> tun2socks_create_context(void *arg, tcp_pcb* tpcb) {
    if (arg == NULL || tpcb == NULL) {
        return NULL;
    }
    auto ioctx = (boost::asio::io_context*)arg;
    auto context = std::make_shared<Socket5Client>(*ioctx, std::move(get_auth_method(g_config->socks5_auth)));
    context->tpcb = tpcb;
    return context;
}

err_t tun2socks_process_tcp_on_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    if (err != ERR_OK || newpcb == NULL)
        return ERR_VAL;
    std::shared_ptr<Socket5Client> context = tun2socks_create_context(arg, newpcb);
    if (context == NULL)
        return ERR_RST;
    if (ERR_OK != (err = tun2socks_socks5_proxy_connect(context, context->tpcb.load())))
        return ERR_OK;
    LWIPStack::lwip_tcp_receive(newpcb, [context](void* arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) mutable {
        return tun2socks_process_tcp_on_recv(context, context->tpcb.load(), p, err);
    });
    context->srbf = std::shared_ptr<u_char>((u_char*)mem_malloc(TCP_MSS), [](u_char* p) {
        if (p)
            mem_free(p);
    });
    context->srcb = std::function<Socket5Client::ReceiveAsyncCallback>(
        [context](const boost::system::error_code& err, std::size_t sz) mutable {
        tcp_pcb *tpcb = context->tpcb.load();
        if (tpcb == NULL || err.failed()) {
            close_on_context(context);
            return;
        }
        else if (sz > 0) {
            context->spts = GetTickCount();
        }
        std::shared_ptr<void> bf(mem_malloc(sz), [](void* p) {
            if (p)
                mem_free(p);
        });
        // it seems that we don't need extra buffer because the original won't be modified before the next call to receives async.
        memcpy(bf.get(), context->srbf.get(), sz);
        LWIPStack::getInstance().strand_tcp_write(tpcb, bf, (u16_t)sz, TCP_WRITE_FLAG_COPY,
            [context](err_t err) mutable {
            tcp_pcb *tpcb = context->tpcb.load();
            if (err != ERR_OK || tpcb == NULL)
                close_on_context(context);
            else {
                LWIPStack::getInstance().lwip_tcp_output(tpcb);
                int sent = std::min<int>(TCP_MSS,
                    LWIPStack::getInstance().lwip_tcp_sndbuf(tpcb));
                do {
                    uint32_t ticks = GetTickCount();
                    if (sent <= 0) {
                        if ((ticks - context->spts) >= 100) {
                            close_on_context(context);
                            break;
                        }
                    }
                    else {
                        context->spts = ticks;
                    }
                    context->receiveAsync(context->srbf, sent, context->srcb);
                } while (0, 0);
            }
        });
        if (err) {
            close_on_context(context);
            return;
        }
    });
    context->receiveAsync(context->srbf, TCP_MSS, context->srcb);
    return ERR_OK;
}

int tun2socks_dns_fill_hostname(const char* hostname, unsigned int hostname_len, char*& payload) {
    char* current_payload_pos = payload;
    {
        char domain[MAX_PATH] = "";
        strncat(domain, hostname, hostname_len);

        char* encoding_bytes = strtok(domain, ".");
        while (NULL != encoding_bytes)
        {
            int max_encoding_bytes = (int)strlen(encoding_bytes);
            if (max_encoding_bytes > 0xc0)
            {
                max_encoding_bytes = 0xc0;
            }

            *payload++ = (char)max_encoding_bytes;
            memcpy(payload, encoding_bytes, max_encoding_bytes);
            payload += max_encoding_bytes;

            encoding_bytes = strtok(NULL, ".");
        }
        *payload++ = '\x0';
    }
    return (int)(payload - current_payload_pos);
}

static void tun2socks_dns_listen() {
    auto fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    struct sockaddr_in bindaddr;
    memset(&bindaddr, 0, sizeof(bindaddr));

    bindaddr.sin_family = AF_INET;
    bindaddr.sin_port = ntohs(53);
    bindaddr.sin_addr.s_addr = 0;

    bind(fd, (struct sockaddr*)&bindaddr, sizeof(bindaddr));
    while (1) {
        struct sockaddr_in fromaddr;
        memset(&fromaddr, 0, sizeof(fromaddr));

        fromaddr.sin_family = AF_INET;
        fromaddr.sin_port = 0;
        fromaddr.sin_addr.s_addr = 0;

        char sz[1500];
        int fromaddr_len = sizeof(fromaddr);
        int buffer_len = recvfrom(fd, sz, sizeof(sz), 0, (struct sockaddr*)&fromaddr, &fromaddr_len);
        if (buffer_len > 0) {
            struct pbuf sp;
            memset(&sp, 0, sizeof(sp));

            sp.payload = sz;
            sp.len = sizeof(sz);
            sp.tot_len = sizeof(sz);

            // 设当前收取到的UDP帧长度不足DNS协议头的长度则返回假。
            if (sp.len < sizeof(DNSHeader)) {
                continue;
            }

            auto request = (DNSHeader*)sp.payload;
            request->usTransID = htons(request->usTransID);
            request->usFlags = htons(request->usFlags);
            request->usQuestionCount = htons(request->usQuestionCount);
            request->usAnswerCount = htons(request->usAnswerCount);
            request->usAuthorityCount = htons(request->usAuthorityCount);
            request->usAdditionalCount = htons(request->usAdditionalCount);

            // 不支持除A4地址解析以外的任何DNS协议（不过按照INETv4以太网卡也不可能出现A6地址析请求）
            // A6根本不需要虚拟网卡链路层网络远程桥接，先天的scope机制就足以抵御外部入侵的防火长城。
            if (0 == (request->usFlags & 0x0100)) {
                continue;
            }

            // 若客户端查询问题是空直接不给客户端应答就让它卡在那里用户态（RING3）通过系统DNS服务进行解析不太可能是请求空答案。
            // 虽然这会造成系统内核使用处于等待数据包应答的状态；句柄资源无法释放但是已经不太重要了；底层也不太好操作把上层
            // 搞崩溃，搞太猛系统就蓝屏了；当然倒是可以强制把目标进程的内存全部设置为WPOFF让它死的难看至极。
            // 不过这么搞了就必须要在RING0做防护了；万一逗逼跑来强制从内核卸载怎么办，一定要让这些人付出代价必须蓝屏死机。
            // 虽然这并不是没有办法。对付小小的用户态程式方法真的太多，搞死它只要你想轻而易举；毕竟应用层都是最低贱的程式。
            if (0 == request->usQuestionCount) {
                continue;
            }

            // 应答客户端查询DNS的请求，DNS地址污染并且强制劫持到分配的保留地址段假IP。
            auto payload = (char*)(request + 1);

            // 从DNS协议流中获取需要解析的域名。
            std::string hostname = "";
            while (*payload) {
                u8_t len = (u8_t)*payload++;
                if (!hostname.empty()) {
                    hostname += ".";
                }
                hostname += std::string(payload, len);
                payload += len;
            }
            payload++; // 查询字符串的最后一个字节是\x0中止符号。

                       // 问题所需求的查询类型。
            u16_t usQType = ntohs(*(u16_t*)payload);
            payload += sizeof(u16_t);

            // 问题所需求的查询类别。
            u16_t usQClass = ntohs(*(u16_t*)payload);
            payload += sizeof(u16_t);

            // 构建DNS应答数据报文。
            std::shared_ptr<pbuf> p(
                pbuf_alloc(pbuf_layer::PBUF_TRANSPORT, 1500, pbuf_type::PBUF_RAM),
                [](pbuf* _p) {
                pbuf_free(_p);
            });

            payload = (char*)p->payload;
            p->tot_len = 0;
            p->len = 0;

            // 构建虚假DNS服务响应头。
            auto response = (DNSHeader*)payload;
            response->usTransID = htons(request->usTransID); // usFlags & 0xfb7f -- RFC1035 4.1.1(Header section format)
            response->usFlags = htons(0x8180);
            response->usAuthorityCount = 0;
            response->usAdditionalCount = 0;
            response->usAnswerCount = 0;
            response->usQuestionCount = htons(1);

            payload += sizeof(DNSHeader);
            tun2socks_dns_fill_hostname(hostname.data(), hostname.length(), payload);

            *(u16_t*)payload = ntohs(usQType);
            payload += sizeof(u16_t);
            *(u16_t*)payload = ntohs(usQClass);
            payload += sizeof(u16_t);

            if (usQClass & 1) {
#pragma pack(push, 1)
                tun2socks_dns_fill_hostname(hostname.data(), hostname.length(), payload);

                struct Answer
                {
                    u16_t usQType;
                    u16_t usQClass;
                    u32_t uTTL;
                    u16_t usRDLength;
                };

                Answer* answer = (Answer*)payload;
                answer->usQType = ntohs(usQType);
                answer->usQClass = ntohs(usQClass);
                answer->uTTL = ntohl(0x7f);
                answer->usRDLength = 0;

                if (usQType & 1) {
                    answer->usQType = ntohs(1);

                    struct AnswerAddress {
                        Answer stAnswer;
                        u32_t dwAddress;
                    };

                    AnswerAddress* rrA = (AnswerAddress*)answer;
                    answer->usRDLength = ntohs(4);
                    rrA->dwAddress = ntohl(tun2socks_dns_alloc(hostname));

                    payload += sizeof(AnswerAddress);
                    response->usAnswerCount = ntohs(1);

                    printf("NS Lookup[A, IN]: %s hijacked -> %s\n", hostname.data(), get_address_string(rrA->dwAddress).data());
                }
                else if (usQType & 5) {
                    answer->usQType = ntohs(5);

                    payload += sizeof(Answer);

                    int resouces_data_length = tun2socks_dns_fill_hostname(hostname.data(), hostname.length(), payload);
                    answer->usRDLength = ntohs(resouces_data_length);

                    response->usAnswerCount = ntohs(1);
                }
#pragma pack(pop)
            }

            // 设置当前应答客户的流的总长度。
            p->tot_len = p->len = (payload - (char*)p->payload);
            sendto(fd, (char*)p->payload, p->len, 0, (struct sockaddr*)&fromaddr, fromaddr_len);
        }
    }
}

void tun2socks_start(const TUN2SOCKSConfig* config) {
    static boost::asio::io_context ioctx;
    static boost::asio::io_context::work work(ioctx);
    g_config = config;
    auto tctx = std::make_shared<TUNDevice>(ioctx, *(config->adapter));
    LWIPStack::getInstance().init(ioctx, config);
    auto t_pcb = LWIPStack::tcp_listen_any();
    auto u_pcb = LWIPStack::udp_listen_any();
    LWIPStack::lwip_tcp_arg(t_pcb, (void*)(&ioctx));
    LWIPStack::lwip_tcp_accept(t_pcb, tun2socks_process_tcp_on_accept);
    LWIPStack::getInstance().set_output_function([tctx](struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)->err_t {
        auto buffer = std::make_unique<u_char[]>(p->tot_len);
        pbuf_copy_partial(p, buffer.get(), p->tot_len, 0);
        tctx->do_write(std::move(buffer), p->tot_len, NULL, NULL);
        return ERR_OK;
    });
    tctx->tap_set_address();
    tctx->start_read([](std::shared_ptr<Request> q) {
        LWIPStack::getInstance().strand_ip_input(q->buf.get(), [q](err_t err) {}); 
    },
    [](const boost::system::error_code& err) {});
    std::thread(tun2socks_dns_listen).detach();
    std::thread([]() { ioctx.run(); }).detach();
    std::thread([]() {
        while (1) {
            ioctx.post([] {
                sys_check_timeouts();
            });
            timeBeginPeriod(1);
            Sleep(1);
            timeEndPeriod(1);
        }
    }).detach();
}

template<class T>
PTUN2SOCKSConfig make_config(
    const TUNAdapter* adapter,
    const char* address, size_t address_length,
    uint16_t port,
    uint32_t timeout,
    const T* auth
) {
    if (address_length > 256)
        return NULL;
    auto config = new TUN2SOCKSConfig();
    config->adapter = new TUNAdapter();
    memcpy(config->adapter, adapter, sizeof(decltype(*adapter)));
    memcpy(config->socks5_address, address, address_length);
    config->socks5_address_length = address_length;
    config->socks5_port = port;
    config->socks5_auth = (PBaseAuth)new T(*auth);
    return config;
}

PTUN2SOCKSConfig make_config_with_socks5_no_auth(
    const TUNAdapter* adapter,
    const char* address, size_t address_length,
    uint16_t port,
    uint32_t timeout,
    const SOCKS5NoAuth* auth
) {
    return make_config(adapter, address, address_length, port, timeout, auth);
}

PTUN2SOCKSConfig make_config_with_socks5_password_auth(
    const TUNAdapter* adapter,
    const char* address, size_t address_length,
    uint16_t port,
    uint32_t timeout,
    const SOCKS5UsernamePassword* auth
) {
    if (auth->username_length >= 256 || auth->password_length >= 256)
        return NULL;
    return make_config(adapter, address, address_length, port, timeout, auth);
}

void delete_config(PTUN2SOCKSConfig config) {
    if (config != NULL) {
        if (config->adapter != NULL)
            delete config->adapter;
        if (config->socks5_auth != NULL)
            delete config->socks5_auth;
        delete config;
    }
    g_config = NULL;
}