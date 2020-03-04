#include <stdio.h>
#include <cstring>

#ifdef __LINUX__
#include <arpa/inet.h>
#endif

#include "netifc.h"
#include "tun2socks.h"

#pragma comment(lib, "WinMM.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "WS2_32.lib")

static const char* tap_ip = "10.0.0.1";
static const char* tap_network = "10.0.0.0";
static const char* tap_mask = "255.255.255.0";

static const char* socks_server = "127.0.0.1";
static uint16_t socks_port = 1080;

void flush_system_dns_cache()
{
    NetworkInterface::System("ipconfig /flushdns");
}

void set_all_netif_static_dns_server(const char* dns)
{
    if (dns == NULL || '\x0' == *dns)
    {
        dns = "8.8.8.8";
    }
    else
    {
        unsigned int server = inet_addr(dns);
        if (0 == server || (unsigned int)~0 == server)
        {
            dns = "8.8.8.8";
        }
    }
    flush_system_dns_cache();
    std::map<std::string, NetworkInterface> netifs;
    if (NetworkInterface::GetAllNetworkInterfaces(netifs) > 0)
    {
        std::map<std::string, NetworkInterface>::iterator tail = netifs.begin();
        std::map<std::string, NetworkInterface>::iterator endl = netifs.end();
        for (; tail != endl; ++tail)
        {
            const NetworkInterface& ni = tail->second;
            char cmd[1024];
            sprintf(cmd, "netsh interface ip set dns %u static %s", ni.IfIndex, dns);
            NetworkInterface::System(cmd);
        }
    }
    flush_system_dns_cache();
}

void route_delete_tun2socks_hijacked_netmask()
{
    NetworkInterface::System("route delete 198.18.0.0");
}

void route_addedi_tun2socks_hijacked_netmask(unsigned int ifIndex)
{
    char cmd[1024];
    snprintf(cmd, 1024, "route add 198.18.0.0 mask 255.254.0.0 10.0.0.0 if %d", ifIndex);
    NetworkInterface::System(cmd);
}

void exit_tun2socks_program()
{
    set_all_netif_static_dns_server(NULL);
    route_delete_tun2socks_hijacked_netmask();
	TerminateProcess(GetCurrentProcess(), 0);
    ExitProcess(0);
}

int main(int argc, char* argv[])
{
	if (argc > 1) {
		socks_server = argv[1];
	}
	
    if (argc > 2) {
		int port = atoi(argv[2]);
		if (port <= 0 || port > 65535) {
			port = 1080;
		}
		socks_port = (uint16_t)port;
	}

	SetConsoleCtrlHandler([](DWORD CtrlType) {
		exit_tun2socks_program();
		return TRUE;
	}, TRUE);

	auto adapter = open_tun();
	adapter->ip = inet_addr(tap_ip);
	adapter->mask = inet_addr(tap_mask);
	adapter->network = inet_addr(tap_network);

	SOCKS5NoAuth auth{ NO_AUTH };
	auto config = make_config_with_socks5_no_auth(
		adapter, 
		socks_server, 
		strlen(socks_server), 
		socks_port, 
		60000, 
	&auth);
	tun2socks_start(config);
    do {
        set_all_netif_static_dns_server("127.0.0.1");
        route_addedi_tun2socks_hijacked_netmask(adapter->index);
        while (1) {
            int rc = getchar();
            if (rc == '\n') {
                break;
            }
        }
        delete_tun(adapter);
        delete_config(config);
    } while (0, 0);
	exit_tun2socks_program();
	return 0;
}