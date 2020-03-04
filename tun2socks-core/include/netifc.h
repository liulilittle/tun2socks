#pragma once

#include <stdio.h>
#include <string>
#include <map>
#include <WinSock2.h>

class NetworkInterface
{
public:
    std::string																		Id;
    std::string																		Name;
    std::string																		Address;
    std::string																		Mask;
    std::string																		GatewayServer;
    std::string																		DhcpServer;
    std::string																		PrimaryWinsServer;
    std::string																		SecondaryWinsServer;
    std::string																		MacAddress;
    uint32_t																		IfIndex;
    uint32_t																		IfType; // MIB_IF_TYPE

public:
    static BOOL                                                                     System(const char* CommandLine);
    static int                                                                      GetAllNetworkInterfaces(std::map<std::string, NetworkInterface>& s);
};