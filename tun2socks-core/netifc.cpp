#include "netifc.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <WinSock2.h>
#include <Windows.h>
#include <iphlpapi.h>

BOOL NetworkInterface::System(const char* CommandLine) {
    if (NULL == CommandLine || *CommandLine == '\x0') {
        return FALSE;
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    si.cb = sizeof(STARTUPINFO);
    GetStartupInfoA(&si);
    si.wShowWindow = SW_HIDE;
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

    return CreateProcessA(NULL, (LPSTR)CommandLine, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi);
}

int NetworkInterface::GetAllNetworkInterfaces(std::map<std::string, NetworkInterface>& s) {
    int interfaces = 0;
    ULONG adapter_size = 0;
    auto adapter = std::make_unique<char[]>(sizeof(IP_ADAPTER_INFO));
    if (GetAdaptersInfo((PIP_ADAPTER_INFO)(adapter.get()), &adapter_size)) {
        adapter.reset();
        adapter = std::make_unique<char[]>(adapter_size);
    }
    if (GetAdaptersInfo((PIP_ADAPTER_INFO)(adapter.get()), &adapter_size))
        return interfaces;
    auto padapter = (PIP_ADAPTER_INFO)adapter.get();
    std::string any = "0.0.0.0";
    while (padapter) {
        if (*padapter->AdapterName == '\x0')
            continue;
        else {
            std::string adapterId = padapter->AdapterName;
            std::map<std::string, NetworkInterface>::iterator i = s.find(adapterId);
            if (i != s.end())
                continue;
            NetworkInterface& interfacex = s[adapterId];
            interfacex.Id = adapterId;
            interfacex.IfIndex = padapter->Index;
            interfacex.Name = padapter->Description;
            interfacex.Address = padapter->IpAddressList.IpAddress.String;
            interfacex.Mask = padapter->IpAddressList.IpMask.String;
            interfacex.IfType = padapter->Type;
            interfacex.GatewayServer = padapter->GatewayList.IpAddress.String;
            if (padapter->DhcpEnabled)
                interfacex.DhcpServer = padapter->DhcpServer.IpAddress.String;
            if (padapter->HaveWins) {
                interfacex.PrimaryWinsServer = padapter->PrimaryWinsServer.IpAddress.String;
                interfacex.SecondaryWinsServer = padapter->SecondaryWinsServer.IpAddress.String;
            }
            if (interfacex.Address.empty()) interfacex.Address = any;
            if (interfacex.Mask.empty()) interfacex.Mask = any;
            if (interfacex.GatewayServer.empty()) interfacex.GatewayServer = any;
            if (interfacex.DhcpServer.empty()) interfacex.DhcpServer = any;
            if (interfacex.PrimaryWinsServer.empty()) interfacex.PrimaryWinsServer = any;
            if (interfacex.SecondaryWinsServer.empty()) interfacex.SecondaryWinsServer = any;
            char sz[MAX_ADAPTER_ADDRESS_LENGTH * 3 + 1];
            for (unsigned int i = 0; i < padapter->AddressLength; i++) {
                if ((1 + i) >= padapter->AddressLength)
                    sprintf(sz + (i * 3), "%02X", padapter->Address[i]);
                else
                    sprintf(sz + (i * 3), "%02X-", padapter->Address[i]);
            }
            interfacex.MacAddress = sz;
            if (interfacex.MacAddress.empty()) interfacex.MacAddress = "00-00-00-00-00-00";
            interfaces++;
        }
        padapter = padapter->Next;
    }
    return interfaces;
}