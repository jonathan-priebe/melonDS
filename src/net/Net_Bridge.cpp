/*
    Copyright 2016-2025 melonDS team

    This file is part of melonDS.

    melonDS is free software: you can redistribute it and/or modify it under
    the terms of the GNU General Public License as published by the Free
    Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    melonDS is distributed in the hope that it will be useful, but WITHOUT ANY
    WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with melonDS. If not, see http://www.gnu.org/licenses/.
*/

#include "Net_Bridge.h"
#include <cstring>
#include <cstdio>

#ifdef __WIN32__
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/ioctl.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

using Platform::Log;
using Platform::LogLevel;

namespace melonDS
{

#ifdef __WIN32__
// Wintun function pointers (dynamically loaded)
typedef WINTUN_ADAPTER_HANDLE (*WintunCreateAdapter_t)(const wchar_t* name, const wchar_t* tunnelType, const GUID* requestedGUID);
typedef void (*WintunCloseAdapter_t)(WINTUN_ADAPTER_HANDLE adapter);
typedef WINTUN_SESSION_HANDLE (*WintunStartSession_t)(WINTUN_ADAPTER_HANDLE adapter, DWORD capacity);
typedef void (*WintunEndSession_t)(WINTUN_SESSION_HANDLE session);
typedef BYTE* (*WintunAllocateSendPacket_t)(WINTUN_SESSION_HANDLE session, DWORD packetSize);
typedef void (*WintunSendPacket_t)(WINTUN_SESSION_HANDLE session, const BYTE* packet);
typedef BYTE* (*WintunReceivePacket_t)(WINTUN_SESSION_HANDLE session, DWORD* packetSize);
typedef void (*WintunReleaseReceivePacket_t)(WINTUN_SESSION_HANDLE session, const BYTE* packet);

static WintunCreateAdapter_t pWintunCreateAdapter = nullptr;
static WintunCloseAdapter_t pWintunCloseAdapter = nullptr;
static WintunStartSession_t pWintunStartSession = nullptr;
static WintunEndSession_t pWintunEndSession = nullptr;
static WintunAllocateSendPacket_t pWintunAllocateSendPacket = nullptr;
static WintunSendPacket_t pWintunSendPacket = nullptr;
static WintunReceivePacket_t pWintunReceivePacket = nullptr;
static WintunReleaseReceivePacket_t pWintunReleaseReceivePacket = nullptr;
#endif

Net_Bridge::Net_Bridge(const Platform::SendPacketCallback& callback) noexcept
    : Callback(callback)
{
    Log(LogLevel::Info, "Net_Bridge: Initializing Bridge Mode networking\n");

    if (!InitTAP())
    {
        Log(LogLevel::Error, "Net_Bridge: Failed to initialize TAP interface\n");
        return;
    }

    Initialized = true;

    // Start receive thread
    Running = true;
    RecvThreadHandle = std::thread(&Net_Bridge::RecvThread, this);

    Log(LogLevel::Info, "Net_Bridge: Initialized successfully\n");
}

Net_Bridge::~Net_Bridge() noexcept
{
    if (Running)
    {
        Running = false;
        if (RecvThreadHandle.joinable())
            RecvThreadHandle.join();
    }

    CleanupTAP();
}

Net_Bridge::Net_Bridge(Net_Bridge&& other) noexcept
    : Callback(std::move(other.Callback))
    , RXBuffer(std::move(other.RXBuffer))
    , TAPIPAddress(other.TAPIPAddress)
    , TAPNetmask(other.TAPNetmask)
    , TAPGateway(other.TAPGateway)
    , TAPDNSServer(other.TAPDNSServer)
    , DHCPEnabled(other.DHCPEnabled)
    , DHCPServerIP(other.DHCPServerIP)
    , DHCPOfferedIP(other.DHCPOfferedIP)
    , DHCPTransactionID(other.DHCPTransactionID)
    , DHCPBound(other.DHCPBound)
    , RecvThreadHandle(std::move(other.RecvThreadHandle))
    , Running(other.Running.load())
    , Initialized(other.Initialized)
    , IPv4ID(other.IPv4ID)
{
#ifdef __WIN32__
    WintunAdapter = other.WintunAdapter;
    WintunSession = other.WintunSession;
    WintunLib = std::move(other.WintunLib);
    other.WintunAdapter = nullptr;
    other.WintunSession = nullptr;
#else
    TAPfd = other.TAPfd;
    memcpy(TAPDeviceName, other.TAPDeviceName, IFNAMSIZ);
    other.TAPfd = -1;
#endif

    other.Initialized = false;
}

Net_Bridge& Net_Bridge::operator=(Net_Bridge&& other) noexcept
{
    if (this != &other)
    {
        // Clean up current state
        if (Running)
        {
            Running = false;
            if (RecvThreadHandle.joinable())
                RecvThreadHandle.join();
        }
        CleanupTAP();

        // Move from other
        Callback = std::move(other.Callback);
        RXBuffer = std::move(other.RXBuffer);
        TAPIPAddress = other.TAPIPAddress;
        TAPNetmask = other.TAPNetmask;
        TAPGateway = other.TAPGateway;
        TAPDNSServer = other.TAPDNSServer;
        DHCPEnabled = other.DHCPEnabled;
        DHCPServerIP = other.DHCPServerIP;
        DHCPOfferedIP = other.DHCPOfferedIP;
        DHCPTransactionID = other.DHCPTransactionID;
        DHCPBound = other.DHCPBound;
        RecvThreadHandle = std::move(other.RecvThreadHandle);
        Running = other.Running.load();
        Initialized = other.Initialized;
        IPv4ID = other.IPv4ID;

#ifdef __WIN32__
        WintunAdapter = other.WintunAdapter;
        WintunSession = other.WintunSession;
        WintunLib = std::move(other.WintunLib);
        other.WintunAdapter = nullptr;
        other.WintunSession = nullptr;
#else
        TAPfd = other.TAPfd;
        memcpy(TAPDeviceName, other.TAPDeviceName, IFNAMSIZ);
        other.TAPfd = -1;
#endif

        other.Initialized = false;
    }
    return *this;
}

#ifdef __WIN32__
bool Net_Bridge::InitTAP() noexcept
{
    Log(LogLevel::Info, "Net_Bridge: Initializing Wintun adapter (Windows)\n");

    // Load Wintun.dll
    WintunLib = Platform::DynamicLibrary::Load("wintun.dll");
    if (!WintunLib)
    {
        Log(LogLevel::Error, "Net_Bridge: Failed to load wintun.dll. Please install Wintun driver.\n");
        Log(LogLevel::Error, "Net_Bridge: Download from: https://www.wintun.net/\n");
        return false;
    }

    // Load function pointers
    pWintunCreateAdapter = (WintunCreateAdapter_t)WintunLib->LoadFunction("WintunCreateAdapter");
    pWintunCloseAdapter = (WintunCloseAdapter_t)WintunLib->LoadFunction("WintunCloseAdapter");
    pWintunStartSession = (WintunStartSession_t)WintunLib->LoadFunction("WintunStartSession");
    pWintunEndSession = (WintunEndSession_t)WintunLib->LoadFunction("WintunEndSession");
    pWintunAllocateSendPacket = (WintunAllocateSendPacket_t)WintunLib->LoadFunction("WintunAllocateSendPacket");
    pWintunSendPacket = (WintunSendPacket_t)WintunLib->LoadFunction("WintunSendPacket");
    pWintunReceivePacket = (WintunReceivePacket_t)WintunLib->LoadFunction("WintunReceivePacket");
    pWintunReleaseReceivePacket = (WintunReleaseReceivePacket_t)WintunLib->LoadFunction("WintunReleaseReceivePacket");

    if (!pWintunCreateAdapter || !pWintunCloseAdapter || !pWintunStartSession || !pWintunEndSession ||
        !pWintunAllocateSendPacket || !pWintunSendPacket || !pWintunReceivePacket || !pWintunReleaseReceivePacket)
    {
        Log(LogLevel::Error, "Net_Bridge: Failed to load Wintun functions\n");
        return false;
    }

    // Create Wintun adapter
    GUID guid = {0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}};
    WintunAdapter = pWintunCreateAdapter(L"melonDS Bridge", L"melonDS", &guid);
    if (!WintunAdapter)
    {
        Log(LogLevel::Error, "Net_Bridge: Failed to create Wintun adapter. Error: %lu\n", GetLastError());
        return false;
    }

    // Start Wintun session
    WintunSession = pWintunStartSession(WintunAdapter, 0x400000); // 4 MB ring buffer
    if (!WintunSession)
    {
        Log(LogLevel::Error, "Net_Bridge: Failed to start Wintun session. Error: %lu\n", GetLastError());
        pWintunCloseAdapter(WintunAdapter);
        WintunAdapter = nullptr;
        return false;
    }

    Log(LogLevel::Info, "Net_Bridge: Wintun adapter created successfully\n");

    // If DHCP is enabled, send DHCP Discover
    if (DHCPEnabled)
    {
        Log(LogLevel::Info, "Net_Bridge: Sending DHCP Discover to get IP address from router\n");
        SendDHCPDiscover();
    }

    return true;
}

void Net_Bridge::CleanupTAP() noexcept
{
    if (WintunSession)
    {
        pWintunEndSession(WintunSession);
        WintunSession = nullptr;
    }

    if (WintunAdapter)
    {
        pWintunCloseAdapter(WintunAdapter);
        WintunAdapter = nullptr;
    }

    WintunLib.reset();
}

#else // Linux

bool Net_Bridge::InitTAP() noexcept
{
    Log(LogLevel::Info, "Net_Bridge: Initializing TAP device (Linux)\n");

    // Open /dev/net/tun
    TAPfd = open("/dev/net/tun", O_RDWR);
    if (TAPfd < 0)
    {
        Log(LogLevel::Error, "Net_Bridge: Failed to open /dev/net/tun: %s\n", strerror(errno));
        Log(LogLevel::Error, "Net_Bridge: Make sure you have permissions. Try: sudo chmod 666 /dev/net/tun\n");
        return false;
    }

    // Configure TAP device
    struct ifreq ifr = {};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;  // TAP device, no packet info
    strncpy(ifr.ifr_name, "melonds%d", IFNAMSIZ);

    if (ioctl(TAPfd, TUNSETIFF, (void*)&ifr) < 0)
    {
        Log(LogLevel::Error, "Net_Bridge: Failed to create TAP device: %s\n", strerror(errno));
        close(TAPfd);
        TAPfd = -1;
        return false;
    }

    strncpy(TAPDeviceName, ifr.ifr_name, IFNAMSIZ);
    Log(LogLevel::Info, "Net_Bridge: Created TAP device: %s\n", TAPDeviceName);

    // Set non-blocking mode
    int flags = fcntl(TAPfd, F_GETFL, 0);
    fcntl(TAPfd, F_SETFL, flags | O_NONBLOCK);

    // Bring interface up (requires root or CAP_NET_ADMIN)
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set %s up", TAPDeviceName);
    if (system(cmd) != 0)
    {
        Log(LogLevel::Warn, "Net_Bridge: Failed to bring up TAP interface. You may need to run: sudo ip link set %s up\n", TAPDeviceName);
    }

    // If DHCP is enabled, send DHCP Discover
    if (DHCPEnabled)
    {
        Log(LogLevel::Info, "Net_Bridge: Sending DHCP Discover to get IP address from router\n");
        SendDHCPDiscover();
    }

    return true;
}

void Net_Bridge::CleanupTAP() noexcept
{
    if (TAPfd >= 0)
    {
        close(TAPfd);
        TAPfd = -1;
    }
}

#endif

// TODO: Continue with remaining implementation in next part...
// We need to implement:
// - SendPacket()
// - RecvCheck()
// - RecvThread()
// - DHCP functions
// - NAT translation functions

int Net_Bridge::SendPacket(u8* data, int len) noexcept
{
    if (!Initialized)
        return 0;

    // TODO: Implement packet sending through TAP interface
    // This will be implemented in the next part

    Log(LogLevel::Debug, "Net_Bridge: SendPacket called (len=%d) - NOT YET IMPLEMENTED\n", len);
    return 0;
}

void Net_Bridge::RecvCheck() noexcept
{
    // Packets are received in the background thread
    // Just process the RX buffer
    while (!RXBuffer.IsEmpty())
    {
        u32 header = RXBuffer.Read();
        u32 len = header >> 16;
        u32 offset = header & 0xFFFF;

        // TODO: Read packet from buffer and send to DS
    }
}

void Net_Bridge::RecvThread() noexcept
{
    u8 buffer[2048];

    while (Running)
    {
#ifdef __WIN32__
        if (!WintunSession)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        DWORD packetSize;
        BYTE* packet = pWintunReceivePacket(WintunSession, &packetSize);
        if (packet)
        {
            if (packetSize <= sizeof(buffer))
            {
                memcpy(buffer, packet, packetSize);
                ProcessReceivedPacket(buffer, packetSize);
            }
            pWintunReleaseReceivePacket(WintunSession, packet);
        }
        else
        {
            // No packet available, sleep briefly
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
#else
        if (TAPfd < 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        ssize_t len = read(TAPfd, buffer, sizeof(buffer));
        if (len > 0)
        {
            ProcessReceivedPacket(buffer, len);
        }
        else if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            Log(LogLevel::Error, "Net_Bridge: TAP read error: %s\n", strerror(errno));
        }
        else
        {
            // No packet available, sleep briefly
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
#endif
    }
}

void Net_Bridge::ProcessReceivedPacket(u8* data, int len) noexcept
{
    // TODO: Implement packet processing
    Log(LogLevel::Debug, "Net_Bridge: Received packet (len=%d) - NOT YET IMPLEMENTED\n", len);
}

bool Net_Bridge::SendDHCPDiscover() noexcept
{
    // TODO: Implement DHCP Discover
    Log(LogLevel::Info, "Net_Bridge: DHCP Discover - NOT YET IMPLEMENTED\n");
    return false;
}

bool Net_Bridge::SendDHCPRequest(u32 offered_ip, u32 server_ip) noexcept
{
    // TODO: Implement DHCP Request
    Log(LogLevel::Info, "Net_Bridge: DHCP Request - NOT YET IMPLEMENTED\n");
    return false;
}

void Net_Bridge::HandleDHCPPacket(u8* data, int len) noexcept
{
    // TODO: Implement DHCP packet handling
    Log(LogLevel::Debug, "Net_Bridge: DHCP packet - NOT YET IMPLEMENTED\n");
}

void Net_Bridge::TranslateOutgoingPacket(u8* data, int len) noexcept
{
    // TODO: Implement NAT translation for outgoing packets
}

void Net_Bridge::TranslateIncomingPacket(u8* data, int len) noexcept
{
    // TODO: Implement NAT translation for incoming packets
}

void Net_Bridge::RecalculateIPChecksum(u8* ip_header) noexcept
{
    // Set checksum to 0
    *(u16*)&ip_header[10] = 0;

    u32 sum = 0;
    for (int i = 0; i < 20; i += 2)
        sum += ntohs(*(u16*)&ip_header[i]);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    *(u16*)&ip_header[10] = htons(~sum);
}

u16 Net_Bridge::CalculateChecksum(u8* data, int len) noexcept
{
    u32 sum = 0;
    for (int i = 0; i < len - 1; i += 2)
        sum += ntohs(*(u16*)&data[i]);

    if (len & 1)
        sum += data[len - 1] << 8;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

void Net_Bridge::RecalculateUDPChecksum(u8* packet, int len) noexcept
{
    // TODO: Implement UDP checksum calculation
}

bool Net_Bridge::SetStaticIP(const char* ip, const char* netmask, const char* gateway) noexcept
{
    DHCPEnabled = false;

    // Parse IP address
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) == 1)
        TAPIPAddress = ntohl(addr.s_addr);
    else
        return false;

    if (inet_pton(AF_INET, netmask, &addr) == 1)
        TAPNetmask = ntohl(addr.s_addr);
    else
        return false;

    if (inet_pton(AF_INET, gateway, &addr) == 1)
        TAPGateway = ntohl(addr.s_addr);
    else
        return false;

    Log(LogLevel::Info, "Net_Bridge: Static IP configured: %s/%s gateway %s\n", ip, netmask, gateway);
    return true;
}

bool Net_Bridge::UseDHCP() noexcept
{
    DHCPEnabled = true;
    Log(LogLevel::Info, "Net_Bridge: DHCP enabled\n");
    return SendDHCPDiscover();
}

std::string Net_Bridge::GetAssignedIP() const noexcept
{
    if (TAPIPAddress == 0)
        return "0.0.0.0";

    char buf[32];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
             (TAPIPAddress >> 24) & 0xFF,
             (TAPIPAddress >> 16) & 0xFF,
             (TAPIPAddress >> 8) & 0xFF,
             TAPIPAddress & 0xFF);
    return std::string(buf);
}

}
