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

#ifndef NET_BRIDGE_H
#define NET_BRIDGE_H

#include "types.h"
#include "FIFO.h"
#include "Platform.h"
#include "NetDriver.h"

#include <memory>
#include <string>
#include <thread>
#include <atomic>

#ifdef __WIN32__
    #include <windows.h>
#else
    #include <sys/socket.h>
    #include <linux/if.h>
    #include <linux/if_tun.h>
#endif

namespace melonDS
{

// Forward declarations for platform-specific handles
#ifdef __WIN32__
    // Wintun types (we'll dynamically load these)
    typedef void* WINTUN_ADAPTER_HANDLE;
    typedef void* WINTUN_SESSION_HANDLE;
#endif

class Net_Bridge : public NetDriver
{
public:
    explicit Net_Bridge(const Platform::SendPacketCallback& callback) noexcept;
    Net_Bridge(const Net_Bridge&) = delete;
    Net_Bridge& operator=(const Net_Bridge&) = delete;
    Net_Bridge(Net_Bridge&& other) noexcept;
    Net_Bridge& operator=(Net_Bridge&& other) noexcept;
    ~Net_Bridge() noexcept override;

    // NetDriver interface
    int SendPacket(u8* data, int len) noexcept override;
    void RecvCheck() noexcept override;

    // Configuration methods
    bool SetStaticIP(const char* ip, const char* netmask, const char* gateway) noexcept;
    bool UseDHCP() noexcept;

    // Status methods
    bool IsInitialized() const noexcept { return Initialized; }
    std::string GetAssignedIP() const noexcept;

private:
    // Platform-specific initialization
    bool InitTAP() noexcept;
    void CleanupTAP() noexcept;

    // Packet processing
    void RecvThread() noexcept;
    void ProcessReceivedPacket(u8* data, int len) noexcept;

    // NAT translation (DS IP ↔ TAP IP)
    void TranslateOutgoingPacket(u8* data, int len) noexcept;
    void TranslateIncomingPacket(u8* data, int len) noexcept;

    // DHCP client functionality
    bool SendDHCPDiscover() noexcept;
    bool SendDHCPRequest(u32 offered_ip, u32 server_ip) noexcept;
    void HandleDHCPPacket(u8* data, int len) noexcept;

    // Helper functions
    void RecalculateIPChecksum(u8* ip_header) noexcept;
    void RecalculateUDPChecksum(u8* packet, int len) noexcept;
    u16 CalculateChecksum(u8* data, int len) noexcept;

    Platform::SendPacketCallback Callback;
    FIFO<u32, (0x8000 >> 2)> RXBuffer {};

    // DS network configuration (internal virtual network)
    static constexpr u32 kDSIP = 0x0A400010;      // 10.64.0.16 (DS IP)
    static constexpr u32 kDSNetmask = 0xFFFFFF00; // 255.255.255.0
    static constexpr u32 kDSGateway = 0x0A400001; // 10.64.0.1 (virtual gateway)

    // TAP interface configuration (real network)
    u32 TAPIPAddress = 0;      // Assigned by DHCP or static
    u32 TAPNetmask = 0;
    u32 TAPGateway = 0;
    u32 TAPDNSServer = 0;

    // DHCP state
    bool DHCPEnabled = true;
    u32 DHCPServerIP = 0;
    u32 DHCPOfferedIP = 0;
    u32 DHCPTransactionID = 0;
    bool DHCPBound = false;

    // TAP interface handle (platform-specific)
#ifdef __WIN32__
    WINTUN_ADAPTER_HANDLE WintunAdapter = nullptr;
    WINTUN_SESSION_HANDLE WintunSession = nullptr;
    std::shared_ptr<Platform::DynamicLibrary> WintunLib = nullptr;
#else
    int TAPfd = -1;
    char TAPDeviceName[IFNAMSIZ] = {};
#endif

    // Receive thread
    std::thread RecvThreadHandle;
    std::atomic<bool> Running = false;
    bool Initialized = false;

    u32 IPv4ID = 0;
};

}

#endif // NET_BRIDGE_H
