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

#include <stdio.h>
#include <string.h>
#include "Net.h"
#include "Net_Slirp.h"
#include "FIFO.h"
#include "Platform.h"

#include <libslirp.h>

#ifdef __WIN32__
	#include <ws2tcpip.h>
	#include <iphlpapi.h>
	#pragma comment(lib, "iphlpapi.lib")
#else
	#include <sys/socket.h>
	#include <netdb.h>
	#include <poll.h>
	#include <time.h>
	#include <ifaddrs.h>
	#include <net/if.h>
#endif

namespace melonDS
{

using Platform::Log;
using Platform::LogLevel;

const u32 kSubnet   = 0x0A400000;
const u32 kServerIP = kSubnet | 0x01;
const u32 kDNSIP    = kSubnet | 0x02;
const u32 kClientIP = kSubnet | 0x10;

const u8 kServerMAC[6] = {0x00, 0xAB, 0x33, 0x28, 0x99, 0x44};

#ifdef __WIN32__

#define poll WSAPoll
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

// https://stackoverflow.com/questions/5404277/porting-clock-gettime-to-windows

struct timespec { long tv_sec; long tv_nsec; };

int clock_gettime(int, struct timespec *spec)
{
    __int64 wintime;
    GetSystemTimeAsFileTime((FILETIME*)&wintime);
    wintime -=116444736000000000LL;                 //1jan1601 to 1jan1970
    spec->tv_sec  = wintime / 10000000LL;           //seconds
    spec->tv_nsec = wintime % 10000000LL * 100;     //nano-seconds
    return 0;
}

#endif // __WIN32__


ssize_t Net_Slirp::SlirpCbSendPacket(const void* buf, size_t len, void* opaque) noexcept
{
    if (len > 2048)
    {
        Log(LogLevel::Warn, "slirp: packet too big (%zu)\n", len);
        return 0;
    }

    Log(LogLevel::Debug, "slirp: response packet of %zu bytes, type %04X\n", len, ntohs(((u16*)buf)[6]));

    Net_Slirp& self = *static_cast<Net_Slirp*>(opaque);

    // Check if this is a UDP packet from NATNEG server (port 27901)
    // We need to intercept and modify the response to fix the IP address
    u8* data = (u8*)buf;
    u16 ethertype = ntohs(*(u16*)&data[0xC]);

    if (ethertype == 0x0800 && len > 0x2A) // IPv4
    {
        u8 protocol = data[0x17];
        if (protocol == 0x11) // UDP
        {
            u16 srcport = ntohs(*(u16*)&data[0x22]);

            // NATNEG server response (from port 27901)
            if (srcport == 27901 && len >= 0x2A + 8) // Need at least 8 bytes of NATNEG payload
            {
                // NATNEG packet structure (after UDP header at 0x2A):
                // The payload may contain IP addresses that need to be replaced

                u32 external_ip = self.GetExternalIP();
                if (external_ip != 0)
                {
                    // Search for local IP in the NATNEG payload and replace it
                    u8* payload = &data[0x2A]; // Start of UDP payload
                    int payload_len = len - 0x2A;

                    // The local IP might be in network byte order (big endian) in the packet
                    // We need to search for 192.168.178.125 = 0xC0A8B27D in network order
                    // But libslirp might have already translated it, so let's just replace any private IP

                    // For now, let's log what we found
                    Platform::Log(Platform::LogLevel::Info, "Net_Slirp: NATNEG response - External IP available: %d.%d.%d.%d\n",
                                 (external_ip >> 24) & 0xFF, (external_ip >> 16) & 0xFF,
                                 (external_ip >> 8) & 0xFF, external_ip & 0xFF);

                    // TODO: Implement actual IP replacement in NATNEG payload
                    // This requires understanding the exact NATNEG packet format
                }
            }
        }
    }

    if (self.Callback)
    {
        self.Callback((const u8*)buf, len);
    }

    return len;
}

void SlirpCbGuestError(const char* msg, void* opaque)
{
    Log(LogLevel::Error, "SLIRP: error: %s\n", msg);
}

int64_t SlirpCbClockGetNS(void* opaque)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

void* SlirpCbTimerNew(SlirpTimerCb cb, void* cb_opaque, void* opaque)
{
    return nullptr;
}

void SlirpCbTimerFree(void* timer, void* opaque)
{
}

void SlirpCbTimerMod(void* timer, int64_t expire_time, void* opaque)
{
}

void SlirpCbRegisterPollFD(int fd, void* opaque)
{
    Log(LogLevel::Debug, "Slirp: register poll FD %d\n", fd);
}

void SlirpCbUnregisterPollFD(int fd, void* opaque)
{
    Log(LogLevel::Debug, "Slirp: unregister poll FD %d\n", fd);
}

void SlirpCbNotify(void* opaque)
{
    Log(LogLevel::Debug, "Slirp: notify???\n");
}

const SlirpCb Net_Slirp::cb =
{
    .send_packet = SlirpCbSendPacket,
    .guest_error = SlirpCbGuestError,
    .clock_get_ns = SlirpCbClockGetNS,
    .timer_new = SlirpCbTimerNew,
    .timer_free = SlirpCbTimerFree,
    .timer_mod = SlirpCbTimerMod,
    .register_poll_fd = SlirpCbRegisterPollFD,
    .unregister_poll_fd = SlirpCbUnregisterPollFD,
    .notify = SlirpCbNotify
};

Net_Slirp::Net_Slirp(const Platform::SendPacketCallback& callback) noexcept : Callback(callback)
{
    SlirpConfig cfg {};
    memset(&cfg, 0, sizeof(cfg));
    cfg.version = 1;

    cfg.in_enabled = true;
    *(u32*)&cfg.vnetwork = htonl(kSubnet);
    *(u32*)&cfg.vnetmask = htonl(0xFFFFFF00);
    *(u32*)&cfg.vhost = htonl(kServerIP);
    cfg.vhostname = "melonServer";
    *(u32*)&cfg.vdhcp_start = htonl(kClientIP);
    *(u32*)&cfg.vnameserver = htonl(kDNSIP);

    Ctx = slirp_new(&cfg, &cb, this);
}

Net_Slirp::~Net_Slirp() noexcept
{
    if (Ctx)
    {
        slirp_cleanup(Ctx);
        Ctx = nullptr;
    }
}

void FinishUDPFrame(u8* data, int len)
{
    u8* ipheader = &data[0xE];
    u8* udpheader = &data[0x22];

    // lengths
    *(u16*)&ipheader[2] = htons(len - 0xE);
    *(u16*)&udpheader[4] = htons(len - (0xE + 0x14));

    // IP checksum
    u32 tmp = 0;

    for (int i = 0; i < 20; i += 2)
        tmp += ntohs(*(u16*)&ipheader[i]);
    while (tmp >> 16)
        tmp = (tmp & 0xFFFF) + (tmp >> 16);
    tmp ^= 0xFFFF;
    *(u16*)&ipheader[10] = htons(tmp);

    // UDP checksum
    // (note: normally not mandatory, but some older sgIP versions require it)
    tmp = 0;
    tmp += ntohs(*(u16*)&ipheader[12]);
    tmp += ntohs(*(u16*)&ipheader[14]);
    tmp += ntohs(*(u16*)&ipheader[16]);
    tmp += ntohs(*(u16*)&ipheader[18]);
    tmp += ntohs(0x1100);
    tmp += (len-0x22);
    for (u8* i = udpheader; i < &udpheader[len-0x23]; i += 2)
        tmp += ntohs(*(u16*)i);
    if (len & 1)
        tmp += ntohs((u_short)udpheader[len-0x23]);
    while (tmp >> 16)
        tmp = (tmp & 0xFFFF) + (tmp >> 16);
    tmp ^= 0xFFFF;
    if (tmp == 0) tmp = 0xFFFF;
    *(u16*)&udpheader[6] = htons(tmp);
}

void Net_Slirp::HandleDNSFrame(u8* data, int len) noexcept
{
    u8* ipheader = &data[0xE];
    u8* udpheader = &data[0x22];
    u8* dnsbody = &data[0x2A];

    u32 srcip = ntohl(*(u32*)&ipheader[12]);
    u16 srcport = ntohs(*(u16*)&udpheader[0]);

    u16 id = ntohs(*(u16*)&dnsbody[0]);
    u16 flags = ntohs(*(u16*)&dnsbody[2]);
    u16 numquestions = ntohs(*(u16*)&dnsbody[4]);
    u16 numanswers = ntohs(*(u16*)&dnsbody[6]);
    u16 numauth = ntohs(*(u16*)&dnsbody[8]);
    u16 numadd = ntohs(*(u16*)&dnsbody[10]);

    Log(LogLevel::Debug, "DNS: ID=%04X, flags=%04X, Q=%d, A=%d, auth=%d, add=%d\n",
           id, flags, numquestions, numanswers, numauth, numadd);

    // for now we only take 'simple' DNS requests
    if (flags & 0x8000) return;
    if (numquestions != 1 || numanswers != 0) return;

    u8 resp[1024];
    u8* out = &resp[0];

    // ethernet
    memcpy(out, &data[6], 6); out += 6;
    memcpy(out, kServerMAC, 6); out += 6;
    *(u16*)out = htons(0x0800); out += 2;

    // IP
    u8* resp_ipheader = out;
    *out++ = 0x45;
    *out++ = 0x00;
    *(u16*)out = 0; out += 2; // total length
    *(u16*)out = htons(IPv4ID); out += 2; IPv4ID++;
    *out++ = 0x00;
    *out++ = 0x00;
    *out++ = 0x80; // TTL
    *out++ = 0x11; // protocol (UDP)
    *(u16*)out = 0; out += 2; // checksum
    *(u32*)out = htonl(kDNSIP); out += 4; // source IP
    *(u32*)out = htonl(srcip); out += 4; // destination IP

    // UDP
    u8* resp_udpheader = out;
    *(u16*)out = htons(53); out += 2; // source port
    *(u16*)out = htons(srcport); out += 2; // destination port
    *(u16*)out = 0; out += 2; // length
    *(u16*)out = 0; out += 2; // checksum

    // DNS
    u8* resp_body = out;
    *(u16*)out = htons(id); out += 2; // ID
    *(u16*)out = htons(0x8000); out += 2; // flags
    *(u16*)out = htons(numquestions); out += 2; // num questions
    *(u16*)out = htons(numquestions); out += 2; // num answers
    *(u16*)out = 0; out += 2; // num authority
    *(u16*)out = 0; out += 2; // num additional

    u32 curoffset = 12;
    for (u16 i = 0; i < numquestions; i++)
    {
        if (curoffset >= (len-0x2A)) return;

        u8 bitlength = 0;
        while ((bitlength = dnsbody[curoffset++]) != 0)
            curoffset += bitlength;

        curoffset += 4;
    }

    u32 qlen = curoffset-12;
    if (qlen > 512) return;
    memcpy(out, &dnsbody[12], qlen); out += qlen;

    curoffset = 12;
	for (u16 i = 0; i < numquestions; i++)
	{
		// assemble the requested domain name
		u8 bitlength = 0;
		char domainname[256] = ""; int o = 0;
		while ((bitlength = dnsbody[curoffset++]) != 0)
		{
		    if ((o+bitlength) >= 255)
            {
                // welp. atleast try not to explode.
                domainname[o++] = '\0';
                break;
            }

			strncpy(&domainname[o], (const char *)&dnsbody[curoffset], bitlength);
			o += bitlength;

			curoffset += bitlength;
			if (dnsbody[curoffset] != 0)
				domainname[o++] = '.';
            else
                domainname[o++] = '\0';
		}

		u16 type = ntohs(*(u16*)&dnsbody[curoffset]);
		u16 cls = ntohs(*(u16*)&dnsbody[curoffset+2]);

		printf("- q%d: %04X %04X %s", i, type, cls, domainname);

		// get answer
		struct addrinfo dns_hint;
		struct addrinfo* dns_res;
		u32 addr_res;

		// Special handling for conntest.nintendowifi.net - redirect to our gateway
		if (strcmp(domainname, "conntest.nintendowifi.net") == 0)
		{
			addr_res = htonl(kServerIP); // Point to our gateway (10.64.0.1)
			printf(" -> INTERCEPTED! Redirecting to gateway %d.%d.%d.%d",
			       (kServerIP >> 24) & 0xFF, (kServerIP >> 16) & 0xFF,
			       (kServerIP >> 8) & 0xFF, kServerIP & 0xFF);
		}
		else
		{
			memset(&dns_hint, 0, sizeof(dns_hint));
			dns_hint.ai_family = AF_INET; // TODO: other address types (INET6, etc)
			if (getaddrinfo(domainname, "0", &dns_hint, &dns_res) == 0)
        {
            struct addrinfo* p = dns_res;
            while (p)
            {
                struct sockaddr_in* addr = (struct sockaddr_in*)p->ai_addr;
                addr_res = *(u32*)&addr->sin_addr;

                printf(" -> %d.%d.%d.%d",
                       addr_res & 0xFF, (addr_res >> 8) & 0xFF,
                       (addr_res >> 16) & 0xFF, addr_res >> 24);

                break;
                p = p->ai_next;
            }
        }
        else
        {
            printf(" shat itself :(");
            addr_res = 0;
        }
		}

		printf("\n");
		curoffset += 4;

		// TODO: betterer support
		// (under which conditions does the C00C marker work?)
		*(u16*)out = htons(0xC00C); out += 2;
		*(u16*)out = htons(type); out += 2;
		*(u16*)out = htons(cls); out += 2;
		*(u32*)out = htonl(3600); out += 4; // TTL (hardcoded for now)
		*(u16*)out = htons(4); out += 2; // address length
		*(u32*)out = addr_res; out += 4; // address
    }

    u32 framelen = (u32)(out - &resp[0]);
    if (framelen & 1) { *out++ = 0; framelen++; }
    FinishUDPFrame(resp, framelen);

    if (Callback)
        Callback(resp, framelen);
}

void Net_Slirp::HandleHTTPConntest(u8* data, int len) noexcept
{
    // This will handle HTTP requests to our fake conntest server
    // For now, just log that we detected the request
    // TODO: Implement TCP response with external IP

    u32 external_ip = GetExternalIP();
    if (external_ip != 0)
    {
        Platform::Log(Platform::LogLevel::Info, "HandleHTTPConntest: Detected conntest request, external IP would be: %d.%d.%d.%d\n",
                     (external_ip >> 24) & 0xFF, (external_ip >> 16) & 0xFF,
                     (external_ip >> 8) & 0xFF, external_ip & 0xFF);
    }
}

void Net_Slirp::HandleDynamicPortForwarding(u8* data, int len) noexcept
{
    if (!DynamicPortForwardingEnabled || len < 0x2A)
        return;

    u16 ethertype = ntohs(*(u16*)&data[0xC]);
    if (ethertype != 0x800) // Not IPv4
        return;

    u8 protocol = data[0x17];
    if (protocol != 0x11) // Not UDP
        return;

    // Extract source IP and port from outgoing packet
    u32 srcip = ntohl(*(u32*)&data[0x1A]);
    u32 dstip = ntohl(*(u32*)&data[0x1E]);
    u16 srcport = ntohs(*(u16*)&data[0x22]);
    u16 dstport = ntohs(*(u16*)&data[0x24]);

    // Check if this is from our guest (10.64.0.16)
    if (srcip != kClientIP)
        return;

    // Log where packets are going (for GameSpy server communication debugging)
    if (srcport >= 1024) // Only log non-system ports
    {
        Platform::Log(Platform::LogLevel::Debug, "Net_Slirp: UDP from local port %d to %d.%d.%d.%d:%d\n",
            srcport,
            (dstip >> 24) & 0xFF, (dstip >> 16) & 0xFF, (dstip >> 8) & 0xFF, dstip & 0xFF,
            dstport);
    }

    // Ignore low ports and DNS
    if (srcport < 1024 || srcport == 53)
        return;

    // Check if we already forwarded this port
    for (u16 port : ForwardedPorts)
    {
        if (port == srcport)
            return; // Already forwarded
    }

    // Add dynamic port forward
    if (AddPortForward(true, srcport, srcport))
    {
        ForwardedPorts.push_back(srcport);
        Log(LogLevel::Info, "Net_Slirp: Dynamic port forward added for UDP port %d\n", srcport);
    }
}

int Net_Slirp::SendPacket(u8* data, int len) noexcept
{
    if (!Ctx) return 0;

    if (len > 2048)
    {
        Log(LogLevel::Error, "Net_SendPacket: error: packet too long (%d)\n", len);
        return 0;
    }

    u16 ethertype = ntohs(*(u16*)&data[0xC]);

    if (ethertype == 0x800)
    {
        u8 protocol = data[0x17];
        u32 dstip = ntohl(*(u32*)&data[0x1E]); // Define dstip here for both UDP and TCP

        if (protocol == 0x11) // UDP
        {
            u16 dstport = ntohs(*(u16*)&data[0x24]);

            if (dstport == 53 && dstip == kDNSIP) // DNS
            {
                HandleDNSFrame(data, len);
                return len;
            }

            // Handle NAT-PMP requests (port 5351 to gateway)
            if (dstport == 5351 && dstip == kServerIP)
            {
                Platform::Log(Platform::LogLevel::Info, "Net_Slirp: Received NAT-PMP request to port 5351\n");
                HandleNATPMP(data, len);
                return len;
            }

            // Log all UDP packets to gateway for debugging
            if (dstip == kServerIP)
            {
                Platform::Log(Platform::LogLevel::Debug, "Net_Slirp: UDP packet to gateway port %d\n", dstport);
            }

            // Check for UPnP SSDP (Simple Service Discovery Protocol) on port 1900
            if (dstport == 1900)
            {
                u32 multicast_addr = 0xEFFFFFFA; // 239.255.255.250 in host order
                Platform::Log(Platform::LogLevel::Info, "Net_Slirp: UPnP SSDP discovery packet detected on port 1900 (dst IP: %08X)\n", dstip);
                // TODO: Implement UPnP SSDP response if needed
            }

            // Check if this is a NATNEG packet (to port 27901) - we need to modify source IP
            if (dstport == 27901)
            {
                u32 external_ip = GetExternalIP();
                if (external_ip != 0)
                {
                    // Replace the source IP in the IP header with our external IP
                    // This makes the NATNEG server see our real public IP instead of local IP
                    u32 old_srcip = ntohl(*(u32*)&data[0x1A]);
                    *(u32*)&data[0x1A] = htonl(external_ip);

                    // Recalculate IP checksum
                    *(u16*)&data[0x18] = 0; // Clear old checksum
                    u32 sum = 0;
                    u8* ipheader = &data[0xE];
                    for (int i = 0; i < 20; i += 2)
                        sum += ntohs(*(u16*)&ipheader[i]);
                    while (sum >> 16)
                        sum = (sum & 0xFFFF) + (sum >> 16);
                    *(u16*)&data[0x18] = htons(~sum);

                    Platform::Log(Platform::LogLevel::Info, "Net_Slirp: Modified NATNEG packet source IP from %d.%d.%d.%d to %d.%d.%d.%d\n",
                                 (old_srcip >> 24) & 0xFF, (old_srcip >> 16) & 0xFF, (old_srcip >> 8) & 0xFF, old_srcip & 0xFF,
                                 (external_ip >> 24) & 0xFF, (external_ip >> 16) & 0xFF, (external_ip >> 8) & 0xFF, external_ip & 0xFF);
                }
            }

            // Handle dynamic port forwarding for outgoing UDP packets
            HandleDynamicPortForwarding(data, len);
        }

        // Log TCP connections to port 80 (HTTP) for IP check detection
        if (protocol == 0x06) // TCP
        {
            u16 dstport_tcp = ntohs(*(u16*)&data[0x24]);

            // Check if this is HTTP request to our gateway (conntest)
            if (dstport_tcp == 80 && dstip == kServerIP)
            {
                Platform::Log(Platform::LogLevel::Info, "Net_Slirp: HTTP request to gateway (conntest)\n");
                HandleHTTPConntest(data, len);
                // Let libslirp handle it for now, we're just logging
            }
            else if (dstport_tcp == 80 || dstport_tcp == 443)
            {
                Platform::Log(Platform::LogLevel::Info, "Net_Slirp: HTTP(S) connection to %d.%d.%d.%d:%d\n",
                    (dstip >> 24) & 0xFF, (dstip >> 16) & 0xFF, (dstip >> 8) & 0xFF, dstip & 0xFF,
                    dstport_tcp);
            }
        }
    }

    slirp_input(Ctx, data, len);
    return len;
}

int Net_Slirp::SlirpCbAddPoll(int fd, int events, void* opaque) noexcept
{
    Net_Slirp& self = *static_cast<Net_Slirp*>(opaque);

    if (self.PollListSize >= PollListMax)
    {
        Log(LogLevel::Error, "slirp: POLL LIST FULL\n");
        return -1;
    }

    int idx = self.PollListSize++;

    u16 evt = 0;

    if (events & SLIRP_POLL_IN) evt |= POLLIN;
    if (events & SLIRP_POLL_OUT) evt |= POLLWRNORM;

#ifndef __WIN32__
    // CHECKME
    if (events & SLIRP_POLL_PRI) evt |= POLLPRI;
    if (events & SLIRP_POLL_ERR) evt |= POLLERR;
    if (events & SLIRP_POLL_HUP) evt |= POLLHUP;
#endif // !__WIN32__

    self.PollList[idx].fd = fd;
    self.PollList[idx].events = evt;

    return idx;
}

int Net_Slirp::SlirpCbGetREvents(int idx, void* opaque) noexcept
{
    Net_Slirp& self = *static_cast<Net_Slirp*>(opaque);

    if (idx < 0 || idx >= self.PollListSize)
        return 0;

    u16 evt = self.PollList[idx].revents;
    int ret = 0;

    if (evt & POLLIN) ret |= SLIRP_POLL_IN;
    if (evt & POLLWRNORM) ret |= SLIRP_POLL_OUT;
    if (evt & POLLPRI) ret |= SLIRP_POLL_PRI;
    if (evt & POLLERR) ret |= SLIRP_POLL_ERR;
    if (evt & POLLHUP) ret |= SLIRP_POLL_HUP;

    return ret;
}

void Net_Slirp::RecvCheck() noexcept
{
    if (!Ctx) return;

    //if (PollListSize > 0)
    {
        u32 timeout = 0;
        PollListSize = 0;
        slirp_pollfds_fill(Ctx, &timeout, SlirpCbAddPoll, this);
        int res = poll(PollList, PollListSize, timeout);
        slirp_pollfds_poll(Ctx, res<0, SlirpCbGetREvents, this);
    }
}

bool Net_Slirp::AddPortForward(bool is_udp, u16 host_port, u16 guest_port) noexcept
{
    if (!Ctx)
    {
        Log(LogLevel::Error, "Net_Slirp::AddPortForward: Slirp context not initialized\n");
        return false;
    }

    struct in_addr host_addr;
    struct in_addr guest_addr;

    host_addr.s_addr = 0; // Listen on all interfaces (0.0.0.0)
    guest_addr.s_addr = htonl(kClientIP); // Forward to guest (10.64.0.16)

    int result = slirp_add_hostfwd(Ctx, is_udp ? 1 : 0, host_addr, host_port, guest_addr, guest_port);

    if (result < 0)
    {
        Log(LogLevel::Error, "Net_Slirp::AddPortForward: Failed to add %s port forward %d -> %d\n",
            is_udp ? "UDP" : "TCP", host_port, guest_port);
        return false;
    }

    Log(LogLevel::Info, "Net_Slirp: Added %s port forward %d -> 10.64.0.16:%d\n",
        is_udp ? "UDP" : "TCP", host_port, guest_port);
    return true;
}

bool Net_Slirp::RemovePortForward(bool is_udp, u16 host_port) noexcept
{
    if (!Ctx)
    {
        Log(LogLevel::Error, "Net_Slirp::RemovePortForward: Slirp context not initialized\n");
        return false;
    }

    struct in_addr host_addr;
    host_addr.s_addr = 0; // Same as when adding

    int result = slirp_remove_hostfwd(Ctx, is_udp ? 1 : 0, host_addr, host_port);

    if (result < 0)
    {
        Log(LogLevel::Warn, "Net_Slirp::RemovePortForward: Failed to remove %s port forward %d\n",
            is_udp ? "UDP" : "TCP", host_port);
        return false;
    }

    Log(LogLevel::Info, "Net_Slirp: Removed %s port forward %d\n",
        is_udp ? "UDP" : "TCP", host_port);
    return true;
}

void Net_Slirp::ClearPortForwards() noexcept
{
    if (!Ctx)
        return;

    Log(LogLevel::Info, "Net_Slirp: Clearing all port forwards\n");
    // Note: libslirp doesn't provide a "clear all" function,
    // so individual forwards need to be tracked and removed by the caller
}

u32 Net_Slirp::GetExternalIP() noexcept
{
    if (ExternalIP != 0)
        return ExternalIP;

#ifdef __WIN32__
    // Get external IP on Windows
    PIP_ADAPTER_INFO pAdapterInfo = nullptr;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    if (!pAdapterInfo)
        return 0;

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        if (!pAdapterInfo)
            return 0;
    }

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR)
    {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter)
        {
            // Skip loopback
            if (pAdapter->Type != MIB_IF_TYPE_LOOPBACK)
            {
                struct in_addr addr;
                if (inet_pton(AF_INET, pAdapter->IpAddressList.IpAddress.String, &addr) == 1)
                {
                    ExternalIP = ntohl(addr.s_addr);
                    Log(LogLevel::Info, "Net_Slirp: Detected external IP: %s\n",
                        pAdapter->IpAddressList.IpAddress.String);
                    break;
                }
            }
            pAdapter = pAdapter->Next;
        }
    }
    free(pAdapterInfo);
#else
    // Get external IP on Linux/Unix
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1)
        return 0;

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == nullptr)
            continue;

        // Skip loopback and non-IPv4
        if ((ifa->ifa_flags & IFF_LOOPBACK) || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        struct sockaddr_in *addr = (struct sockaddr_in*)ifa->ifa_addr;
        ExternalIP = ntohl(addr->sin_addr.s_addr);

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ip_str, INET_ADDRSTRLEN);
        Log(LogLevel::Info, "Net_Slirp: Detected external IP: %s\n", ip_str);
        break;
    }

    freeifaddrs(ifaddr);
#endif

    return ExternalIP;
}

void Net_Slirp::SendNATPMPResponse(u8 opcode, u16 result_code, u32 epoch, const u8* payload, int payload_len) noexcept
{
    u8 response[512];
    u8* ptr = response;

    // Ethernet header (to guest) - use broadcast for simplicity
    static const u8 broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(ptr, broadcast_mac, 6); ptr += 6; // Dest: broadcast
    memcpy(ptr, kServerMAC, 6); ptr += 6;    // Source: server
    *(u16*)ptr = htons(0x0800); ptr += 2;    // IPv4

    // IP header
    u8* ip_header = ptr;
    *ptr++ = 0x45; // Version 4, header length 5
    *ptr++ = 0x00; // DSCP/ECN
    *(u16*)ptr = 0; ptr += 2; // Total length (fill later)
    *(u16*)ptr = htons(IPv4ID++); ptr += 2;
    *(u16*)ptr = 0; ptr += 2; // Flags/fragment
    *ptr++ = 64; // TTL
    *ptr++ = 17; // UDP
    *(u16*)ptr = 0; ptr += 2; // Checksum (fill later)
    *(u32*)ptr = htonl(kServerIP); ptr += 4; // Source: gateway
    *(u32*)ptr = htonl(kClientIP); ptr += 4; // Dest: guest

    // UDP header
    u8* udp_header = ptr;
    *(u16*)ptr = htons(5351); ptr += 2; // Source port (NAT-PMP)
    *(u16*)ptr = htons(5351); ptr += 2; // Dest port
    *(u16*)ptr = 0; ptr += 2; // Length (fill later)
    *(u16*)ptr = 0; ptr += 2; // Checksum

    // NAT-PMP payload
    *ptr++ = 0; // Version
    *ptr++ = opcode | 0x80; // Response opcode
    *(u16*)ptr = htons(result_code); ptr += 2;
    *(u32*)ptr = htonl(epoch); ptr += 4;

    if (payload && payload_len > 0)
    {
        memcpy(ptr, payload, payload_len);
        ptr += payload_len;
    }

    // Fill in lengths
    int total_len = ptr - ip_header;
    int udp_len = ptr - udp_header;
    *(u16*)(ip_header + 2) = htons(total_len);
    *(u16*)(udp_header + 4) = htons(udp_len);

    // Calculate IP checksum
    u32 sum = 0;
    for (int i = 0; i < 20; i += 2)
        sum += ntohs(*(u16*)(ip_header + i));
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    *(u16*)(ip_header + 10) = htons(~sum);

    int frame_len = ptr - response;
    if (Callback)
        Callback(response, frame_len);
}

void Net_Slirp::HandleNATPMP(u8* data, int len) noexcept
{
    if (len < 0x2A + 2) // Ethernet + IP + UDP headers + version + opcode
    {
        Platform::Log(Platform::LogLevel::Warn, "NAT-PMP: Packet too short (%d bytes)\n", len);
        return;
    }

    u8* natpmp_data = &data[0x2A]; // Start of NAT-PMP payload
    int natpmp_len = len - 0x2A;

    if (natpmp_len < 2)
    {
        Platform::Log(Platform::LogLevel::Warn, "NAT-PMP: Payload too short (%d bytes)\n", natpmp_len);
        return;
    }

    u8 version = natpmp_data[0];
    u8 opcode = natpmp_data[1];

    Platform::Log(Platform::LogLevel::Info, "NAT-PMP: Received request - version=%d, opcode=%d\n", version, opcode);

    if (version != 0)
    {
        Platform::Log(Platform::LogLevel::Warn, "NAT-PMP: Invalid version %d (expected 0)\n", version);
        return;
    }

    u32 epoch = static_cast<u32>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());

    Log(LogLevel::Debug, "NAT-PMP: Received request opcode %d\n", opcode);

    switch (opcode)
    {
        case 0: // External IP address request
        {
            u32 external_ip = GetExternalIP();
            u8 payload[4];
            *(u32*)payload = htonl(external_ip);
            SendNATPMPResponse(opcode, 0, epoch, payload, 4);
            Log(LogLevel::Info, "NAT-PMP: Responded with external IP: %d.%d.%d.%d\n",
                (external_ip >> 24) & 0xFF, (external_ip >> 16) & 0xFF,
                (external_ip >> 8) & 0xFF, external_ip & 0xFF);
            break;
        }

        case 1: // UDP port mapping request
        case 2: // TCP port mapping request
        {
            if (natpmp_len < 12)
            {
                SendNATPMPResponse(opcode, 1, epoch, nullptr, 0); // Unsupported version
                return;
            }

            bool is_udp = (opcode == 1);
            u16 internal_port = ntohs(*(u16*)&natpmp_data[4]);
            u16 external_port = ntohs(*(u16*)&natpmp_data[6]);
            u32 lifetime = ntohl(*(u32*)&natpmp_data[8]);

            Log(LogLevel::Info, "NAT-PMP: %s port mapping request: internal=%d, external=%d, lifetime=%d\n",
                is_udp ? "UDP" : "TCP", internal_port, external_port, lifetime);

            // If external_port is 0, assign automatically
            if (external_port == 0)
                external_port = internal_port;

            if (lifetime == 0)
            {
                // Remove mapping
                RemovePortForward(is_udp, external_port);
                PortMappings.erase(internal_port);

                u8 payload[12];
                *(u16*)&payload[0] = 0; // Reserved
                *(u16*)&payload[2] = htons(internal_port);
                *(u16*)&payload[4] = htons(external_port);
                *(u32*)&payload[8] = 0;
                SendNATPMPResponse(opcode, 0, epoch, payload, 12);

                Log(LogLevel::Info, "NAT-PMP: Removed %s mapping for port %d\n",
                    is_udp ? "UDP" : "TCP", external_port);
            }
            else
            {
                // Add mapping
                if (AddPortForward(is_udp, external_port, internal_port))
                {
                    PortMapping mapping;
                    mapping.internal_port = internal_port;
                    mapping.external_port = external_port;
                    mapping.is_udp = is_udp;
                    mapping.expiry = std::chrono::steady_clock::now() +
                                   std::chrono::seconds(lifetime);
                    PortMappings[internal_port] = mapping;

                    u8 payload[12];
                    *(u16*)&payload[0] = 0; // Reserved
                    *(u16*)&payload[2] = htons(internal_port);
                    *(u16*)&payload[4] = htons(external_port);
                    *(u32*)&payload[8] = htonl(lifetime);
                    SendNATPMPResponse(opcode, 0, epoch, payload, 12);

                    Log(LogLevel::Info, "NAT-PMP: Added %s mapping %d -> %d (lifetime: %ds)\n",
                        is_udp ? "UDP" : "TCP", external_port, internal_port, lifetime);
                }
                else
                {
                    SendNATPMPResponse(opcode, 3, epoch, nullptr, 0); // Network failure
                }
            }
            break;
        }

        default:
            SendNATPMPResponse(opcode, 5, epoch, nullptr, 0); // Unsupported opcode
            break;
    }
}

}
