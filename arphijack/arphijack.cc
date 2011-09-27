#include <cstdlib>
#include <cstring>
#include <string>

#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

using namespace std;

namespace
{
    char   g_szLastErr[PCAP_ERRBUF_SIZE] = {0};
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
    in_addr     senderIP;		        /* Sender IP address.  */
    u_int8_t    targetMAC[ETH_ALEN];	/* Target hardware address.  */
    in_addr     targetIP;		        /* Target IP address.  */
} ARPPacket;

void WriteARP(u_char* pPacket,
              unsigned int& nPos,
              u_int16_t totalLen,
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
    
    memcpy(pARP->senderMAC, pSenderMAC, ETH_ALEN * sizeof(u_char));
    
    in_addr senderIPAddr;
    inet_aton(szSenderIP, &senderIPAddr);
    pARP->senderIP      = senderIPAddr;
    
    memcpy(pARP->targetMAC, pTargetMAC, ETH_ALEN * sizeof(u_char));
    
    in_addr targetIPAddr;
    inet_aton(szTargetIP, &targetIPAddr);
    pARP->targetIP      = targetIPAddr;
    
    nPos += sizeof(ARPPacket);
}             
    
void WriteEthernet(u_char* pPacket,
                   unsigned int& nPos,
                   const u_char* pSrc,
                   const u_char* pDst)
{
    ether_header* pEth = reinterpret_cast<ether_header*>(pPacket+nPos);
    
    memcpy(pEth->ether_dhost, pDst, ETH_ALEN * sizeof(u_char));
    memcpy(pEth->ether_shost, pSrc, ETH_ALEN * sizeof(u_char));
    pEth->ether_type = htons(0x0800);
    
    nPos += sizeof(ether_header);
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
    
    pcap_t* handle = pcap_open_live(szDevice, BUFSIZ, 1, -1, g_szLastErr);
    MY_ASSERT(handle);
}

