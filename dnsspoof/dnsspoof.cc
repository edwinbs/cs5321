#include <cstdlib>
#include <pcap.h>

namespace
{
    char   g_szLastErr[PCAP_ERRBUF_SIZE] = {0};
};

#define MYASSERT(expr, err) \
    if (!expr) \
    { \
        printf("Assertion failed: %s\n", #expr); \
        printf("Error: %s\n", err); \
        return -1; \
    }

int main(int argc, char** argv)
{
    char* dev = NULL;
    
    if (argc < 2)
        dev = pcap_lookupdev(g_szLastErr);
    else
        dev = argv[1];
        
    MYASSERT(dev, g_szLastErr);
    printf("Listening on %s\n", dev);
    
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, -1, g_szLastErr);
    MYASSERT(handle, g_szLastErr);
    
    bpf_u_int32 net;
    bpf_u_int32 mask;
    MYASSERT(pcap_lookupnet(dev, &net, &mask, g_szLastErr) != -1, pcap_geterr(handle));
    
    bpf_program fp;
    MYASSERT(pcap_compile(handle, &fp, "port 53", 0, net) != -1, pcap_geterr(handle));
    
    MYASSERT(pcap_setfilter(handle, &fp) != -1, pcap_geterr(handle));
    
    return 0;
}
