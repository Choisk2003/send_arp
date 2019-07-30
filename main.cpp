#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include "protocol/all.h"
#include "sendArp.h"

int main(int argc, char *argv[])
{
    char *dev = argv[1];
    
    ip_addr srcIp;
    mac_addr srcMAC;
    ip_addr dstIp;
    mac_addr dstMAC;
    if(4 != sscanf(argv[2], "%d.%d.%d.%d", &srcIp.a, &srcIp.b, &srcIp.c, &srcIp.d)){
        return -1;
    }
    if(6 != sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &srcMAC.oui[0], &srcMAC.oui[1], &srcMAC.oui[2], &srcMAC.nic[0], &srcMAC.nic[1], &srcMAC.nic[2])){
        return -1;
    }
    if(4 != sscanf(argv[4], "%d.%d.%d.%d", &dstIp.a, &dstIp.b, &dstIp.c, &dstIp.d)){
        return -1;
    }
    if(6 != sscanf(argv[5], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",  &dstMAC.oui[0], &dstMAC.oui[1], &dstMAC.oui[2], &dstMAC.nic[0], &dstMAC.nic[1], &dstMAC.nic[2])){
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true)
    {
        arpReply(handle, srcIp,srcMAC, dstIp, dstMAC);
    }

    pcap_close(handle);
    return 0;
}