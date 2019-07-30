#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include "protocol/all.h"

bool arpSend(pcap_t *handle, mac_addr srcMAC, mac_addr dstMAC, uint16_t arpOp, ip_addr arpSrcIp, mac_addr arpSrcMAC, ip_addr arpDstIp, mac_addr arpDstMAC)
{
    uint8_t buffer[1500];
    int packetIndex = 0;
    ether_header eth;
    eth.ether_type = htons(ETHERTYPE_ARP);
    mac_addr src;
    src.oui[0] = srcMAC.oui[0];
    src.oui[1] = srcMAC.oui[1];
    src.oui[2] = srcMAC.oui[2];
    src.nic[0] = srcMAC.nic[0];
    src.nic[1] = srcMAC.nic[1];
    src.nic[2] = srcMAC.nic[2];
    eth.src = src;

    mac_addr dest;
    dest.oui[0] = dstMAC.oui[0];
    dest.oui[1] = dstMAC.oui[1];
    dest.oui[2] = dstMAC.oui[2];
    dest.nic[0] = dstMAC.nic[0];
    dest.nic[1] = dstMAC.nic[1];
    dest.nic[2] = dstMAC.nic[2];
    eth.dst = dest;
    memcpy(buffer, &eth, sizeof(ether_header));
    packetIndex += sizeof(ether_header);

    /* ARP */
    arp_header arp;
    arp.arp_ht = 0x0001;
    arp.arp_pt = 0x0800;
    arp.arp_hs = 6;
    arp.arp_ps = 4;
    arp.arp_op = arpOp;

    arp.ip_send.a = arpSrcIp.a;
    arp.ip_send.b = arpSrcIp.b;
    arp.ip_send.c = arpSrcIp.c;
    arp.ip_send.d = arpSrcIp.d;

    arp.arp_send[0] = arpSrcMAC.oui[0];
    arp.arp_send[1] = arpSrcMAC.oui[1];
    arp.arp_send[2] = arpSrcMAC.oui[2];
    arp.arp_send[3] = arpSrcMAC.nic[0];
    arp.arp_send[4] = arpSrcMAC.nic[1];
    arp.arp_send[5] = arpSrcMAC.nic[2];

    arp.ip_targ.a = arpDstIp.a;
    arp.ip_targ.b = arpDstIp.b;
    arp.ip_targ.c = arpDstIp.c;
    arp.ip_targ.d = arpDstIp.d;

    arp.arp_targ[0] = arpDstMAC.oui[0];
    arp.arp_targ[0] = arpDstMAC.oui[1];
    arp.arp_targ[0] = arpDstMAC.oui[2];
    arp.arp_targ[0] = arpDstMAC.nic[0];
    arp.arp_targ[0] = arpDstMAC.nic[1];
    arp.arp_targ[0] = arpDstMAC.nic[2];

    memcpy(buffer + packetIndex, &arp, sizeof(arp_header));
    packetIndex += sizeof(arp_header);

    if (pcap_sendpacket(handle, buffer, packetIndex) != 0)
    {
        return false;
    }
    return true;
}

bool arpReply(pcap_t *handle, ip_addr srcIp, mac_addr srcMAC, ip_addr dstIp, mac_addr dstMAC){
    return arpSend(handle, srcMAC, dstMAC, 2, srcIp, srcMAC, dstIp, dstMAC);
}