#pragma once

#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "protocol/all.h"

bool arpSend(pcap_t *handle, mac_addr srcMAC, mac_addr dstMAC, uint16_t arpOp, ip_addr arpSrcIp, mac_addr arpSrcMAC, ip_addr arpDstIp, mac_addr arpDstMAC);
bool arpReply(pcap_t *handle, ip_addr srcIp, mac_addr srcMAC, ip_addr dstIp, mac_addr dstMAC);