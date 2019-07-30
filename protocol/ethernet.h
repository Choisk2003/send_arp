#pragma once

#include <stdint.h>


struct mac_addr {
    uint8_t oui[3];
    uint8_t nic[3];
};

#define ETH_ALEN 6
#define ETHERTYPE_IP 0x0800 /* IP */
#define ETHERTYPE_ARP 0x0806 /* Address resolution */
#define ETHERTYPE_IPV6 0x86dd /* IP protocol version 6 */

struct ether_header
{
    mac_addr dst;
    mac_addr src;
    uint16_t ether_type;
} __attribute__ ((__packed__));
