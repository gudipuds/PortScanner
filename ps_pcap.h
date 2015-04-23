#ifndef _PS_PCAP_H
#define _PS_PCAP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <string>
#include <iostream>
#include <list>
#include <map>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>

#include "ps_setup.h"
#include "ps_lib.h"
#include "ps_pcap.h"

/**
 * isPortInPacketList(int portNum) -> bool
 *
 * Checks if the port number is present in the packet list
 **/
bool isPortInPacketList(int portNum);

/**
 * getPacketFromList(int portNum, u_char **packetData) -> void
 *
 * Returns the packet data of requested port number
 **/
void getPacketFromList(int portNum, u_char **packetData);

/**
 * addToPacketList(int portNum, u_char *packetData) -> void
 *
 * Stores all the sniffed packets in a structure
 **/
void addToPacketList(int portNum, u_char *packetData);

/**
 * removeFromPacketList(int portNum) -> void
 *
 * Removes the packet from the list
 **/
void removeFromPacketList(int portNum);

/**
 * getICMPPortNumber(u_char * icmpHeader) -> int
 *
 * Gets the source port number from the ip packet present in ICMP packet
 **/
int getICMPPortNumber(u_char * icmpHeader);

/**
 * capturePackets(void * arg) -> void *
 *
 * Captures the incoming packets and analyses the packets
 **/
void * capturePackets(void * arg);

#endif