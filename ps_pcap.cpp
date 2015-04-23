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

extern ps_args_t ps_args;
extern std::map<int, packet> packetList;
extern pthread_mutex_t packetListLock, pcapLock;
extern bool exitPcap;

/**
 * isPortInPacketList(int portNum) -> bool
 *
 * Checks if the port number is present in the packet list
 **/
bool isPortInPacketList(int portNum) {
  bool isPortPresent = false;
  std::map<int, packet>::iterator it;

  pthread_mutex_lock(&packetListLock);

  //Check if the port is already in the map
  it = packetList.find(portNum);
  if(it != packetList.end())
    isPortPresent = true;

  pthread_mutex_unlock(&packetListLock);

  return isPortPresent;
}

/**
 * getPacketFromList(int portNum, u_char **packetData) -> void
 *
 * Returns the packet data of requested port number
 **/
void getPacketFromList(int portNum, u_char **packetData) {
  pthread_mutex_lock(&packetListLock);

  //Get the packet data of the port is in the map
    memcpy(*packetData, packetList[portNum], sizeof(iphdr) + sizeof(tcphdr));

  pthread_mutex_unlock(&packetListLock);
}

/**
 * addToPacketList(int portNum, u_char *packetData) -> void
 *
 * Stores all the sniffed packets in a structure
 **/
void addToPacketList(int portNum, u_char *packetData) {
  std::map<int, packet>::iterator it;

  pthread_mutex_lock(&packetListLock);

  //Check if the port is already in the map
  it = packetList.find(portNum);

  //Add to map if the port number is not already in the map
  if(it == packetList.end())
    packetList[portNum] = (const u_char *)packetData;

  pthread_mutex_unlock(&packetListLock);
}

/**
 * removeFromPacketList(int portNum) -> void
 *
 * Removes the packet from the list
 **/
void removeFromPacketList(int portNum) {
  std::map<int, packet>::iterator it;

  pthread_mutex_lock(&packetListLock);

  //Check if the port is already in the map
  it = packetList.find(portNum);

  //Remove the port from the map if it is present
  if(it != packetList.end())
    packetList.erase(portNum);

  pthread_mutex_unlock(&packetListLock);
}

/**
 * getICMPPortNumber(u_char * icmpHeader) -> int
 *
 * Gets the source port number from the ip packet present in ICMP packet
 **/
int getICMPPortNumber(u_char * icmpHeader) {
  int icmpPort;

  //Get the protocol from IP header of original packet
  struct iphdr *ipHead = (struct iphdr *)(icmpHeader + ETH_HLEN);

  //Get the source port from the TCP Header
  if(ipHead->protocol == IPPROTO_TCP) {
	struct tcphdr *tcpHead = (struct tcphdr *)(icmpHeader + ETH_HLEN + ipHead->ihl* 4);
	icmpPort = ntohs(tcpHead->source);
  }
  //Get the source port from the UDP Header
  else if(ipHead->protocol == IPPROTO_TCP) {
	struct udphdr *udpHead = (struct udphdr *)(icmpHeader + ETH_HLEN + ipHead->ihl* 4);
	icmpPort = ntohs(udpHead->source);
  }

  return icmpPort;
}

/**
 * capturePackets(void * arg) -> void *
 *
 * Captures the incoming packets and analyses the packets
 **/
void * capturePackets(void * arg) {
  pcap_t *pcapHandle;
  char errorPcap[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr *packHdr;
  struct bpf_program filter;
  char filter_exp[100] = "dst host ";
  const u_char *packetData;
  int readStatus, portNum;
  bpf_u_int32 localIp;

  //Convert local ip to 32 bit format
  inet_pton(AF_INET, ps_args.localIP.c_str(), &localIp);

  //Append the local machine ip to filter expression
  strcat(filter_exp, ps_args.localIP.c_str());

  //Open the specified interface for live capturing
  pcapHandle = pcap_open_live("eth0", BUFSIZ, 0, 1000, errorPcap);
  if(pcapHandle == NULL ){
    fprintf(stderr,"Error in opening pcap for live capture: %s \n",errorPcap );
	exit(EXIT_FAILURE);
  }

  //Add a filter to capture incoming packets only
  if (pcap_compile(pcapHandle, &filter, filter_exp, 0, localIp) == -1) {
    printf("Filter Parse Error %s: %s\n", filter_exp, pcap_geterr(pcapHandle));
	exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(pcapHandle, &filter) == -1) {
    printf("Could not add filter %s: %s\n", filter_exp, pcap_geterr(pcapHandle));
	exit(EXIT_FAILURE);
  }

  //Start sniffing the packets
  while(1) {
    //Check for pcap exit condition
	pthread_mutex_lock(&pcapLock);
    if(exitPcap == true) {
	  pthread_mutex_unlock(&pcapLock);
	  break;
	}
    pthread_mutex_unlock(&pcapLock);

	//Capture the packet from Ethernet interface
    readStatus = pcap_next_ex(pcapHandle, &packHdr, &packetData);

	if(readStatus == -1) {
	  printf("Error reading packets: %s\n", pcap_geterr(pcapHandle));
	}

	if(readStatus > 0) {
	  struct iphdr *iph = (struct iphdr *)(packetData + ETH_HLEN);

	  //Get the destination port from the TCP Header
	  if(iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcpH = (struct tcphdr *)(packetData + ETH_HLEN + iph->ihl* 4);
		portNum = ntohs(tcpH->dest);
	  }
	  //Get the destination port from the UDP Header
	  else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udpH = (struct udphdr *)(packetData + ETH_HLEN + iph->ihl* 4);
		portNum = ntohs(udpH->dest);
	  }
	  //Get the destination port from the ICMP Header
      else if (iph->protocol == IPPROTO_UDP) {
		struct icmphdr *icmpH = (struct icmphdr *) (packetData + ETH_HLEN + iph->ihl* 4);
        portNum = getICMPPortNumber((u_char *)(packetData + ETH_HLEN + iph->ihl* 4 + sizeof(icmphdr)));		  
	  }
	}

	//Adds the packet to the global map
	addToPacketList(portNum, (u_char *)packetData + ETH_HLEN);
  }

  //Close the pcap handle
  pcap_close(pcapHandle);

  pthread_exit(NULL);
}