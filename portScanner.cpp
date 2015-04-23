#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <string>
#include <errno.h>
#include <map>
#include <queue>
#include <ctime>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <pthread.h>

#include "ps_setup.h"
#include "ps_lib.h"
#include "ps_pcap.h"

//Recommended Time To Live value
#define TIMETOLIVE 64

//IPV4 version
#define IPV4VERSION 4

//Minimum Internet Header Length value
#define MIN_IHL 5

//Minimum TCP Header Size
#define DATA_OFFSET 5

//Maximum TCP Window Size
#define MAX_TCP_WINDOW_SIZE 65535

//Maximum Retransmission Count
#define MAXRETRANSMIT 3

//Initial Time out
#define TIMEOUT 4

//Maximum Number of Threads
#define MAX_THREADS 15;

using namespace std;
int sourcePort;
map<int, packet> packetList;
ps_args_t ps_args;
bool exitPcap = false;
queue<string> workQueue;
map<string, resultSet> finalResults;
pthread_mutex_t packetListLock, pcapLock, sourcePortLock, workQueueLock, finalResultsLock;

/**
 * doTcpSynScan(string srcIP, string destIP, int portNum, struct resultSet * result) -> void
 *
 * Performs TCP SYN scan
 **/
void doTcpSynScan(string srcIP, string destIP, int portNum, struct resultSet * result) {
  u_char *recvPacket;
  struct iphdr ipHeader;
  struct tcphdr tcpHeader;
  struct sockaddr_in destIPAddr;
  int sockfd, readSize, retransCount;
  double time_out = (double)TIMEOUT;
  int enbl_iphdr = 1;
  const int *optval = &enbl_iphdr;
  unsigned char * packet;
  bool flag = false;
  double duration;
  socklen_t destAddrLen;
  clock_t startTime;
  packet = (unsigned char *)malloc(sizeof(tcphdr) + sizeof(iphdr));
  recvPacket = (u_char *)malloc(2048);

  //Constructing the IP header
  memset(&ipHeader, 0, sizeof(iphdr));
  ipHeader.version = 4;
  ipHeader.ihl = 5;
  ipHeader.tos = 0;
  ipHeader.tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
  ipHeader.id = htons(0);
  ipHeader.frag_off = 0;
  ipHeader.ttl = TIMETOLIVE;
  ipHeader.protocol = IPPROTO_TCP;
  ipHeader.check = 0;
  inet_pton(AF_INET, srcIP.c_str(), &(ipHeader.saddr));
  inet_pton(AF_INET, destIP.c_str(), &(ipHeader.daddr));
  
  //Calculate the checksum of IP Header
  ipHeader.check = getChecksum((uint16_t *)&ipHeader, sizeof(iphdr));

  //Constructing the TCP Header with SYN flag
  memset(&tcpHeader, 0, sizeof(tcphdr));
  tcpHeader.source = htons(getSourcePort());
  tcpHeader.dest = htons(portNum);
  tcpHeader.seq = htonl(0);
  tcpHeader.ack_seq = htonl(0);
  tcpHeader.res1 = 0;
  tcpHeader.doff = DATA_OFFSET;
  tcpHeader.fin = 0;
  tcpHeader.syn = 1;
  tcpHeader.rst = 0;
  tcpHeader.psh = 0;
  tcpHeader.ack = 0;
  tcpHeader.urg = 0;
  tcpHeader.res2 = 0;
  tcpHeader.window = MAX_TCP_WINDOW_SIZE;
  tcpHeader.check = 0;
  tcpHeader.urg_ptr = 0;

  //Calculate the checksum of TCP Header
  tcpHeader.check = getTcpChecksum(ipHeader, tcpHeader);

  memcpy(packet, &ipHeader, sizeof(iphdr));
  memcpy(packet + sizeof(iphdr), &tcpHeader, sizeof(tcphdr));

  //Create a new socket
  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sockfd < 0) {
    fprintf(stderr, "%s\n", strerror(errno));
    printf("Error in raw socket creation\n");
	exit(EXIT_FAILURE);
  }

  //Setting socket options
  if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(enbl_iphdr)) < 0) {
    fprintf(stderr, "%s\n", strerror(errno));
    printf("Error setting socket option - IP_HDRINCL\n");
  }

  startTime = clock();
  for(retransCount = 0; retransCount < MAXRETRANSMIT; retransCount++) {
    //Send SYN packet
    destIPAddr.sin_family = AF_INET;
    destIPAddr.sin_addr.s_addr = inet_addr(destIP.c_str());
    destIPAddr.sin_port = htons(portNum);
    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&destIPAddr, sizeof(destIPAddr)) < 0) {
      fprintf(stderr, "%s\n", strerror(errno));
	  printf("Error sending packets.\n");
    }

	//Wait for response
    while(1) {
	  //Check if pcap has seen the packet with given source port
	  if(isPortInPacketList(ntohs(tcpHeader.source))) {
	    getPacketFromList(ntohs(tcpHeader.source), &recvPacket);
		removeFromPacketList(ntohs(tcpHeader.source));

		//Get the IP Header from the received packet
		struct iphdr *ipHead = (struct iphdr *) recvPacket;
		if(ipHead->protocol == IPPROTO_TCP) {
		  //Get the TCP Header from received packet
		  struct tcphdr *tcpHead = (struct tcphdr *) (recvPacket + sizeof(struct iphdr));
		  if (tcpHeader.source == tcpHead->dest && tcpHeader.dest == tcpHead->source) {
	        if(tcpHead->syn == 1 || tcpHead->ack == 1) {
		      result->scanResult[0] = 1;
		      flag = true;
	          //printf("Port is open\n");
		    }
	        else if (tcpHead->rst == 1) {
		      result->scanResult[0] = 2;
		      flag = true;
	          //printf("Port is closed\n");
		    }
		  }
		}
		else if(ipHead->protocol == IPPROTO_ICMP) {
		  //Get the ICMP Header from the received packet
		  struct icmphdr *icmpHead = (struct icmphdr *) (recvPacket + sizeof(struct iphdr));
		  if(icmpHead->type == 3) {
		    switch(icmpHead->code) {
		      case 1:
			  case 2:
			  case 3:
			  case 9:
			  case 10:
			  case 13:
			    //printf("Port is filtered\n");
                result->scanResult[0] = 3;
			    flag = true;
			    break;
		    }
		  }
		}
	  }
	  if(flag)
		break;

	  //Check for time out
	  duration = (clock() - startTime)/(double)CLOCKS_PER_SEC;
	  if(duration > time_out)
	    break;
	}
	//Increase the time out for next retransmission
	time_out += 1.0;

	if(flag)
	  break;
  }

  if (retransCount == MAXRETRANSMIT) {
    //printf("Port is filtered\n");
    result->scanResult[0] = 3;
  }

  //Close the socket
  close(sockfd);
  free(packet);
  free(recvPacket);
}

/**
 * doTcpNullScan(string srcIP, string destIP, int portNum, struct resultSet * result) -> void
 *
 * Performs TCP NULL scan
 **/
void doTcpNullScan(string srcIP, string destIP, int portNum, struct resultSet * result) {
  u_char *recvPacket;
  struct iphdr ipHeader;
  struct tcphdr tcpHeader;
  struct sockaddr_in destIPAddr;
  int sockfd, readSize, retransCount;
  double time_out = (double)TIMEOUT;
  int enbl_iphdr = 1;
  const int *optval = &enbl_iphdr;
  unsigned char * packet;
  bool flag = false;
  double duration;
  socklen_t destAddrLen;
  clock_t startTime;
  packet = (unsigned char *)malloc(sizeof(tcphdr) + sizeof(iphdr));
  recvPacket = (u_char *)malloc(2048);

  //Constructing the IP header
  memset(&ipHeader, 0, sizeof(iphdr));
  ipHeader.version = 4;
  ipHeader.ihl = 5;
  ipHeader.tos = 0;
  ipHeader.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
  ipHeader.id = htons(0);
  ipHeader.frag_off = 0;
  ipHeader.ttl = TIMETOLIVE;
  ipHeader.protocol = IPPROTO_TCP;
  ipHeader.check = 0;
  inet_pton(AF_INET, srcIP.c_str(), &(ipHeader.saddr));
  inet_pton(AF_INET, destIP.c_str(), &(ipHeader.daddr));
  
  //Calculate the checksum of IP Header
  ipHeader.check = getChecksum((uint16_t *)&ipHeader, sizeof(struct iphdr));
  
  //Constructing the TCP Header with SYN flag
  memset(&tcpHeader, 0, sizeof(tcphdr));
  tcpHeader.source = htons(getSourcePort());
  tcpHeader.dest = htons(portNum);
  tcpHeader.seq = htonl(0);
  tcpHeader.ack_seq = htonl(0);
  tcpHeader.res1 = 0;
  tcpHeader.doff = DATA_OFFSET;
  tcpHeader.fin = 0;
  tcpHeader.syn = 0;
  tcpHeader.rst = 0;
  tcpHeader.psh = 0;
  tcpHeader.ack = 0;
  tcpHeader.urg = 0;
  tcpHeader.res2 = 0;
  tcpHeader.window = MAX_TCP_WINDOW_SIZE;
  tcpHeader.check = 0;
  tcpHeader.urg_ptr = 0;

  //Calculate the checksum of TCP Header
  tcpHeader.check = getTcpChecksum(ipHeader, tcpHeader);

  memcpy(packet, &ipHeader, sizeof(iphdr));
  memcpy(packet + sizeof(iphdr), &tcpHeader, sizeof(tcphdr));

  //Create a new socket
  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sockfd < 0) {
    fprintf(stderr, "%s\n", strerror(errno));
    printf("Error in raw socket creation\n");
	exit(EXIT_FAILURE);
  }

  //Setting socket options
  if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(enbl_iphdr)) < 0) {
    fprintf(stderr, "%s\n", strerror(errno));
    printf("Error setting socket option - IP_HDRINCL\n");
  }

  startTime = clock();
  for(retransCount = 0; retransCount < MAXRETRANSMIT; retransCount++) {
    //Send TCP NULL packet
    destIPAddr.sin_family = AF_INET;
    destIPAddr.sin_addr.s_addr = inet_addr(destIP.c_str());
    destIPAddr.sin_port = htons(portNum);
    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&destIPAddr, sizeof(destIPAddr)) < 0) {
      fprintf(stderr, "%s\n", strerror(errno));
	  printf("Error sending packets.\n");
    }

	//Wait for response
    while(1) {
	  //Check if pcap has seen the packet with given source port
	  if(isPortInPacketList(ntohs(tcpHeader.source))) {
	    getPacketFromList(ntohs(tcpHeader.source), &recvPacket);
		removeFromPacketList(ntohs(tcpHeader.source));

		//Get the IP Header from the received packet
		struct iphdr *ipHead = (struct iphdr *) recvPacket;
		if(ipHead->protocol == IPPROTO_TCP) {
		  //Get the TCP Header from received packet
		  struct tcphdr *tcpHead = (struct tcphdr *) (recvPacket + sizeof(struct iphdr));
		  if (tcpHeader.source == tcpHead->dest && tcpHeader.dest == tcpHead->source) {
	        if (tcpHead->rst == 1) {
		      result->scanResult[1] = 2;
		      flag = true;
	          //printf("Port is closed\n");
		    }
		  }
		}
		else if(ipHead->protocol == IPPROTO_ICMP) {
		  //Get the ICMP Header from the received packet
		  struct icmphdr *icmpHead = (struct icmphdr *) (recvPacket + sizeof(struct iphdr));
		  if(icmpHead->type == 3) {
		    switch(icmpHead->code) {
		      case 1:
			  case 2:
			  case 3:
			  case 9:
			  case 10:
			  case 13:
			    //printf("Port is filtered\n");
                result->scanResult[1] = 3;
			    flag = true;
			    break;
		    }
		  }
		}
	  }
	  if(flag)
		break;

	  //Check for time out
	  duration = (clock() - startTime)/(double)CLOCKS_PER_SEC;
	  if(duration > time_out)
	    break;
	}
	//Increase the time out for next retransmission
	time_out += 1.0;

	if(flag)
	  break;
  }

  //Check if there is no response from the destination host
  if (retransCount == MAXRETRANSMIT) {
    //printf("Port is open/filtered\n");
    result->scanResult[1] = 5;
  }

  //Close the socket
  close(sockfd);
  free(packet);
  free(recvPacket);
}

/**
 * doTcpFinScan(string srcIP, string destIP, int portNum, struct resultSet * result) -> void
 *
 * Performs TCP FIN scan
 **/
void doTcpFinScan(string srcIP, string destIP, int portNum, struct resultSet * result) {
  u_char *recvPacket;
  struct iphdr ipHeader;
  struct tcphdr tcpHeader;
  struct sockaddr_in destIPAddr;
  int sockfd, readSize, retransCount;
  double time_out = (double)TIMEOUT;
  int enbl_iphdr = 1;
  const int *optval = &enbl_iphdr;
  unsigned char * packet;
  bool flag = false;
  double duration;
  socklen_t destAddrLen;
  clock_t startTime;
  packet = (unsigned char *)malloc(sizeof(tcphdr) + sizeof(iphdr));
  recvPacket = (u_char *)malloc(2048);

  //Constructing the IP header
  memset(&ipHeader, 0, sizeof(iphdr));
  ipHeader.version = 4;
  ipHeader.ihl = 5;
  ipHeader.tos = 0;
  ipHeader.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
  ipHeader.id = htons(0);
  ipHeader.frag_off = 0;
  ipHeader.ttl = TIMETOLIVE;
  ipHeader.protocol = IPPROTO_TCP;
  ipHeader.check = 0;
  inet_pton(AF_INET, srcIP.c_str(), &(ipHeader.saddr));
  inet_pton(AF_INET, destIP.c_str(), &(ipHeader.daddr));
  
  //Calculate the checksum of IP Header
  ipHeader.check = getChecksum((u_int16_t *)&ipHeader, sizeof(struct iphdr));
  
  //Constructing the TCP Header with SYN flag
  memset(&tcpHeader, 0, sizeof(tcphdr));
  tcpHeader.source = htons(getSourcePort());
  tcpHeader.dest = htons(portNum);
  tcpHeader.seq = htonl(0);
  tcpHeader.ack_seq = htonl(0);
  tcpHeader.res1 = 0;
  tcpHeader.doff = DATA_OFFSET;
  tcpHeader.fin = 1;
  tcpHeader.syn = 0;
  tcpHeader.rst = 0;
  tcpHeader.psh = 0;
  tcpHeader.ack = 0;
  tcpHeader.urg = 0;
  tcpHeader.res2 = 0;
  tcpHeader.window = MAX_TCP_WINDOW_SIZE;
  tcpHeader.check = 0;
  tcpHeader.urg_ptr = 0;

  //Calculate the checksum of TCP Header
  tcpHeader.check = getTcpChecksum(ipHeader, tcpHeader);

  memcpy(packet, &ipHeader, sizeof(iphdr));
  memcpy(packet + sizeof(iphdr), &tcpHeader, sizeof(tcphdr));

  //Create a new socket
  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sockfd < 0) {
    fprintf(stderr, "%s\n", strerror(errno));
    printf("Error in raw socket creation\n");
	exit(EXIT_FAILURE);
  }

  //Setting socket options
  if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(enbl_iphdr)) < 0) {
    fprintf(stderr, "%s\n", strerror(errno));
    printf("Error setting socket option - IP_HDRINCL\n");
  }

  startTime = clock();
  for(retransCount = 0; retransCount < MAXRETRANSMIT; retransCount++) {
    //Send FIN packet
    destIPAddr.sin_family = AF_INET;
    destIPAddr.sin_addr.s_addr = inet_addr(destIP.c_str());
    destIPAddr.sin_port = htons(portNum);
    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&destIPAddr, sizeof(destIPAddr)) < 0) {
      fprintf(stderr, "%s\n", strerror(errno));
	  printf("Error sending packets.\n");
    }

	//Wait for response
    while(1) {
	  //Check if pcap has seen the packet with given source port
	  if(isPortInPacketList(ntohs(tcpHeader.source))) {
	    getPacketFromList(ntohs(tcpHeader.source), &recvPacket);
		removeFromPacketList(ntohs(tcpHeader.source));

		//Get the IP Header from the received packet
		struct iphdr *ipHead = (struct iphdr *) recvPacket;
		if(ipHead->protocol == IPPROTO_TCP) {
		  //Get the TCP Header from received packet
		  struct tcphdr *tcpHead = (struct tcphdr *) (recvPacket + sizeof(struct iphdr));
		  if (tcpHeader.source == tcpHead->dest && tcpHeader.dest == tcpHead->source) {
	        if (tcpHead->rst == 1) {
		      result->scanResult[2] = 2;
		      flag = true;
	          //printf("Port is closed\n");
		    }
		  }
		}
		else if(ipHead->protocol == IPPROTO_ICMP) {
		  //Get the ICMP Header from the received packet
		  struct icmphdr *icmpHead = (struct icmphdr *) (recvPacket + sizeof(struct iphdr));
		  if(icmpHead->type == 3) {
		    switch(icmpHead->code) {
		      case 1:
			  case 2:
			  case 3:
			  case 9:
			  case 10:
			  case 13:
			    //printf("Port is filtered\n");
                result->scanResult[2] = 3;
			    flag = true;
			    break;
		    }
		  }
		}
	  }
	  if(flag)
		break;

	  //Check for time out
	  duration = (clock() - startTime)/(double)CLOCKS_PER_SEC;
	  if(duration > time_out)
	    break;
	}
	//Increase the time out for next retransmission
	time_out += 1.0;

	if(flag)
	  break;
  }

  //Check if there is no response from the destination host
  if (retransCount == MAXRETRANSMIT) {
    //printf("Port is open/filtered\n");
    result->scanResult[2] = 5;
  }

  //Close the socket
  close(sockfd);
  free(packet);
  free(recvPacket);
}

/**
 * doTcpXmasScan(string srcIP, string destIP, int portNum, struct resultSet * result) -> void
 *
 * Performs TCP XMAS scan
 **/
void doTcpXmasScan(string srcIP, string destIP, int portNum, struct resultSet * result) {
  u_char *recvPacket;
  struct iphdr ipHeader;
  struct tcphdr tcpHeader;
  struct sockaddr_in destIPAddr;
  int sockfd, readSize, retransCount;
  double time_out = (double)TIMEOUT;
  int enbl_iphdr = 1;
  const int *optval = &enbl_iphdr;
  unsigned char * packet;
  bool flag = false;
  double duration;
  socklen_t destAddrLen;
  clock_t startTime;
  packet = (unsigned char *)malloc(sizeof(tcphdr) + sizeof(iphdr));
  recvPacket = (u_char *)malloc(2048);

  //Constructing the IP header
  memset(&ipHeader, 0, sizeof(iphdr));
  ipHeader.version = 4;
  ipHeader.ihl = 5;
  ipHeader.tos = 0;
  ipHeader.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
  ipHeader.id = htons(0);
  ipHeader.frag_off = 0;
  ipHeader.ttl = TIMETOLIVE;
  ipHeader.protocol = IPPROTO_TCP;
  ipHeader.check = 0;
  inet_pton(AF_INET, srcIP.c_str(), &(ipHeader.saddr));
  inet_pton(AF_INET, destIP.c_str(), &(ipHeader.daddr));
  
  //Calculate the checksum of IP Header
  ipHeader.check = getChecksum((u_int16_t *)&ipHeader, sizeof(struct iphdr));
  
  //Constructing the TCP Header with SYN flag
  memset(&tcpHeader, 0, sizeof(tcphdr));
  tcpHeader.source = htons(getSourcePort());
  tcpHeader.dest = htons(portNum);
  tcpHeader.seq = htonl(0);
  tcpHeader.ack_seq = htonl(0);
  tcpHeader.res1 = 0;
  tcpHeader.doff = DATA_OFFSET;
  tcpHeader.fin = 1;
  tcpHeader.syn = 0;
  tcpHeader.rst = 0;
  tcpHeader.psh = 1;
  tcpHeader.ack = 0;
  tcpHeader.urg = 1;
  tcpHeader.res2 = 0;
  tcpHeader.window = MAX_TCP_WINDOW_SIZE;
  tcpHeader.check = 0;
  tcpHeader.urg_ptr = 0;

  //Calculate the checksum of TCP Header
  tcpHeader.check = getTcpChecksum(ipHeader, tcpHeader);

  memcpy(packet, &ipHeader, sizeof(iphdr));
  memcpy(packet + sizeof(iphdr), &tcpHeader, sizeof(tcphdr));

  //Create a new socket
  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sockfd < 0) {
    fprintf(stderr, "%s\n", strerror(errno));
    printf("Error in raw socket creation\n");
	exit(EXIT_FAILURE);
  }

  //Setting socket options
  if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(enbl_iphdr)) < 0) {
    fprintf(stderr, "%s\n", strerror(errno));
    printf("Error setting socket option - IP_HDRINCL\n");
  }

  startTime = clock();
  for(retransCount = 0; retransCount < MAXRETRANSMIT; retransCount++) {
    //Send XMAS packet
    destIPAddr.sin_family = AF_INET;
    destIPAddr.sin_addr.s_addr = inet_addr(destIP.c_str());
    destIPAddr.sin_port = htons(portNum);
    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&destIPAddr, sizeof(destIPAddr)) < 0) {
      fprintf(stderr, "%s\n", strerror(errno));
	  printf("Error sending packets.\n");
    }

	//Wait for response
    while(1) {
	  //Check if pcap has seen the packet with given source port
	  if(isPortInPacketList(ntohs(tcpHeader.source))) {
	    getPacketFromList(ntohs(tcpHeader.source), &recvPacket);
		removeFromPacketList(ntohs(tcpHeader.source));

		//Get the IP Header from the received packet
		struct iphdr *ipHead = (struct iphdr *) recvPacket;
		if(ipHead->protocol == IPPROTO_TCP) {
		  //Get the TCP Header from received packet
		  struct tcphdr *tcpHead = (struct tcphdr *) (recvPacket + sizeof(struct iphdr));
		  if (tcpHeader.source == tcpHead->dest && tcpHeader.dest == tcpHead->source) {
	        if (tcpHead->rst == 1) {
		      result->scanResult[3] = 2;
		      flag = true;
	          //printf("Port is closed\n");
		    }
		  }
		}
		else if(ipHead->protocol == IPPROTO_ICMP) {
		  //Get the ICMP Header from the received packet
		  struct icmphdr *icmpHead = (struct icmphdr *) (recvPacket + sizeof(struct iphdr));
		  if(icmpHead->type == 3) {
		    switch(icmpHead->code) {
		      case 1:
			  case 2:
			  case 3:
			  case 9:
			  case 10:
			  case 13:
			    //printf("Port is filtered\n");
                result->scanResult[3] = 3;
			    flag = true;
			    break;
		    }
		  }
		}
	  }
	  if(flag)
		break;

	  //Check for time out
	  duration = (clock() - startTime)/(double)CLOCKS_PER_SEC;
	  if(duration > time_out)
	    break;
	}
	//Increase the time out for next retransmission
	time_out += 1.0;

	if(flag)
	  break;
  }

  //Check if there is no response from the destination host
  if (retransCount == MAXRETRANSMIT) {
    //printf("Port is open/filtered\n");
    result->scanResult[3] = 5;
  }

  //Close the socket
  close(sockfd);
  free(packet);
  free(recvPacket);
}

/**
 * doTcpAckScan(string srcIP, string destIP, int portNum, struct resultSet * result) -> void
 *
 * Performs TCP ACK scan
 **/
void doTcpAckScan(string srcIP, string destIP, int portNum, struct resultSet * result) {
  u_char *recvPacket;
  struct iphdr ipHeader;
  struct tcphdr tcpHeader;
  struct sockaddr_in destIPAddr;
  int sockfd, readSize, retransCount;
  double time_out = (double)TIMEOUT;
  int enbl_iphdr = 1;
  const int *optval = &enbl_iphdr;
  unsigned char * packet;
  bool flag = false;
  double duration;
  socklen_t destAddrLen;
  clock_t startTime;
  packet = (unsigned char *)malloc(sizeof(tcphdr) + sizeof(iphdr));
  recvPacket = (u_char *)malloc(2048);

  //Constructing the IP header
  memset(&ipHeader, 0, sizeof(iphdr));
  ipHeader.version = 4;
  ipHeader.ihl = 5;
  ipHeader.tos = 0;
  ipHeader.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
  ipHeader.id = htons(0);
  ipHeader.frag_off = 0;
  ipHeader.ttl = TIMETOLIVE;
  ipHeader.protocol = IPPROTO_TCP;
  ipHeader.check = 0;
  inet_pton(AF_INET, srcIP.c_str(), &(ipHeader.saddr));
  inet_pton(AF_INET, destIP.c_str(), &(ipHeader.daddr));
  
  //Calculate the checksum of IP Header
  ipHeader.check = getChecksum((u_int16_t *)&ipHeader, sizeof(struct iphdr));
  
  //Constructing the TCP Header with SYN flag
  memset(&tcpHeader, 0, sizeof(tcphdr));
  tcpHeader.source = htons(getSourcePort());
  tcpHeader.dest = htons(portNum);
  tcpHeader.seq = htonl(0);
  tcpHeader.ack_seq = htonl(0);
  tcpHeader.res1 = 0;
  tcpHeader.doff = DATA_OFFSET;
  tcpHeader.fin = 0;
  tcpHeader.syn = 0;
  tcpHeader.rst = 0;
  tcpHeader.psh = 0;
  tcpHeader.ack = 1;
  tcpHeader.urg = 0;
  tcpHeader.res2 = 0;
  tcpHeader.window = MAX_TCP_WINDOW_SIZE;
  tcpHeader.check = 0;
  tcpHeader.urg_ptr = 0;

  //Calculate the checksum of TCP Header
  tcpHeader.check = getTcpChecksum(ipHeader, tcpHeader); 

  memcpy(packet, &ipHeader, sizeof(iphdr));
  memcpy(packet + sizeof(iphdr), &tcpHeader, sizeof(tcphdr));

  //Create a new socket
  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sockfd < 0) {
    fprintf(stderr, "%s\n", strerror(errno));
    printf("Error in raw socket creation\n");
	exit(EXIT_FAILURE);
  }

  //Setting socket options
  if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(enbl_iphdr)) < 0) {
    fprintf(stderr, "%s\n", strerror(errno));
    printf("Error setting socket option - IP_HDRINCL\n");
  }

  startTime = clock();
  for(retransCount = 0; retransCount < MAXRETRANSMIT; retransCount++) {
    //Send ACK packet
    destIPAddr.sin_family = AF_INET;
    destIPAddr.sin_addr.s_addr = inet_addr(destIP.c_str());
    destIPAddr.sin_port = htons(portNum);
    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&destIPAddr, sizeof(destIPAddr)) < 0) {
      //fprintf(stderr, "%s\n", strerror(errno));
	  printf("Error sending packets.\n");
    }

	//Wait for response
    while(1) {
	  //Check if pcap has seen the packet with given source port
	  if(isPortInPacketList(ntohs(tcpHeader.source))) {
	    getPacketFromList(ntohs(tcpHeader.source), &recvPacket);
		removeFromPacketList(ntohs(tcpHeader.source));

		//Get the IP Header from the received packet
		struct iphdr *ipHead = (struct iphdr *) recvPacket;
		if(ipHead->protocol == IPPROTO_TCP) {
		  //Get the TCP Header from received packet
		  struct tcphdr *tcpHead = (struct tcphdr *) (recvPacket + sizeof(struct iphdr));
		  if (tcpHeader.source == tcpHead->dest && tcpHeader.dest == tcpHead->source) {
	        if (tcpHead->rst == 1) {
		      result->scanResult[4] = 4;
		      flag = true;
	          //printf("Port is unfiltered\n");
		    }
		  }
		}
		else if(ipHead->protocol == IPPROTO_ICMP) {
		  //Get the ICMP Header from the received packet
		  struct icmphdr *icmpHead = (struct icmphdr *) (recvPacket + sizeof(struct iphdr));
		  if(icmpHead->type == 3) {
		    switch(icmpHead->code) {
		      case 1:
			  case 2:
			  case 3:
			  case 9:
			  case 10:
			  case 13:
			    //printf("Port is filtered\n");
                result->scanResult[4] = 3;
			    flag = true;
			    break;
		    }
		  }
		}
	  }
	  if(flag)
		break;

	  //Check for time out
	  duration = (clock() - startTime)/(double)CLOCKS_PER_SEC;
	  if(duration > time_out)
	    break;
	}
	//Increase the time out for next retransmission
	time_out += 1.0;

	if(flag)
	  break;
  }

  //Check if there is no response from the destination host
  if (retransCount == MAXRETRANSMIT) {
    //printf("Port is filtered\n");
    result->scanResult[4] = 3;
  }

  //Close the socket
  close(sockfd);
  free(packet);
  free(recvPacket);
}

/**
 * doUdpScan(string srcIP, string destIP, int portNum, struct resultSet * result) -> void
 *
 * Performs UDP scan
 **/
void doUdpScan(string srcIP, string destIP, int portNum, struct resultSet * result) {
  u_char *recvPacket;
  unsigned char *packet;
  unsigned char dnsQuestion [] = "www.google.com" ;
  unsigned char testData [] =" Test UDP data";
  unsigned char udpData[65535], *qname;
  struct iphdr ipHeader;
  struct udphdr udpHeader;
  struct sockaddr_in srcIPAddr, destIPAddr;
  struct dnshdr *dnsheader = (struct dnshdr *)&udpData;
  struct dnsquestion  *question = NULL;
  int i, sockfd, destAddrLen, readSize, retransCount;
  int enbl_iphdr = 1;
  const int *optval = &enbl_iphdr;
  bool flag = false;
  char *token;
  clock_t startTime;
  double duration;
  double time_out = (double)TIMEOUT;
  size_t dat;
  int payloadLength = strlen((char *)testData);
  recvPacket = (u_char *)malloc(2048);

  //Check for regular UDP packet
  if( portNum != 53 ){
    packet = (unsigned char *)malloc(sizeof( struct udphdr) + sizeof( struct iphdr) + payloadLength );

    //Constructing the IP header
    memset(&ipHeader, 0, sizeof(iphdr));
    ipHeader.version = IPV4VERSION;
    ipHeader.ihl = MIN_IHL;
    ipHeader.tos = 0;
    ipHeader.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payloadLength);
    ipHeader.id = htons(0);
    ipHeader.frag_off = 0;
    ipHeader.ttl = TIMETOLIVE;
    ipHeader.protocol = IPPROTO_UDP;
    ipHeader.check = 0;
    inet_pton(AF_INET, srcIP.c_str(), &(ipHeader.saddr));
    inet_pton(AF_INET, destIP.c_str(), &(ipHeader.daddr));

    //Constructing the UDP Header 
    memset(&udpHeader, 0, sizeof(udphdr));
    udpHeader.source = htons(getSourcePort());
    udpHeader.dest = htons(portNum);
    udpHeader.len = htons(sizeof(udphdr) + payloadLength);
    udpHeader.check = 0;

    memcpy(packet, &ipHeader, sizeof( struct iphdr));
    memcpy(packet + sizeof( struct iphdr), &udpHeader, sizeof(struct udphdr));
	memcpy( packet + sizeof( struct iphdr) + sizeof(struct udphdr), &testData, payloadLength );
  
    //Create a new socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
      fprintf(stderr, "%s\n", strerror(errno));
      printf("Error in raw socket creation\n");
	  exit(EXIT_FAILURE);
    }

    //Setting socket options
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(enbl_iphdr)) < 0) {
      fprintf(stderr, "%s\n", strerror(errno));
      printf("Error setting socket options - IP_HDRINCL\n");
    } 

	startTime = clock();
    for(retransCount = 0; retransCount < MAXRETRANSMIT; retransCount++) {
	  //Sending UDP Packet
      destIPAddr.sin_family = AF_INET;
      destIPAddr.sin_addr.s_addr = inet_addr(destIP.c_str());
      destIPAddr.sin_port = htons(portNum);
      if (( dat=sendto(sockfd, packet, sizeof(iphdr) + sizeof(udphdr) + payloadLength, 0, (struct sockaddr *)&destIPAddr, sizeof(destIPAddr))) < 0) {
        fprintf(stderr, "%s\n", strerror(errno));
	    printf("Error sending packets.\n"); 
      }

	  //Wait for response
      while(1) {
	    //Check if pcap has seen the packet with given source port
	    if(isPortInPacketList(ntohs(udpHeader.source))) {
	      getPacketFromList(ntohs(udpHeader.source), &recvPacket);
		  removeFromPacketList(ntohs(udpHeader.source));

		  //Get the IP Header from the received packet
		  struct iphdr *ipHead = (struct iphdr *) recvPacket;
		  if(ipHead->protocol == IPPROTO_UDP) {
		    //If the response is an UDP packet
		    result->scanResult[5] = 1;
		    flag = true;
	        //printf("Port is open\n");
		  }
		  else if(ipHead->protocol == IPPROTO_ICMP) {
		    //Get the ICMP Header from the received packet
		    struct icmphdr *icmpHead = (struct icmphdr *) (recvPacket + sizeof(struct iphdr));
		    if(icmpHead->type == 3) {
		      switch(icmpHead->code) {
		        case 1:
			    case 2:
			    case 9:
			    case 10:
			    case 13:
			      //printf("Port is filtered\n");
                  result->scanResult[5] = 3;
			      flag = true;
			      break;

				case 3:
				  //printf("Port is closed\n");
                  result->scanResult[5] = 2;
			      flag = true;
			      break;
		      }
		    }
		  }
	    }
	    if(flag)
		  break;

	    //Check for time out
	    duration = (clock() - startTime)/(double)CLOCKS_PER_SEC;
	    if(duration > time_out)
	      break;
	  }
	  //Increase the time out for next retransmission
	  time_out += 1.0;

	  if(flag)
	    break;
    }

	//Check if there is no response from the destination host
    if (retransCount == MAXRETRANSMIT) {
      //printf("Port is open/filtered\n");
      result->scanResult[5] = 3;
    }
    //Close the socket
    close(sockfd); 
	free(packet);
  }
  else{
    //dns query to google public dns
    //Creating a socket
	sockfd = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	int sourcePort = getSourcePort();

	//Binding it to a port number
	srcIPAddr.sin_family = AF_INET;
    srcIPAddr.sin_addr.s_addr = inet_addr(srcIP.c_str());
    srcIPAddr.sin_port = htons(sourcePort);
	if(bind(sockfd, (struct sockaddr *)&srcIPAddr, sizeof(struct sockaddr_in)) < 0){
	  cout << "Bind error" << endl;
	}

    destIPAddr.sin_family = AF_INET;
    destIPAddr.sin_addr.s_addr = inet_addr(destIP.c_str()); // for public dns server destIP ="8.8.8.8"
    destIPAddr.sin_port = htons(portNum);

    // Constructing DNS Header 
    dnsheader->id = htons(3);
    dnsheader->qr = htons(0);
    dnsheader->opcode = 0;
    dnsheader->aa = 0;
    dnsheader-> tc = 0;
    dnsheader-> rd = htons(1);
    dnsheader-> ra =0;
    dnsheader-> cd =0;
    dnsheader-> ad =0;
    dnsheader-> z = 0;
    dnsheader->rcode = 0;
    dnsheader-> qdcount = htons(1);
    dnsheader-> anscount = 0;
    dnsheader->authcount = 0;
    dnsheader->addcount = 0;

    qname = (unsigned char *) &udpData[sizeof(struct dnshdr )] ;

    // Get the DNS format for the given query
    token = strtok((char*)dnsQuestion, ".");
    while( token != NULL ){
      *qname++ = (unsigned char )strlen(token);
	  fflush(stdout);
	  for ( int i = 0; i < strlen(token); i++){
	    *qname++ = token[i];
	  }
	  token = strtok(NULL, ".");
    }
	*qname='\0';

    qname = (unsigned char *) &udpData[sizeof(struct dnshdr )] ;
    for(i = 0 ; i < 100; i++) {   
	  if ( qname[i] == '\0' ){
		break;
	  }
    } 

    // Construct the DNSQuestion structure
    question = (struct dnsquestion *) &udpData[ sizeof(struct dnshdr ) +  strlen( (const char * )qname ) + 1 ] ;
    question -> qtype = htons(1); //ipv4 T_A
    question -> qclass = htons(1); //internet class

	startTime = clock();
    for(retransCount = 0; retransCount < MAXRETRANSMIT; retransCount++) {
	  //Sending DNS Query
      if( sendto(sockfd, (char *)udpData, sizeof(struct dnshdr ) +  strlen( (const char * )qname ) + 1 + sizeof(struct dnsquestion),
                                            0,(struct sockaddr *)&destIPAddr, sizeof(destIPAddr) ) < 0 ){
	    //fprintf(stderr, "%s\n", strerror(errno));
	    printf("Error sending dns query.\n");
	  }

	  //Wait for response
      while(1) {
	    //Check if pcap has seen the packet with given source port
	    if(isPortInPacketList(ntohs(srcIPAddr.sin_port))) {
	      getPacketFromList(ntohs(srcIPAddr.sin_port), &recvPacket);
		  removeFromPacketList(ntohs(srcIPAddr.sin_port));

		  //Get the IP Header from the received packet
		  struct iphdr *ipHead = (struct iphdr *) recvPacket;
		  if(ipHead->protocol == IPPROTO_UDP) {
		    //If the response is an UDP packet
		    result->scanResult[5] = 1;
		    flag = true;
	        //printf("Port is open\n");
		  }
		  else if(ipHead->protocol == IPPROTO_ICMP) {
		    //Get the ICMP Header from the received packet
		    struct icmphdr *icmpHead = (struct icmphdr *) (recvPacket + sizeof(struct iphdr));
		    if(icmpHead->type == 3) {
		      switch(icmpHead->code) {
		        case 1:
			    case 2:
			    case 9:
			    case 10:
			    case 13:
			      //printf("Port is filtered\n");
                  result->scanResult[5] = 3;
			      flag = true;
			      break;

				case 3:
				  printf("Port is closed\n");
                  result->scanResult[5] = 2;
			      flag = true;
			      break;
		      }
		    }
		  }
	    }
	    if(flag)
		  break;

	    //Check for time out
	    duration = (clock() - startTime)/(double)CLOCKS_PER_SEC;
	    if(duration > time_out)
	      break;
	  }
	  //Increase the time out for next retransmission
	  time_out += 1.0;

	  if(flag)
	    break;
    }

	/*for(retransCount = 0; retransCount < MAXRETRANSMIT; retransCount++) {
      //Sending DNS Query
      if( sendto(sockfd, (char *)udpData, sizeof(struct dnshdr ) +  strlen( (const char * )qname ) + 1 + sizeof(struct dnsquestion),
                                            0,(struct sockaddr *)&destIPAddr, sizeof(destIPAddr) ) < 0 ){
	    //fprintf(stderr, "%s\n", strerror(errno));
	    printf("Error sending dns query.\n");
	  }

      //Read DNS Response
      memset(udpData, 0, 65535); //magic number
      destAddrLen = sizeof(destIPAddr);

	  //Set time out
	  struct timeval timeOut1;
      timeOut1.tv_sec = TIMEOUT;
      timeOut1.tv_usec = 10;
	  if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeOut1, sizeof(timeval)) < 0) {
	    fprintf(stderr, "%s\n", strerror(errno));
        printf("Error setting socket option - SO_RCVTIMEO\n");
	  }

	  //Read from the socket
      readSize = recvfrom(sockfd,(char *) udpData, 65536, 0, (struct sockaddr *)&destIPAddr, (socklen_t *) &destAddrLen );

	  if(readSize > 0) {
	    //printf("Port is open\n");
	    result->scanResult[5] = 1;
		break;
	  }
	}*/
	if(retransCount == MAXRETRANSMIT) {
	  //printf("Port is open/filtered\n");
	  result->scanResult[5] = 5;
	}
	close(sockfd);
  }

  free(recvPacket);
}

/**
 * getServiceInfo( string srcIP, string destIP, int portNum) -> string
 *
 * Checks if the expected service is running on a particular port
 **/
string getServiceInfo( string srcIP, string destIP, int portNum){
  struct sockaddr_in destIPAddr;
  struct sockaddr_in srcIPAddr;
  int sockfd, readSize, connectStatus;
  destIPAddr.sin_family = AF_INET;
  destIPAddr.sin_addr.s_addr = inet_addr(destIP.c_str());
  destIPAddr.sin_port = htons(portNum);
  char buffer[1024];
  char response[1024];

  // create a new socket
  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sockfd < 0) {
    fprintf(stderr, "%s\n", strerror(errno));
    printf("Error in socket creation\n");
  }

  //bind with source port  ** not required **	  
  /* srcIPAddr.sin_family = AF_INET;
  srcIPAddr.sin_addr.s_addr = inet_addr(srcIP.c_str());
  cout<< htons(8072) << endl;
  srcIPAddr.sin_port = htons(8075);
  if (bind(sockfd, (struct sockaddr *) &srcIPAddr,
    sizeof(srcIPAddr)) < 0) 
    cout << " error in bind " << endl; */		  
    
  // connect 
  if(connect( sockfd, ( struct sockaddr *) &destIPAddr, sizeof(destIPAddr) ) < 0 ){
	close(sockfd);
	return "UNKNOWN";
  }

  memset(response, 0, 1024);
  string responseString ( " " );

  if( portNum == 22 || portNum == 24 || portNum == 587  || portNum == 25 || portNum ==110 || portNum == 143){       
	readSize = recv( sockfd, buffer, 1024, 0);
	if(readSize < 0){
	   close(sockfd);
	   return "UNKNOWN";
	}

    //Copy  response to responseSTring
    memcpy(response, buffer, readSize );
    response[readSize+1] ='\0';
    responseString.append(response);
		  
	//get version from responseString
	if( portNum == 22){
	  //SSH
	  //check for openssh 	   
	  int index = responseString.find("OpenSSH", 0);
      if (index == string::npos){
	    return "UNKNOWN";
	  }
	  else{
	    int index2 = responseString.find("\n", 0);
		return responseString.substr(0,index2-1);
	  }	   
	}
	else if( portNum == 143){	         
	  //IMAP
	  int index = responseString.find("IMAP", 0, 4);
	  if ( index == string::npos){
		return "UNKNOWN";
	  }
	  else {
		int  index2 = responseString.find(" ", index);
		if ( index2 == string::npos){
		  return "UNKNOWN";
		}
		else {
		  return "IMAP version "+responseString.substr(index + 4, index2 - index - 4 );
		}
	  }  
	}
	else if(portNum == 24) {			   
	  // Private Mail System
	  int index = responseString.find(" ",  responseString.find(" ", 0) + 1);
	  if ( index == string::npos){
		return "UNKNOWN";
	  }
	  else {
		int index2 = responseString.find(";", index + 1);
		if ( index2 == string::npos){
		  return "UNKNOWN";
		}
		else{
		  int index2 = responseString.find(";", index + 1);
		  if (index2 == string::npos){
	        index2 = responseString.find("\n", index + 1);
			string temp (responseString.substr(index, index2 - index ));
			return  "Private Mail: " + temp ;				
		  }
		  else{
			return  "Private Mail: " + responseString.substr(index, index2 - index );
		  }
		}
	  }
	}
	else if( portNum == 110 ){		     
      //POP3
	  int index = responseString.find(" ",  responseString.find("OK", 0));
	  //responseString.append( " version POP3 ");
	  if ( index == string::npos){
		return "UNKNOWN";
	  }
	  else if( portNum == 110 ){		 
		int  index2 = responseString.find(" ", index + 1);
		if (index2 == string::npos){
		  return "UNKNOWN";
		}
		else {
		  return   "POP3 server " +responseString.substr(index, index2 - index );
		}
	  }
	}
	else if( portNum == 25 || portNum == 587){
	  //SMTP
	  int index =responseString.find("220",0);
	  //int index = responseString.find(" ",  responseString.find(" ", 0) + 1);
	  if ( index == string::npos){
		return "UNKNOWN";
	  }
	  else{
		int  index2 = responseString.find(";", index + 4);
		if ( index2 == string::npos){
		  index2 = responseString.find("\n", index + 1);
		  string temp (responseString.substr(index, index2 - index ));
		  return  "SMTP: " + temp ;
		}
		else{
		  return  "SMTP: " + responseString.substr(index, index2 - index );
		}	
      }			
	}
  }

  if(portNum == 80 ){
    // HTTP 
	memset(buffer, 0, 1024);	     
	strcpy( buffer, "GET /.html HTTP/1.0\n\r\n" );
	if (send(sockfd, buffer, strlen(buffer), 0) < 0 ){
	  close(sockfd);
	  return "UNKNOWN";
	}

    if ( (readSize = recv( sockfd, buffer, 1024, 0) ) < 0 ){
	  close(sockfd);
	  return "UNKNOWN";
	}

    //get version from response 
	memcpy(response, buffer, readSize );
	response[readSize+1] ='\0';
	responseString.append(response );

	int index = responseString.find("HTTP/", 0, 5);
	if (index == string::npos){
	  return "UNKNOWN";
	}
	else{
	  int  index2 = responseString.find(" ", index);
	  if (index2 == string::npos){
		return "UNKNOWN";
	  }
	  else{
		return "WWW HTTP version "+ responseString.substr(index + 5, index2 - index - 5);
	  }
	}          	   
  } 

  if ( portNum == 43 ){
    // WHOIS 
    memset(buffer, 0, 1024);
	strcpy( buffer, " Who is this\r\n" );

    if (send(sockfd, buffer, strlen(buffer), 0) < 0 ){
	  close(sockfd);
	  return "UNKNOWN";
	}  

    if ((readSize = recv( sockfd, buffer, 1024, 0) ) < 0){		  
      close(sockfd);
	  return "UNKNOWN" ;
	}

    //get version from response 
	memcpy(response, buffer, readSize );
	response[readSize+1] ='\0';
	responseString.append(response );

	int index = responseString.find("Whois Server Version", 0, 20);
	if(index == string::npos){
	  return "UNKNOWN";
	}
	else{		  
	  int  index2 = responseString.find("\n", index);
	  if (index2 == string::npos){
		return "UNKNOWN";
	  }
	  else{
		return "WHOIS protocol version"+responseString.substr(index + 20, index2 - index - 20);
	  }
	}
  }
}

/**
 * scanPorts(ps_args_t * ps_args) -> void *
 *
 * Performs all the scans for each pair of IP and Port Number
 **/
void * scanPorts( void * args) {

  while( !isQueueEmpty()){
	int portNum, index;
	struct resultSet result;
	char port1[64];
    string work (pickWorkFromQueue());
	index = work.find("+",0);

	//Get Destination IP Address
	string ipAddress(work.substr(0, index));
	string port(work.substr(index + 1, string::npos));

	memset(port1, 0,sizeof(port1));
	memcpy(port1,( void *) port.c_str(), port.length());
	port1[port.length() +1] = '\0'; 

    //Get Destination Port Number
	portNum = atoi( port1 );
	result.portNum = portNum;
	result.ipAddr = ipAddress ;

	//Perform TCP SYN SCAN
    if( ps_args.use_scan == false || ( ps_args.use_scan == true && ps_args.scan_opt[0] == 1) ){
	  doTcpSynScan(ps_args.localIP, ipAddress, portNum, &result);
	}

	//Perform TCP NULL SCAN
	if( ps_args.use_scan == false || ( ps_args.use_scan == true && ps_args.scan_opt[1] == 1) ){
	  doTcpNullScan(ps_args.localIP, ipAddress, portNum, &result);
	}

	//Perform TCP FIN SCAN
	if( ps_args.use_scan == false || ( ps_args.use_scan == true && ps_args.scan_opt[2] == 1 )){
	  doTcpFinScan(ps_args.localIP, ipAddress, portNum, &result);
	}

    //Perform TCP XMAS SCAN	
	if( ps_args.use_scan == false || ( ps_args.use_scan == true && ps_args.scan_opt[3] == 1) ){
	  doTcpXmasScan(ps_args.localIP, ipAddress, portNum, &result);
	}

	//Perform TCP ACK SCAN
	if( ps_args.use_scan == false || ( ps_args.use_scan == true && ps_args.scan_opt[4] == 1) ){
	  doTcpAckScan(ps_args.localIP, ipAddress, portNum, &result);
	}

	//Perform UDP Scan
	if( ps_args.use_scan == false || ( ps_args.use_scan == true && ps_args.scan_opt[5] == 1 )){
	  doUdpScan(ps_args.localIP, ipAddress, portNum, &result);
	}

	//Derive the final conclusion from the scans performed
	getConclusion(&result);
	//printf("%s\n\n", result.conclusion.c_str());

    //Find Service information for specific ports
	if(portNum == 22 || portNum == 24 || portNum == 25 || portNum == 43 || portNum == 110 || portNum == 143 || portNum == 80 || portNum == 587 ){
	  result.serviceInfo = getServiceInfo(ps_args.localIP, ipAddress, portNum);
	}
	else
	  result.serviceInfo = "UNKNOWN";

	//Add the result to the finalResults map
	addToMap(work, result);
  }

  pthread_exit(NULL);
}

int main (int argc, char * argv[]){
  pthread_t threadID[30]; 
  pthread_t pcapThreadID;
  int threadError;
  unsigned char *packet;
  struct ifreq localIPAddr;
  clock_t startTime;
  double duration;

  sourcePort = 8072;

  //Parse the input arguments from the command line
  parse_args(&ps_args, argc, argv);

  printf("Completed parsing of arguments...\n\n");

  //Create a job queue
  createToDoList();

  //DEBUG
  //printArguments();

  //Getting the local ip address of the machine
  getLocalIpAddress(&localIPAddr);
  ps_args.localIP = inet_ntoa(((struct sockaddr_in *)&localIPAddr.ifr_addr)->sin_addr);
  //DEBUG
  //cout << ps_args.localIP << endl;

  //Initialise mutex lock for packetList structure
  if(pthread_mutex_init(&packetListLock, NULL )!= 0 
      || pthread_mutex_init(&pcapLock, NULL )!= 0
	  || pthread_mutex_init(&sourcePortLock, NULL) != 0
	  || pthread_mutex_init(&workQueueLock, NULL)!= 0
	  || pthread_mutex_init(&finalResultsLock, NULL)!= 0){ 
	cout<< "Error in mutex locks initialization" <<endl;
	exit(EXIT_FAILURE);
  }

  //Create a thread to capture packets using pcap
  if(threadError = pthread_create(&pcapThreadID, NULL, capturePackets, NULL)) {
    fprintf(stderr, "%s\n", strerror(threadError));
	exit(EXIT_FAILURE);
  }
  usleep(100000);

  //Create threads to run the scans
  if(!ps_args.use_threads){
	ps_args.no_of_threads = 1;
  }

  //Start the timer
  startTime = clock();

  printf("Starting to scan the ports...\n\n");

  //Scan the ports
  for (int j = 0; j < ps_args.no_of_threads; j++) {
    if((threadError = pthread_create( &threadID[j], NULL, &scanPorts, NULL)) != 0){
      fprintf(stderr, "%s\n", strerror(threadError));
      printf("Error creating thread :  \n");
	  exit(EXIT_FAILURE);
    }
  }

  //Wait for speed up threads to complete work
  for(int i = 0; i < ps_args.no_of_threads; i++){
    pthread_join( threadID[i],NULL);
  }

  //Get the total time to scan all the ports
  duration = (clock() - startTime)/(double)CLOCKS_PER_SEC;

  //Print results on the screen
  printf("Completed scanning\n\n");
  printf("Scan took %.2lf seconds\n\n", duration);

  printResults();

  //Exit live capturing of packets
  pthread_mutex_lock(&pcapLock);
  exitPcap = true;
  pthread_mutex_unlock(&pcapLock);

  pthread_join( pcapThreadID, NULL);
}