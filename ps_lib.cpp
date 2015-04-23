#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <iostream>
#include <list>
#include <queue>
#include <map>
#include <algorithm>
#include <string>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>

#include "ps_setup.h"
#include "ps_lib.h"
#include "ps_helper.h"

extern int sourcePort;
extern ps_args_t ps_args;
extern std::queue<std::string> workQueue;
extern std::map<std::string, resultSet> finalResults;
extern pthread_mutex_t sourcePortLock, workQueueLock, finalResultsLock;

/**
 * getSourcePort() -> int
 *
 * Gets a source port number
 **/
int getSourcePort() {
  int sourcePrt;

  pthread_mutex_lock(&sourcePortLock);
  sourcePrt = sourcePort++;
  pthread_mutex_unlock(&sourcePortLock);

  return sourcePrt;
}

/**
 * addToMap(std::string ipPortPair, struct resultSet results) -> void
 *
 * Adds the result into a map
 **/
void addToMap(std::string ipPortPair, struct resultSet results) {

  pthread_mutex_lock(&finalResultsLock);
  finalResults[ipPortPair] = results;
  pthread_mutex_unlock(&finalResultsLock);

}

/**
 * createToDoList() -> void
 *
 * Creates a job queue
 **/
void createToDoList(){
  char temp[6];
  memset(temp, 0,sizeof(temp));

  for (std::list<std::string>::iterator it = ps_args.ip_addrs.begin(); it != ps_args.ip_addrs.end(); ++it) {
    for (std::list<int>::iterator it2 = ps_args.ports_list.begin(); it2 != ps_args.ports_list.end(); ++it2) {
	  std::string ipAddress (*it);
	  sprintf( temp, "%d", *it2);
	  temp[getDigits(*it2)+1] = '\0';
	  std::string port(temp);
	  std::string work(ipAddress+"+"+port);
      workQueue.push(work);	   
	}
  }
}

/**
 * isQueueEmpty() -> bool
 *
 * Checks if the job queue is empty
 **/
bool isQueueEmpty(){
  bool isEmpty;

  pthread_mutex_lock( &workQueueLock );
  isEmpty = workQueue.empty();
  pthread_mutex_unlock( &workQueueLock );

  return isEmpty;
}

/**
 * pickWorkFromQueue() -> string
 *
 * Picks an IP + PortNumber pair from the queue
 **/
std::string pickWorkFromQueue(){
  pthread_mutex_lock( &workQueueLock );
  std::string work (workQueue.front());
  workQueue.pop();
  pthread_mutex_unlock( &workQueueLock );

  return work;
}

/**
 * printArguments() -> void
 *
 * Prints the arguments for Milestone
 **/
void printArguments() {
  //Printing IP Addresses for MileStone1
  std::cout << "List of IP Addresses:" << std::endl; 
  for (std::list<std::string>::iterator it = ps_args.ip_addrs.begin(); it!= ps_args.ip_addrs.end(); ++it)
    std::cout << *it << std::endl;
  std::cout << std::endl;

  //Printing the list of port numbers
  std::cout << "Ports List" << std::endl;
  for (std::list<int>::iterator it = ps_args.ports_list.begin(); it!= ps_args.ports_list.end(); ++it)
    std::cout << *it << ' ';
  std::cout << std::endl << std::endl;

  //Printing the list of scan options selected
  std::cout << "Scan options selected" << std::endl;
  for (int i = 0 ; i < NO_OF_SCAN_TYPES; i++)
    std::cout << " " << ps_args.scan_opt[i];
  std::cout << std::endl;
}

/**
 * getLocalIpAddress(ifreq * ipaddr) -> void
 *
 * Gets the ip addresses of a local machine and stores it in struct type ifreq
 **/
void getLocalIpAddress(ifreq * ipaddr) {
  int sockfd;

  //Open a socket connection for TCP
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  //Since we are looking for IPV4 address, setting the sa_family to AF_INET
  ipaddr->ifr_addr.sa_family = AF_INET;

  //Getting the ip address attached to Ethernet(Interface of established connection)
  strcpy(ipaddr->ifr_name, "eth0");

  //Using ioctl to obtain the ip address of the machine
  ioctl(sockfd, SIOCGIFADDR, ipaddr);

  //Closing the socket connection
  close(sockfd);
}

/**
 * getChecksum(uint16_t *pktHdr, int length) -> uint16_t
 *
 * Calculates the checksum of IP/TCP header
 **/
uint16_t getChecksum(uint16_t *pktHdr, int length) {
  uint32_t chkSum = 0;

  //Calculate the cumulative sum of every 16-bit words
  for(int i = 0; i < length/2; i++){
    chkSum += pktHdr[i];

	//If there is any carry beyond 16 bits, add it to the 16-bit checksum value
    while(chkSum >> 16)
      chkSum = (chkSum >> 16) + (chkSum & 0xffff);
  }

  //Get the one's complement of checksum value
  chkSum = ~chkSum;

  return (uint16_t)chkSum;
}

/**
 * getTcpChecksum (struct iphdr ipHdr, struct tcphdr tcpHdr) -> unsigned short
 *
 * Gets the checksum of TCP Header
 **/
uint16_t getTcpChecksum (struct iphdr ipHdr, struct tcphdr tcpHdr) {
  int len = sizeof(tcphdr) + sizeof(psdhdr);
  unsigned char pseudoPacket[len]; // = new unsigned char[sizeof(tcphdr) + sizeof(psdhdr)];
  struct psdhdr pseudoHdr;

  pseudoHdr.saddr = ipHdr.saddr;
  pseudoHdr.daddr = ipHdr.daddr;
  pseudoHdr.rsvdZero = 0;
  pseudoHdr.protocol = IPPROTO_TCP;
  pseudoHdr.tcpLength = htons(sizeof(tcphdr));

  memcpy(pseudoPacket, &pseudoHdr, sizeof(psdhdr));
  memcpy(pseudoPacket + sizeof(psdhdr), &tcpHdr, sizeof(tcphdr));

  return getChecksum((u_int16_t *)pseudoPacket, sizeof(tcphdr) + sizeof(psdhdr));
}

/**
 * getConclusion(struct resultSet * result) -> void
 *
 * Gets the conclusion of all the scan results
 **/
void getConclusion(struct resultSet * result) {
  //SYN and UDP are the only scans that can determine if the port is open
  if(result->scanResult[0] == 1 || result->scanResult[5] == 1){
    result->conclusion = "OPEN";
  }
  //Check if any of the scans returns a closed port
  else if(result->scanResult[0] == 2 || result->scanResult[1] == 2 || result->scanResult[2] == 2 
          || result->scanResult[3] == 2 || result->scanResult[5] == 2){
	result->conclusion = "Closed";
  }
  //Check for filtered
  else if (result->scanResult[1] == 3 || result->scanResult[2] == 3 
          || result->scanResult[3] == 3 || result->scanResult[4] == 3 || result->scanResult[5] == 3) {
	result->conclusion = "Filtered";
  }
  //Check if ACK returns unfiltered
  else if(result->scanResult[4] == 4) {
    if ( result->scanResult[0] == 5 || result->scanResult[1] == 5 || result->scanResult[2] == 5 
	     || result->scanResult[3] == 5 || result->scanResult[5] == 5)
	  result->conclusion = "Open";
	else
      result->conclusion = "Unfiltered";
  }
  else
    result->conclusion = "Open|Filtered";
}

/**
 * string getScantype(int index) -> string
 *
 * Returns the type of scan performed
 **/
std::string getScantype(int index) {
  std::string scanType;

  switch(index) {
    case 0:
	  scanType = "SYN";
	  break;

	case 1:
	  scanType = "NULL";
	  break;

	case 2:
	  scanType = "FIN";
	  break;

	case 3:
	  scanType = "XMAS";
	  break;

	case 4:
	  scanType = "ACK";
	  break;

	case 5:
	  scanType = "UDP";
	  break;
  }

  return scanType;
}

/**
 * getPortStatus(int value) -> string
 *
 * Returns the status of port
 **/
std::string getPortStatus(int value) {
  std::string portStatus;

  switch(value) {
    case 1:
	  portStatus = "Open";
	  break;

	case 2:
	  portStatus = "Closed";
	  break;

	case 3:
	  portStatus = "Filtered";
	  break;

	case 4:
	  portStatus = "Unfiltered";
	  break;

	case 5:
	  portStatus = "Open|Filtered";
	  break;

	default:
	  portStatus = "N/A";
	  break;
  }

  return portStatus;
}

/**
 * getResults(int scanResults[]) -> void
 *
 * Prints the scan result in an order
 **/
void getResults(int scanResults[]) {
  std::string resultOutput = "";
  for(int i = 0 ; i < 6; i++){
    resultOutput = " ";
	resultOutput = getScantype(i) + "(" + getPortStatus(scanResults[i]) + ")";
    printf("%-19s  ", resultOutput.c_str());
  }
}

/**
 * printHeader() -> void
 *
 * Prints the header
 **/
void printHeader() {
  printf("Port \tServiceName (If Applicable)  \t\tResults\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t Conclusion\n");
  printf("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
}

/**
 * printResults() -> void
 *
 * Prints the result on the screen
 **/
void printResults() {
  bool openFlag = false, closeFlag = false;
  std::string serviceNam;
  std::string ipPortPair;

  //Print the results group by IP Address
  for (std::list<std::string>::iterator it = ps_args.ip_addrs.begin(); it != ps_args.ip_addrs.end(); ++it) {
    openFlag = false;
	closeFlag = false;

	//Print the list of open ports
    for (std::map<std::string,resultSet>::iterator it2 = finalResults.begin(); it2 != finalResults.end(); ++it2) {
	  if(*it == it2->second.ipAddr) {

	    //Check for open ports
	    if(it2->second.conclusion == "OPEN") {
		  if(!openFlag) {
		    printf("IP Address: %s\n", it2->second.ipAddr.c_str());
		    printf("Open Ports:\n\n");
		    printHeader();
			openFlag = true;
		  }
		  printf("%-5d\t", it2->second.portNum);
		  if(it2->second.portNum >= 0 && it2->second.portNum <= 1024){
		    serviceNam = getServiceName(it2->second.portNum, it2->second.serviceInfo);
		  }else
		    serviceNam = " ";
		  printf("%-32s\t", serviceNam.c_str());
		  getResults(it2->second.scanResult);
		  printf("%-10s\n\n", it2->second.conclusion.c_str());
		  //Erase from the map
		  finalResults.erase(*it);
		}
	  }
	}

	printf("\n\n");

	//Print list of closed/filtered/unfiltered ports
	for (std::map<std::string,resultSet>::iterator it2 = finalResults.begin(); it2 != finalResults.end(); ++it2) {
	  if(*it == it2->second.ipAddr) {

	    //Check for open ports
	    if(it2->second.conclusion != "OPEN") {
		  if(!closeFlag) {
		    printf("IP Address: %s\n", it2->second.ipAddr.c_str());
		    printf("Closed|Filtered|Unfiltered Ports:\n\n");
		    printHeader();
			closeFlag = true;
		  }
		  printf("%-5d\t", it2->second.portNum);
		  if(it2->second.portNum >= 0 && it2->second.portNum <= 1024){
		    serviceNam = getServiceName(it2->second.portNum, it2->second.serviceInfo);
		  }else
		    serviceNam = " ";
		  printf("%-32s\t", serviceNam.c_str());
		  getResults(it2->second.scanResult);
		  printf("%-10s\n\n", it2->second.conclusion.c_str());
		  //Erase from the map
		  finalResults.erase(*it);
		}
	  }
	}
  }
  printf("* Ports not running expected service\n\n");
}