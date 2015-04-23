#ifndef _PS_LIB_H
#define _PS_LIB_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <iostream>
#include <list>
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

//Number of characters required to hold an ip address in a char array
#define MAX_IP_LENGTH 15

//The number of scan types available
#define NO_OF_SCAN_TYPES 6

//Index of SYN scan in scan_opt
#define SYN 0;

//Index of NULL scan in scan_opt
#define NULLS 1;

//Index of FIN scan in scan_opt
#define FIN 2;

//Index of XMAS scan in scan_opt
#define XMAS 3;

//Index of ACK scan in scan_opt
#define ACK 4;

//Index of UDP scan in scan_opt
#define UDP 5;

typedef const u_char * packet;

//Holds the input arguments read from the command line
typedef struct {
  //Arguments required to hold port numbers info
  std::list<int> ports_list;

  //Arguments required to hold ip address/prefix/file
  std::list<std::string> ip_addrs;

  //Arguments required to hold multi-threading information
  bool use_threads;
  int no_of_threads;

  //Arguments to hold the scan types information
  bool use_scan;
  int scan_opt[NO_OF_SCAN_TYPES];
  
  //Argument to store the machine's local ip address
  std::string localIP;
} ps_args_t;

//Pseudo header to calculate TCP Header Checksum
struct psdhdr{
  u_int32_t saddr;      // Source Ip address
  u_int32_t daddr;      // Destination IP Address
  u_int8_t rsvdZero;    // Reserved field which contains 8 bits of zeros
  u_int8_t protocol;    // Protocol in IP header
  u_int16_t tcpLength;  // Length of TCP segment including data
};

//Structure of DNS Header
struct dnshdr{
  u_int16_t id;
  unsigned char rd :1;
  unsigned char tc:1;
  unsigned char aa:1;
  unsigned char opcode:4;
  unsigned char qr:1;
  unsigned char rcode:4;
  unsigned char cd:1;
  unsigned char ad:1;
  unsigned char z:1;
  unsigned char ra:1;
  u_int16_t qdcount;
  u_int16_t anscount;
  u_int16_t authcount;
  u_int16_t addcount;
};
 
//Structure of DNS Question
struct dnsquestion{
  u_int16_t qtype;
  u_int16_t qclass;
};
 
//Structure of DNS Query 
typedef struct
{
  unsigned char *qname;
  struct dnsquestion question;    
} dnsquery;

//Structure of DNS Response
struct dnsresponse{
  u_int16_t  type;
  u_int16_t _class;
  unsigned int ttl;
  u_int16_t rdlength;
  unsigned char *rdata;
};

//Structure to store result
struct resultSet {
  int portNum;
  std::string ipAddr;
  std::string conclusion;
  std::string serviceInfo;
  int scanResult[6];

  resultSet() {
    for(int k = 0; k < 6; k++)
	  scanResult[k] = -1;
  }
};

/**
 * createToDoList() -> void
 *
 * Creates a job queue
 **/
void createToDoList();

/**
 * getSourcePort() -> int
 *
 * Gets a source port number
 **/
int getSourcePort();

/**
 * addToMap(std::string ipPortPair, struct resultSet results) -> void
 *
 * Adds the result into a map
 **/
void addToMap(std::string ipPortPair, struct resultSet results);

/**
 * isQueueEmpty() -> bool
 *
 * Checks if the job queue is empty
 **/
bool isQueueEmpty();

/**
 * pickWorkFromQueue() -> string
 *
 * Picks an IP + PortNumber pair from the queue
 **/
std::string pickWorkFromQueue();

/**
 * printArguments() -> void
 *
 * Prints the arguments for Milestone
 **/
void printArguments();

/**
 * getLocalIpAddress(ifreq * ipaddr) -> void
 *
 * Gets the ip addresses of a local machine and stores it in struct type ifreq
 **/
void getLocalIpAddress(ifreq * ipaddr);

/**
 * getConclusion(struct resultSet * result) -> void
 *
 * Gets the conclusion of all the scan results
 **/
void getConclusion(struct resultSet * result);

/**
 * getChecksum(u_int16_t *pktHdr, int length) -> u_int16_t
 *
 * Calculates the checksum of IP/TCP header
 **/
u_int16_t getChecksum(u_int16_t *pktHdr, int length);

/**
 * getTcpChecksum (struct iphdr ipHdr, struct tcphdr tcpHdr) -> unsigned short
 *
 * Gets the checksum of TCP Header
 **/
uint16_t getTcpChecksum (struct iphdr ipHdr, struct tcphdr tcpHdr);

/**
 * printHeader() -> void
 *
 * Prints the header
 **/
void printHeader();

/**
 * string getScantype(int index) -> string
 *
 * Returns the type of scan performed
 **/
std::string getScantype(int index);

/**
 * getPortStatus(int value) -> string
 *
 * Returns the status of port
 **/
std::string getPortStatus(int value);

/**
 * getResults(int scanResults[]) -> void
 *
 * Prints the scan result in an order
 **/
void getResults(int scanResults[]);

/**
 * printResults() -> void
 *
 * Prints the result on the screen
 **/
void printResults();

#endif