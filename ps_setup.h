#ifndef _PS_SETUP_H
#define _PS_SETUP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <math.h>
#include <iostream>
#include <list>
#include <vector>
#include <string>
#include <fstream>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "ps_setup.h"
#include "ps_lib.h"

//Length of an ip prefix
#define PREFIX_SIZE 2

//Number of characters required to store a valid port number in a char array
#define MAX_PORT_SIZE 5

//The length of scan type option
#define OPT_LENGTH 3

//Number of octets in an IPV4 address
#define IP_OCTETS 4

//Number of bits required to hold an octet of ip address
#define OCTET_SIZE 8

//Size of an IPV4 address
#define IP_ADDR_SIZE 32


/**
 * usage(FILE * file) -> void
 *
 * print the usage of this program to the file stream file
 *
 **/
void usage(FILE * file);

/**
 * getDigits(int number ) -> int
 *
 * Returns the number of digits in a number
 *
 **/
int getDigits(int number );

/**
 * getRangeofPortNumbers(char * portRange, list<int> &ports_list, bool &flag) -> void
 *
 * Adds the range of port numbers specified to the list of port numbers
 **/
void getRangeofPortNumbers(char * port, std::list<int> &ports_list, bool &flag);

/**
 * getInputPortValues (char *inputPorts, list<int> &ports_list) -> void
 *
 * Adds the port numbers specified by port option to port numbers list
 **/
void getInputPortValues (char *inputPorts, std::list<int> &ports_list);

/**
 * isValidIPAddress(char* ipAddr) -> bool
 *
 * Returns true if the input ip address is a valid ip address
 **/
bool isValidIPAddress(char* ipAddr);

/**
 * readIPFromFile(char* fileName, list<string> &ipList) -> void
 *
 * Reads the list of ip addresses from the file
 **/
void readIPFromFile(char* fileName, std::list<std::string> &ipList);

/**
 * getBinary(int octet, vector<int> &binaryVal) -> void
 *
 * Converts an integer to binary format
 **/
void getBinary(int octet, std::vector<int> &binaryVal);

/**
 * getBinaryFormatofIP(char* ipAddr, int octetInd, std::vector<int> &binaryIPAddr, int (&ipAddrNw)[IP_OCTETS]) -> void
 *
 * Converts the required octets of ip address into a binary format and stores it in a vector
 * octetInd specifies the number of octets required to be converted to binary format
 **/
void getBinaryFormatofIP(char* ipAddr, int octetInd, std::vector<int> &binaryIPAddr, int (&ipAddrNw)[IP_OCTETS]);

/**
 * getDecimalFromBinary (vector<int> ipList, int octetPos) -> int
 *
 * Converts a binary format of number to decimal format
 **/
int getDecimalFromBinary (std::vector<int> ipList, int octetPos);

/**
 * getIpAddressesFromPrefix(char* ipPrefix, list<string> &ipList) -> void
 *
 * Gets the list of ip addresses for a given prefix
 **/
void getIpAddressesFromPrefix(char* ipPrefix, std::list<std::string> &ipList);

/**
 * parse_args(ps_args_t * ps_args, int argc, char * argv[]) -> void
 *
 * Parse the command line arguments to portScanner using getopt_long and
 * store the result in a structure.
 *
 * ERRORS: Will exit on various errors
 *
 **/
void parse_args(ps_args_t * ps_args, int argc,  char * argv[]);

#endif