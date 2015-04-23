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

using namespace std;

/**
 * usage(FILE * file) -> void
 *
 * Print the usage of this program to the file stream file
 **/
void usage(FILE * file) {
  if(file == NULL){
    file = stdout;
  }

  fprintf(file,
          "portScanner [OPTIONS] \n"
          "  --help                        \t Print this help screen\n"
          "  --ports ports_to_scan         \t Scans 1-1024 ports if this option is not specified.\n"
          "                                \t If specified, scans the individual ports separated by a comma or a range.\n"
          "  --ip ip_addr                  \t Scans the ip address specified in the ip_addr\n"
          "  --prefix ip_prefix            \t Scans the list of ip addresses specified in ip_prefix\n"
          "  --file fileName.txt           \t Scans the list of ip addresses present in the specified file.\n"
          "  --speedup no_of_threads       \t Use multi-threaded version of portScanner,\n"
		  "                                \t no_of_threads is the number of threads to be used.\n"
          "  --scan scan_type              \t Select a subset of scans from {SYN, NULL, FIN, XMAS, ACK, UDP}\n"
		  "                                \t Multiple scans can be specified. All scans performed by default\n");
}

/**
 * getDigits(int number ) -> int
 *
 * Returns the number of digits in a number
 *
 **/
 
int getDigits(int number ){
  int length = 1;
  
  while (number /= 10)
    length ++;

  return length;
}

/**
 * getRangeofPortNumbers(char * portRange, list<int> &ports_list, bool &flag) -> void
 *
 * Adds the range of port numbers specified to the list of port numbers
 **/

void getRangeofPortNumbers(char * port, list<int> &ports_list, bool &flag) {
  int portNum, portNumEnd;
  char *portRange, portInit[MAX_PORT_SIZE];

  portRange = strstr(port, "-");
  strncpy(portInit, port, strlen(port) - strlen(portRange));
  portInit[strlen(port) - strlen(portRange)] = '\0';
  portNum = atoi(portInit);
  portNumEnd = atoi(portRange + 1);

  if(portNumEnd == 0) {
    usage(stderr);
    exit(EXIT_FAILURE);
  }

  for (int i = portNum; i <= portNumEnd; i++){
    if (i >= 0 && i < 65536)
      ports_list.push_back(i);
	else
	  flag = true;
  }
}

/**
 * getInputPortValues (char *inputPorts, list<int> &ports_list) -> void
 *
 * Adds the port numbers specified by port option to port numbers list
 **/

void getInputPortValues (char *inputPorts, list<int> &ports_list) {
  char *port, *portRange, portInit[MAX_PORT_SIZE];
  int portNum, portNumEnd;
  bool flag = false;

  //Add the specified port numbers to list
  port = strtok(inputPorts, ",");

  if(port != NULL) {
    while(port != NULL) {

	  //Check if the range of ports are specified
	  portRange = strstr(port, "-");

	  if( portRange == NULL) {
        portNum = atoi(port);
        if (portNum >= 0 && portNum < 65536) {
          ports_list.push_back(atoi(port));
		}
		else
		  flag = true;
	  }
	  else {
	    getRangeofPortNumbers(port, ports_list, flag);
	  }
	  port = strtok(NULL, ",");
    }
  }
  else  if(strstr(inputPorts, "-") != NULL)
    getRangeofPortNumbers(inputPorts, ports_list, flag);
  
  if (flag)
    printf("\nIgnoring few port numbers whose values exceeded 65535\n\n");
}

/**
 * isValidIPAddress(char* ipAddr) -> bool
 *
 * Returns true if the input ip address is a valid ip address
 **/

bool isValidIPAddress(char* ipAddr) {
  int validIP;
  struct sockaddr_in sa;

  //Convert ip address into network address structure
  validIP = inet_pton(AF_INET, ipAddr, &sa.sin_addr);

  if(validIP != 1)
    return false;
  return true;
}

/**
 * readIPFromFile(char* fileName, list<string> &ipList) -> void
 *
 * Reads the list of ip addresses from the file
 **/

void readIPFromFile(char* fileName, list<string> &ipList) {
  string ipAddr;
  int invalidIpCnt = 0;

  //Open the text file
  ifstream ipFile (fileName, std::ifstream::in);
  if(!ipFile) {
    perror("Error opening the torrent file");
  }

  //Read from the file line by line
  while(!ipFile.eof()){
    ipFile >> ipAddr;
	if(isValidIPAddress((char*)ipAddr.c_str())) {
	  ipList.push_back(ipAddr);
	}
	else
	  invalidIpCnt++;
  }

  //Close the file
  ipFile.close();

  //Check if there are any invalid ip addresses
  if(invalidIpCnt != 0)
    printf("\nIgnoring %d invalid IP addresses read from the file\n\n", invalidIpCnt);
}

/**
 * getBinary(int octet, vector<int> &binaryVal) -> void
 *
 * Converts a given integer to binary format
 **/

void getBinary(int octet, vector<int> &binaryVal) {
  int binaryOctet[OCTET_SIZE], binDigit, i = 0; 

  while(octet != 0) {
    //Find if the octet is even or odd -> add 0 to binaryOctet if even, 1 if odd
    if(octet % 2 == 0)
	  binaryOctet[i] = 0;
	else
	  binaryOctet[i] = 1;

	//Divide by octet by 2
	octet = octet/2;
	i++;
  }

  //Pad with 0's if the octet can be represented in less than 8 bits
  while(i != 8) {
    binaryOctet[i] = 0;
	i++;
  }

  //The binary format just calculated is in the reverse order. Copy it in correct order to the vector
  for (i = (OCTET_SIZE - 1) ; i >= 0; i--)
    binaryVal.push_back(binaryOctet[i]);
}

/**
 * getBinaryFormatofIP(char* ipAddr, vector<int> &binaryIPAddr) -> void
 *
 * Converts the required octets of ip address into a binary format and stores it in a vector
 * octetInd specifies the number of octets required to be converted to binary format
 **/

void getBinaryFormatofIP(char* ipAddr, int octetInd, vector<int> &binaryIPAddr, int (&ipAddrNw)[IP_OCTETS]) {
  char* octetVal;
  int octetPos = 1;

  //Convert the required octet of ip address into binary format
  octetVal = strtok(ipAddr, ".");
  while(octetVal != NULL) {
    ipAddrNw[octetPos - 1] = atoi(octetVal);
	if( octetPos > octetInd)
	  getBinary(atoi(octetVal), binaryIPAddr);
	octetPos++;
	octetVal = strtok(NULL, ".");
  }
}

/**
 * getDecimalFromBinary (vector<int> ipList, int octetPos) -> int
 *
 * Converts a binary format of number to decimal format
 **/

int getDecimalFromBinary (vector<int> ipList, int octetPos) {
  int i,j, decimalVal = 0;
  for(i = (octetPos - 1), j = 0; j < OCTET_SIZE; i--, j++) {
    decimalVal += ipList.at(i) * pow(2,j);
  }

  return decimalVal;
}

/**
 * getIpAddressesFromPrefix(char* ipPrefix, list<string> &ipList) -> void
 *
 * Gets the list of ip addresses for a given prefix
 **/

void getIpAddressesFromPrefix(char* ipPrefix, list<string> &ipList) {
  char *prefix, ipAddr[MAX_IP_LENGTH], addIPAddr[MAX_IP_LENGTH];
  int prefixVal, ipAddrNw[IP_OCTETS], ipAddrBC[IP_OCTETS], octetNum, ipAddrLen;
  vector<int> binaryIPVal, broadcastAddr;

  //Get the prefix value from the input argument
  prefix = strstr(ipPrefix, "/");
  prefixVal = atoi(prefix + 1);

  //Get the IP from the input argument
  strncpy(ipAddr, ipPrefix, strlen(ipPrefix) - strlen(prefix));
  ipAddr[strlen(ipPrefix) - strlen(prefix)] = '\0';

  //Check if the ip and prefix are valid
  if((prefixVal < 1 || prefixVal > 32) || !isValidIPAddress(ipAddr)) {
    printf("\nPlease enter a valid IP/Prefix \n\n");
	usage(stderr);
    exit(EXIT_FAILURE);
  }

  if(prefixVal < 24){
    printf("\nPlease consider scanning a small number of hosts (Minimum Prefix Value: 24)\n\n");
	usage(stderr);
    exit(EXIT_FAILURE);
  }
  //Get the binary format of ip address and store it in a vector
  getBinaryFormatofIP(ipAddr, prefixVal/OCTET_SIZE, binaryIPVal, ipAddrNw);  

  //Holds the value of number octets present in binary format
  octetNum = binaryIPVal.size()/OCTET_SIZE;

  //Get the network address for the given prefix
  for (int i = prefixVal%OCTET_SIZE; i < binaryIPVal.size(); i++)
    binaryIPVal[i] = 0;

  //Get the network address in decimal format and store it in an array
  for(int i = 1; i <= octetNum; i++) {
    ipAddrNw[IP_OCTETS - octetNum + i - 1] = getDecimalFromBinary(binaryIPVal, i * OCTET_SIZE);
  }

  //Copy data from network address array and store it in broadcast address array
  for (int i = 0; i < IP_OCTETS; i++)
    ipAddrBC[i] = ipAddrNw[i];

  //Get the broadcast address for the given prefix
  broadcastAddr = binaryIPVal;
  for (int i = prefixVal%OCTET_SIZE; i < broadcastAddr.size(); i++)
    broadcastAddr[i] = 1;

  //Get the broadcast address in decimal format and store it in an array
  for(int i = 1; i <= octetNum; i++) {
    ipAddrBC[IP_OCTETS - octetNum + i - 1] = getDecimalFromBinary(broadcastAddr, i * OCTET_SIZE);
  }

  while(1) {
    //Construct the IP address and add it to the list
	ipAddrLen = getDigits(ipAddrNw[0]) + getDigits(ipAddrNw[1]) + getDigits(ipAddrNw[2]) + getDigits(ipAddrNw[3]) + IP_OCTETS;
	sprintf(addIPAddr, "%d.%d.%d.%d", ipAddrNw[0], ipAddrNw[1],ipAddrNw[2], ipAddrNw[3]);
	addIPAddr[ipAddrLen] = '\0';
	string newIPAddr(addIPAddr);
    ipList.push_back(addIPAddr);	

	//Exit the loop when last octets of network address and broadcast address are equal
	if(ipAddrBC[IP_OCTETS - 1] == ipAddrNw[IP_OCTETS - 1])
	  break;

	//Increment tha value of last octet of network address to get the next IP address
	ipAddrNw[IP_OCTETS - 1] ++;
  }
}

/**
 * parse_args(ps_args_t * ps_args, int argc, char * argv[]) -> void
 *
 * Parse the command line arguments to portScanner using getopt_long and
 * store the result in a structure.
 *
 * ERRORS: Will exit on various errors
 *
 * Reference - http://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
 **/

void parse_args(ps_args_t * ps_args, int argc,  char * argv[]) {
  int ch;
  bool port_specified = false, flag;
  char scanOption[OPT_LENGTH];

  //Initialise the default values to ps_args
  ps_args->use_threads = false;
  ps_args->use_scan = false;
  ps_args->no_of_threads = 0;
  for (int i = 0 ; i < NO_OF_SCAN_TYPES; i++)
    ps_args->scan_opt[i] = 0;

  while(1) {
    int this_option_optind = optind ? optind : 1;
    int option_index = 0;

	static struct option long_options[] = {
            {"help",     no_argument,       0, 'h' },
            {"ports",    required_argument, 0, 'p' },
            {"ip",       required_argument, 0, 'i' },
            {"prefix",   required_argument, 0, 'r' },
            {"file",     required_argument, 0, 'f' },
            {"speedup",  required_argument, 0, 's' },
			{"scan",     required_argument, 0, 'c' },
            {0,          0,                 0,  0  }
        };

    //Read the option from the command line
    ch = getopt_long (argc, argv, "hp:i:r:f:s:c:", long_options, &option_index);

	//Check for end of options
	if (ch == -1)
	  break;

	switch(ch) {
	  //help
	  case 'h': 
        usage(stdout);
        exit(EXIT_SUCCESS);
        break;

	  //ports
	  case 'p':
	    //Check for invalid inputs of port numbers
		if(!isdigit(optarg[0]) || !isdigit(optarg[strlen(optarg) - 1])) {
		  usage(stderr);
          exit(EXIT_FAILURE);
		}
	    port_specified = true;
	    getInputPortValues(optarg, ps_args->ports_list);
	    break;

	  //ip
	  case 'i':
	    if(isValidIPAddress(optarg)) {
		  string ipAddr(optarg);
		  ps_args->ip_addrs.push_back(ipAddr);
		}
		else {
		  printf("\nPlease enter a valid IP address\n\n");
		  usage(stderr);
          exit(EXIT_FAILURE);
		}
		break;

	  //prefix
	  case 'r':
	    getIpAddressesFromPrefix(optarg, ps_args->ip_addrs);
	    break;

      //file
	  case 'f':
	    readIPFromFile(optarg, ps_args->ip_addrs);
	    break;

	  //speedup
	  case 's':
	    ps_args->use_threads = true;
		ps_args->no_of_threads = atoi(optarg);
		if(ps_args->no_of_threads > 30) {
		  printf("The maximum number of threads allowed is 30.\n\n");
		  usage(stderr);
          exit(EXIT_FAILURE);
		}
		break;

	  //scan
      case 'c':
	    ps_args->use_scan = true;
		strcpy(scanOption, optarg);
		do{
		  //Set 1 in scan_options if a scan option is specified
		  if(strcmp(scanOption, "SYN") == 0)
		    ps_args->scan_opt[0] = 1;
		  else if (strcmp(scanOption, "NULL") == 0)
		    ps_args->scan_opt[1] = 1;
		  else if (strcmp(scanOption, "FIN") == 0)
		    ps_args->scan_opt[2] = 1;
		  else if (strcmp(scanOption, "XMAS") == 0)
		    ps_args->scan_opt[3] = 1;
		  else if (strcmp(scanOption, "ACK") == 0)
		    ps_args->scan_opt[4] = 1;
		  else if (strcmp(scanOption, "UDP") == 0)
		    ps_args->scan_opt[5] = 1;

		  //Increment the optind value from second iteration of loop
		  if(strcmp(scanOption, optarg) != 0)
		    optind++;

		  //Exit the loop if there are no more scan options
		  if(optind >= argc)
		    break;
		  else if(argv[optind][0] == '-') {
		    optind--;
			break;
		  }
		  //Copy the next scan option to scanOption array
		  strcpy(scanOption, argv[optind]);
		} while(1);
	    break;

      default:
	    usage(stderr);
        exit(EXIT_FAILURE);
	    break;
	}
  }

  //If the ports option is not specified
  if(!port_specified) {
    for( int i = 0; i < 1024; i++)
      ps_args->ports_list.push_back(i);
  }

  //If the ip list is empty, exit the program
  if (ps_args->ip_addrs.empty()) {
    printf("\nPlease enter at least one valid host address to scan.\n\n");
	usage(stderr);
    exit(EXIT_FAILURE);
  }

  //Check for improper input of SYN option
  flag = false;
  if(ps_args->use_scan) {
    for(int i = 0 ; i < NO_OF_SCAN_TYPES; i++) {
	  if( ps_args->scan_opt[i] == 1){
	    flag = true;
		break;
	  }
	}
    if(!flag) {
	  printf("\nPlease enter the scan options separated by a space.\n\n");
	  usage(stderr);
      exit(EXIT_FAILURE);
	}
  }
}