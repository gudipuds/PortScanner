#ifndef _PS_HELPER_H
#define _PS_HELPER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <iostream>
#include <string>

/**
 * getServiceName(int portNum, std::string serviceInfo) -> string
 *
 * Gets the service name for set of 0-1024 ports
 **/
std::string getServiceName(int portNum, std::string serviceInfo);

#endif