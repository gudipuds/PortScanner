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
std::string getServiceName(int portNum, std::string serviceInfo) {
  std::string serviceName;

  switch(portNum) {
    case 0: 
      serviceName = "Reserved";
      break;

    case 1: 
      serviceName = "TcpMux";
      break;

    case 2: 
      serviceName = "Management Utility";
      break;

    case 3: 
      serviceName = "Compression Process";
      break;

    case 4: 
      serviceName = "Unassigned";
      break;

    case 5: 
      serviceName = "Remote Job Entry";
      break;

    case 6: 
      serviceName = "Unassigned";
      break;

    case 7: 
      serviceName = "Echo";
      break;

    case 8: 
      serviceName = "Unassigned";
      break;

    case 9: 
      serviceName = "Discard";
      break;

    case 10: 
      serviceName = "Unassigned";
      break;

    case 11: 
      serviceName = "Active Users";
      break;

    case 12: 
      serviceName = "Unassigned";
      break;

    case 13: 
      serviceName = "Daytime";
      break;

    case 14: 
      serviceName = "Unassigned";
      break;

    case 15: 
      serviceName = "Unassigned";
      break;

    case 16: 
      serviceName = "Unassigned";
      break;

    case 17: 
      serviceName = "Quote of the Day";
      break;

    case 18: 
      serviceName = "Message Send Protocol";
      break;

    case 19: 
      serviceName = "Character Generator";
      break;

    case 20: 
      serviceName = "File Transfer";
      break;

    case 21: 
      serviceName = "File Transfer";
      break;

    case 22:
      if(serviceInfo != "UNKNOWN"){
	    serviceName = serviceInfo;
	  }
      else	  
        serviceName = "SSH*";
      break;

    case 23: 
      serviceName = "Telnet";
      break;

    case 24: 
	  if(serviceInfo != "UNKNOWN"){
	    serviceName = serviceInfo;
	  }
      else	  
        serviceName = "Private Mail System*";
      break;

    case 25: 
	  if(serviceInfo != "UNKNOWN"){
	    serviceName = serviceInfo;
	  }
      else
        serviceName = "SMTP*";
      break;

    case 26: 
      serviceName = "Unassigned";
      break;

    case 27: 
      serviceName = "NSW User System FE";
      break;

    case 28: 
      serviceName = "Unassigned";
      break;

    case 29: 
      serviceName = "MSG ICP";
      break;

    case 30: 
      serviceName = "Unassigned";
      break;

    case 31: 
      serviceName = "MSG Authentication";
      break;

    case 32: 
      serviceName = "Unassigned";
      break;

    case 33: 
      serviceName = "Display Support Protocol";
      break;

    case 34: 
      serviceName = "Unassigned";
      break;

    case 35: 
      serviceName = "Any Private Printer Srvr";
      break;

    case 36: 
      serviceName = "Unassigned";
      break;

    case 37: 
      serviceName = "Time";
      break;

    case 38: 
      serviceName = "Route Access Protocol";
      break;

    case 39: 
      serviceName = "Resource Location Protocol";
      break;

    case 40: 
      serviceName = "Unassigned";
      break;

    case 41: 
      serviceName = "Graphics";
      break;

    case 42: 
      serviceName = "Host Name Server";
      break;

    case 43: 
	  if(serviceInfo != "UNKNOWN"){
	    serviceName = serviceInfo;
	  }
      else
        serviceName = "WHOIS*";
      break;

    case 44: 
      serviceName = "MPM FLAGS Protocol";
      break;

    case 45: 
      serviceName = "Message Processing Module";
      break;

    case 46: 
      serviceName = "MPM";
      break;

    case 47: 
      serviceName = "NI FTP";
      break;

    case 48: 
      serviceName = "Digital Audit Daemon";
      break;

    case 49: 
      serviceName = "Login Host Protocol (TACACS)";
      break;

    case 50: 
      serviceName = "Remote Mail Checking Protocl";
      break;

    case 51: 
      serviceName = "Reserved";
      break;

    case 52: 
      serviceName = "XNS Time Protocol";
      break;

    case 53: 
      serviceName = "Domain Name Server";
      break;

    case 54: 
      serviceName = "XNS Clearinghouse";
      break;

    case 55: 
      serviceName = "ISI Graphics Language";
      break;

    case 56: 
      serviceName = "XNS Authentication";
      break;

    case 57: 
      serviceName = "Any Private Terminal Access";
      break;

    case 58: 
      serviceName = "XNS Mail";
      break;

    case 59: 
      serviceName = "Any Private File Service";
      break;

    case 60: 
      serviceName = "Unassigned";
      break;

    case 61: 
      serviceName = "NI MAIL";
      break;

    case 62: 
      serviceName = "ACA Services";
      break;

    case 63: 
      serviceName = "WhoIs++";
      break;

    case 64: 
      serviceName = "Communications Integrator";
      break;

    case 65: 
      serviceName = "TACACS-Database Service";
      break;

    case 66: 
      serviceName = "Oracle SQL*NET";
      break;

    case 67: 
      serviceName = "Bootstrap Protocol Server";
      break;

    case 68: 
      serviceName = "Bootstrap Protocol Client";
      break;

    case 69: 
      serviceName = "Trivial File Transfer";
      break;

    case 70: 
      serviceName = "Gopher";
      break;

    case 71: 
      serviceName = "Remote Job Service";
      break;

    case 72: 
      serviceName = "Remote Job Service";
      break;

    case 73: 
      serviceName = "Remote Job Service";
      break;

    case 74: 
      serviceName = "Remote Job Service";
      break;

    case 75: 
      serviceName = "Any Private DialOut Servc";
      break;

    case 76: 
      serviceName = "DEOS";
      break;

    case 77: 
      serviceName = "Any Private RJE Service";
      break;

    case 78: 
      serviceName = "vettcp";
      break;

    case 79: 
      serviceName = "Finger";
      break;

    case 80: 
	  if(serviceInfo != "UNKNOWN"){
	    serviceName = serviceInfo;
	  }
      else
        serviceName = "WWW HTTP*";
      break;

    case 81: 
      serviceName = "Unassigned";
      break;

    case 82: 
      serviceName = "XFER Utility";
      break;

    case 83: 
      serviceName = "MIT ML Device";
      break;

    case 84: 
      serviceName = "Common Trace Facility";
      break;

    case 85: 
      serviceName = "MIT ML Device";
      break;

    case 86: 
      serviceName = "Micro Focus Cobol";
      break;

    case 87: 
      serviceName = "Any Private Terminal Link";
      break;

    case 88: 
      serviceName = "Kerberos";
      break;

    case 89: 
      serviceName = "SU/MIT Telnet Gateway";
      break;

    case 90: 
      serviceName = "DNSIX";
      break;

    case 91: 
      serviceName = "MIT Dover Spooler";
      break;

    case 92: 
      serviceName = "Network Printing Protocol";
      break;

    case 93: 
      serviceName = "Device Control Protocol";
      break;

    case 94: 
      serviceName = "Tivoli Object Dispatcher";
      break;

    case 95: 
      serviceName = "SUPDUP";
      break;

    case 96: 
      serviceName = "DIXIE Protocol Spec";
      break;

    case 97: 
      serviceName = "Swift Remote Virtual File";
      break;

    case 98: 
      serviceName = "TAC News";
      break;

    case 99: 
      serviceName = "Metagram Relay";
      break;

    case 100: 
      serviceName = "Unassigned";
      break;

    case 101: 
      serviceName = "NIC Host Name Server";
      break;

    case 102: 
      serviceName = "ISO-TSAP Class 0";
      break;

    case 103: 
      serviceName = "gppitnp";
      break;

    case 104: 
      serviceName = "ACR-NEMA";
      break;

    case 105: 
      serviceName = "CCSO name server protocol";
      break;

    case 106: 
      serviceName = "3COM-TSMUX";
      break;

    case 107: 
      serviceName = "Remote Telnet Service";
      break;

    case 108: 
      serviceName = "SNA Gateway Access Server";
      break;

    case 109: 
      serviceName = "Post Office Protocol Ver 2";
      break;

    case 110: 
	  if(serviceInfo != "UNKNOWN"){
	    serviceName = serviceInfo;
	  }
      else
        serviceName = "POP Ver 3*";
      break;

    case 111: 
      serviceName = "SUN Remote Procedure Call";
      break;

    case 112: 
      serviceName = "McIDAS";
      break;

    case 113: 
      serviceName = "Authentication Service";
      break;

    case 114: 
      serviceName = "Unassigned";
      break;

    case 115: 
      serviceName = "Simple File Transfer Protocl";
      break;

    case 116: 
      serviceName = "ANSA REX Notify";
      break;

    case 117: 
      serviceName = "UUCP Path Service";
      break;

    case 118: 
      serviceName = "SQL Services";
      break;

    case 119: 
      serviceName = "NNTP";
      break;

    case 120: 
      serviceName = "CFDPTKT";
      break;

    case 121: 
      serviceName = "ERPC";
      break;

    case 122: 
      serviceName = "SMAKYNET";
      break;

    case 123: 
      serviceName = "Network Time Protocol";
      break;

    case 124: 
      serviceName = "ANSA REX Trader";
      break;

    case 125: 
      serviceName = "Locus-Map";
      break;

    case 126: 
      serviceName = "NXEdit";
      break;

    case 127: 
      serviceName = "Locus-Con";
      break;

    case 128: 
      serviceName = "GSS X License Verification";
      break;

    case 129: 
      serviceName = "Password Generator Protocol";
      break;

    case 130: 
      serviceName = "Cisco FNATIVE";
      break;

    case 131: 
      serviceName = "Cisco TNATIVE";
      break;

    case 132: 
      serviceName = "Cisco SYSMAINT";
      break;

    case 133: 
      serviceName = "Statistics Service";
      break;

    case 134: 
      serviceName = "INGRES-NET Service";
      break;

    case 135: 
      serviceName = "DCE endpoint resolution";
      break;

    case 136: 
      serviceName = "PROFILE Naming System";
      break;

    case 137: 
      serviceName = "NETBIOS Name Service";
      break;

    case 138: 
      serviceName = "NETBIOS Datagram Service";
      break;

    case 139: 
      serviceName = "NETBIOS Session Service";
      break;

    case 140: 
      serviceName = "EMFIS Data Service";
      break;

    case 141: 
      serviceName = "EMFIS Control Service";
      break;

    case 142: 
      serviceName = "Britton-Lee IDM";
      break;

    case 143: 
	  if(serviceInfo != "UNKNOWN"){
	    serviceName = serviceInfo;
	  }
      else
        serviceName = "IMAP*";
      break;

    case 144: 
      serviceName = "UMA";
      break;

    case 145: 
      serviceName = "UAAC Protocol";
      break;

    case 146: 
      serviceName = "ISO-IP0";
      break;

    case 147: 
      serviceName = "ISO-IP";
      break;

    case 148: 
      serviceName = "Jargon";
      break;

    case 149: 
      serviceName = "AED 512 Emulation Service";
      break;

    case 150: 
      serviceName = "SQL-NET";
      break;

    case 151: 
      serviceName = "HEMS";
      break;

    case 152: 
      serviceName = "BFTP";
      break;

    case 153: 
      serviceName = "SGMP";
      break;

    case 154: 
      serviceName = "NETSC";
      break;

    case 155: 
      serviceName = "NETSC";
      break;

    case 156: 
      serviceName = "SQL Service";
      break;

    case 157: 
      serviceName = "KNET-CMP";
      break;

    case 158: 
      serviceName = "PCMail Server";
      break;

    case 159: 
      serviceName = "NSS-Routing";
      break;

    case 160: 
      serviceName = "SGMP-TRAPS";
      break;

    case 161: 
      serviceName = "SNMP";
      break;

    case 162: 
      serviceName = "SNMPTRAP";
      break;

    case 163: 
      serviceName = "CMIP/TCP Manager";
      break;

    case 164: 
      serviceName = "CMIP/TCP Agent";
      break;

    case 165: 
      serviceName = "Xerox";
      break;

    case 166: 
      serviceName = "Sirius Systems";
      break;

    case 167: 
      serviceName = "NAMP";
      break;

    case 168: 
      serviceName = "RSVD";
      break;

    case 169: 
      serviceName = "SEND";
      break;

    case 170: 
      serviceName = "Network PostScript";
      break;

    case 171: 
      serviceName = "Multiplex";
      break;

    case 172: 
      serviceName = "CL/1";
      break;

    case 173: 
      serviceName = "Xyplex";
      break;

    case 174: 
      serviceName = "MAILQ";
      break;

    case 175: 
      serviceName = "VMNET";
      break;

    case 176: 
      serviceName = "GENRAD-MUX";
      break;

    case 177: 
      serviceName = "XDMCP";
      break;

    case 178: 
      serviceName = "NextStep Window Server";
      break;

    case 179: 
      serviceName = "Border Gateway Protocol";
      break;

    case 180: 
      serviceName = "Intergraph";
      break;

    case 181: 
      serviceName = "Unify";
      break;

    case 182: 
      serviceName = "Unisys Audit SITP";
      break;

    case 183: 
      serviceName = "OCBinder";
      break;

    case 184: 
      serviceName = "OCServer";
      break;

    case 185: 
      serviceName = "Remote-KIS";
      break;

    case 186: 
      serviceName = "KIS Protocol";
      break;

    case 187: 
      serviceName = "ACI";
      break;

    case 188: 
      serviceName = "Plus Five's MUMPS";
      break;

    case 189: 
      serviceName = "Queued File Transport";
      break;

    case 190: 
      serviceName = "GACP";
      break;

    case 191: 
      serviceName = "Prospero Directory Service";
      break;

    case 192: 
      serviceName = "OSU-NMS";
      break;

    case 193: 
      serviceName = "SRMP";
      break;

    case 194: 
      serviceName = "Internet Relay Chat Protocol";
      break;

    case 195: 
      serviceName = "DNSIX NLM Aud";
      break;

    case 196: 
      serviceName = "DNSIX SMM Red";
      break;

    case 197: 
      serviceName = "Directory Location Service";
      break;

    case 198: 
      serviceName = "DLS-Mon";
      break;

    case 199: 
      serviceName = "SMUX";
      break;

    case 200: 
      serviceName = "System Resource Controller";
      break;

    case 201: 
      serviceName = "AT-RTMP";
      break;

    case 202: 
      serviceName = "AppleTalk Name Binding";
      break;

    case 203: 
      serviceName = "AppleTalk Unused";
      break;

    case 204: 
      serviceName = "AppleTalk Echo";
      break;

    case 205: 
      serviceName = "AppleTalk Unused";
      break;

    case 206: 
      serviceName = "AppleTalk Zone Information";
      break;

    case 207: 
      serviceName = "AppleTalk Unused";
      break;

    case 208: 
      serviceName = "AppleTalk Unused";
      break;

    case 209: 
      serviceName = "Quick Mail Transfer Protocol";
      break;

    case 210: 
      serviceName = "ANSI Z39.50";
      break;

    case 211: 
      serviceName = "914C/G Terminal";
      break;

    case 212: 
      serviceName = "ATEXSSTR";
      break;

    case 213: 
      serviceName = "IPX";
      break;

    case 214: 
      serviceName = "VM PWSCS";
      break;

    case 215: 
      serviceName = "Insignia Solutions";
      break;

    case 216: 
      serviceName = "CSiLiC";
      break;

    case 217: 
      serviceName = "dBASE Unix";
      break;

    case 218: 
      serviceName = "Message Posting Protocol";
      break;

    case 219: 
      serviceName = "Unisys ARPs";
      break;

    case 220: 
      serviceName = "IMAP 3";
      break;

    case 221: 
      serviceName = "FLN-SPX";
      break;

    case 222: 
      serviceName = "RSH-SPX";
      break;

    case 223: 
      serviceName = "CDC";
      break;

    case 224: 
      serviceName = "masqdialer";
      break;

    case 225: 
      serviceName = "Reserved";
      break;

    case 226: 
      serviceName = "Reserved";
      break;

    case 227: 
      serviceName = "Reserved";
      break;

    case 228: 
      serviceName = "Reserved";
      break;

    case 229: 
      serviceName = "Reserved";
      break;

    case 230: 
      serviceName = "Reserved";
      break;

    case 231: 
      serviceName = "Reserved";
      break;

    case 232: 
      serviceName = "Reserved";
      break;

    case 233: 
      serviceName = "Reserved";
      break;

    case 234: 
      serviceName = "Reserved";
      break;

    case 235: 
      serviceName = "Reserved";
      break;

    case 236: 
      serviceName = "Reserved";
      break;

    case 237: 
      serviceName = "Reserved";
      break;

    case 238: 
      serviceName = "Reserved";
      break;

    case 239: 
      serviceName = "Reserved";
      break;

    case 240: 
      serviceName = "Reserved";
      break;

    case 241: 
      serviceName = "Reserved";
      break;

    case 242: 
      serviceName = "Direct";
      break;

    case 243: 
      serviceName = "Survey Measurement";
      break;

    case 244: 
      serviceName = "inbusiness";
      break;

    case 245: 
      serviceName = "LINK";
      break;

    case 246: 
      serviceName = "Display Systems Protocol";
      break;

    case 247: 
      serviceName = "SUBNTBCST_TFTP";
      break;

    case 248: 
      serviceName = "bhfhs";
      break;

    case 249: 
      serviceName = "Reserved";
      break;

    case 250: 
      serviceName = "Reserved";
      break;

    case 251: 
      serviceName = "Reserved";
      break;

    case 252: 
      serviceName = "Reserved";
      break;

    case 253: 
      serviceName = "Reserved";
      break;

    case 254: 
      serviceName = "Reserved";
      break;

    case 255: 
      serviceName = "Reserved";
      break;

    case 256: 
      serviceName = "RAP";
      break;

    case 257: 
      serviceName = "SET";
      break;

    case 258: 
      serviceName = "Unassigned";
      break;

    case 259: 
      serviceName = "ESRO-Gen";
      break;

    case 260: 
      serviceName = "Openport";
      break;

    case 261: 
      serviceName = "nsiiops";
      break;

    case 262: 
      serviceName = "Arcisdms";
      break;

    case 263: 
      serviceName = "HDAP";
      break;

    case 264: 
      serviceName = "BGMP";
      break;

    case 265: 
      serviceName = "X-Bone CTL";
      break;

    case 266: 
      serviceName = "SCSI on ST";
      break;

    case 267: 
      serviceName = "Tobit David Service Layer";
      break;

    case 268: 
      serviceName = "Tobit David Replica";
      break;

    case 269: 
      serviceName = "MANET Protocols";
      break;

    case 270: 
      serviceName = "GIST";
      break;

    case 271: 
      serviceName = "Reserved";
      break;

    case 272: 
      serviceName = "Unassigned";
      break;

    case 273: 
      serviceName = "Unassigned";
      break;

    case 274: 
      serviceName = "Unassigned";
      break;

    case 275: 
      serviceName = "Unassigned";
      break;

    case 276: 
      serviceName = "Unassigned";
      break;

    case 277: 
      serviceName = "Unassigned";
      break;

    case 278: 
      serviceName = "Unassigned";
      break;

    case 279: 
      serviceName = "Unassigned";
      break;

    case 280: 
      serviceName = "http-mgmt";
      break;

    case 281: 
      serviceName = "Personal Link";
      break;

    case 282: 
      serviceName = "Cable Port A/X";
      break;

    case 283: 
      serviceName = "rescap";
      break;

    case 284: 
      serviceName = "corerjd";
      break;

    case 285: 
      serviceName = "Unassigned";
      break;

    case 286: 
      serviceName = "FXP Communication";
      break;

    case 287: 
      serviceName = "K-BLOCK";
      break;

    case 288: 
      serviceName = "Unassigned";
      break;

    case 289: 
      serviceName = "Unassigned";
      break;

    case 290: 
      serviceName = "Unassigned";
      break;

    case 291: 
      serviceName = "Unassigned";
      break;

    case 292: 
      serviceName = "Unassigned";
      break;

    case 293: 
      serviceName = "Unassigned";
      break;

    case 294: 
      serviceName = "Unassigned";
      break;

    case 295: 
      serviceName = "Unassigned";
      break;

    case 296: 
      serviceName = "Unassigned";
      break;

    case 297: 
      serviceName = "Unassigned";
      break;

    case 298: 
      serviceName = "Unassigned";
      break;

    case 299: 
      serviceName = "Unassigned";
      break;

    case 300: 
      serviceName = "Unassigned";
      break;

    case 301: 
      serviceName = "Unassigned";
      break;

    case 302: 
      serviceName = "Unassigned";
      break;

    case 303: 
      serviceName = "Unassigned";
      break;

    case 304: 
      serviceName = "Unassigned";
      break;

    case 305: 
      serviceName = "Unassigned";
      break;

    case 306: 
      serviceName = "Unassigned";
      break;

    case 307: 
      serviceName = "Unassigned";
      break;

    case 308: 
      serviceName = "Novastor Backup";
      break;

    case 309: 
      serviceName = "EntrustTime";
      break;

    case 310: 
      serviceName = "bhmds";
      break;

    case 311: 
      serviceName = "AppleShare IP WebAdmin";
      break;

    case 312: 
      serviceName = "VSLMP";
      break;

    case 313: 
      serviceName = "Magenta Logic";
      break;

    case 314: 
      serviceName = "Opalis Robot";
      break;

    case 315: 
      serviceName = "DPSI";
      break;

    case 316: 
      serviceName = "decAuth";
      break;

    case 317: 
      serviceName = "Zannet";
      break;

    case 318: 
      serviceName = "PKIX TimeStamp";
      break;

    case 319: 
      serviceName = "PTP Event";
      break;

    case 320: 
      serviceName = "PTP General";
      break;

    case 321: 
      serviceName = "PIP";
      break;

    case 322: 
      serviceName = "RTSPS";
      break;

    case 323: 
      serviceName = "Reserved";
      break;

    case 324: 
      serviceName = "Reserved";
      break;

    case 325: 
      serviceName = "Unassigned";
      break;

    case 326: 
      serviceName = "Unassigned";
      break;

    case 327: 
      serviceName = "Unassigned";
      break;

    case 328: 
      serviceName = "Unassigned";
      break;

    case 329: 
      serviceName = "Unassigned";
      break;

    case 330: 
      serviceName = "Unassigned";
      break;

    case 331: 
      serviceName = "Unassigned";
      break;

    case 332: 
      serviceName = "Unassigned";
      break;

    case 333: 
      serviceName = "Texar Security Port";
      break;

    case 334: 
      serviceName = "Unassigned";
      break;

    case 335: 
      serviceName = "Unassigned";
      break;

    case 336: 
      serviceName = "Unassigned";
      break;

    case 337: 
      serviceName = "Unassigned";
      break;

    case 338: 
      serviceName = "Unassigned";
      break;

    case 339: 
      serviceName = "Unassigned";
      break;

    case 340: 
      serviceName = "Unassigned";
      break;

    case 341: 
      serviceName = "Unassigned";
      break;

    case 342: 
      serviceName = "Unassigned";
      break;

    case 343: 
      serviceName = "Unassigned";
      break;

    case 344: 
      serviceName = "Prospero Data Access Protocl";
      break;

    case 345: 
      serviceName = "Perf Analysis Workbench";
      break;

    case 346: 
      serviceName = "Zebra server";
      break;

    case 347: 
      serviceName = "Fatmen Server";
      break;

    case 348: 
      serviceName = "Cabletron Management Protocl";
      break;

    case 349: 
      serviceName = "mftp";
      break;

    case 350: 
      serviceName = "MATIP Type A";
      break;

    case 351: 
      serviceName = "MATIP Type B";
      break;

    case 352: 
      serviceName = "DTAG";
      break;

    case 353: 
      serviceName = "NDSAUTH";
      break;

    case 354: 
      serviceName = "bh611";
      break;

    case 355: 
      serviceName = "DATEX-ASN";
      break;

    case 356: 
      serviceName = "Cloanto Net 1";
      break;

    case 357: 
      serviceName = "bhevent";
      break;

    case 358: 
      serviceName = "Shrinkwrap";
      break;

    case 359: 
      serviceName = "NSRMP";
      break;

    case 360: 
      serviceName = "scoi2odialog";
      break;

    case 361: 
      serviceName = "Semantix";
      break;

    case 362: 
      serviceName = "SRS Send";
      break;

    case 363: 
      serviceName = "RSVP Tunnel";
      break;

    case 364: 
      serviceName = "Aurora CMGR";
      break;

    case 365: 
      serviceName = "DTK";
      break;

    case 366: 
      serviceName = "ODMR";
      break;

    case 367: 
      serviceName = "MortgageWare";
      break;

    case 368: 
      serviceName = "QbikGDP";
      break;

    case 369: 
      serviceName = "rpc2portmap";
      break;

    case 370: 
      serviceName = "codaauth2";
      break;

    case 371: 
      serviceName = "Clearcase";
      break;

    case 372: 
      serviceName = "ListProcessor";
      break;

    case 373: 
      serviceName = "Legent Corporation";
      break;

    case 374: 
      serviceName = "Legent Corporation";
      break;

    case 375: 
      serviceName = "Hassle";
      break;

    case 376: 
      serviceName = "Network Inquiry Protocol";
      break;

    case 377: 
      serviceName = "NEC Corporation";
      break;

    case 378: 
      serviceName = "NEC Corporation";
      break;

    case 379: 
      serviceName = "TIA/EIA/IS-99 modem client";
      break;

    case 380: 
      serviceName = "TIA/EIA/IS-99 modem server";
      break;

    case 381: 
      serviceName = "HP-Collector";
      break;

    case 382: 
      serviceName = "HP-managed-node";
      break;

    case 383: 
      serviceName = "HP-alarm-mgr";
      break;

    case 384: 
      serviceName = "ARNS";
      break;

    case 385: 
      serviceName = "IBM Application";
      break;

    case 386: 
      serviceName = "ASA";
      break;

    case 387: 
      serviceName = "AURP";
      break;

    case 388: 
      serviceName = "Unidata LDM";
      break;

    case 389: 
      serviceName = "LDAP";
      break;

    case 390: 
      serviceName = "UIS";
      break;

    case 391: 
      serviceName = "SynOptics SNMP Relay Port";
      break;

    case 392: 
      serviceName = "SynOptics Port Broker Port";
      break;

    case 393: 
      serviceName = "Meta5";
      break;

    case 394: 
      serviceName = "EMBL Nucleic Data Transfer";
      break;

    case 395: 
      serviceName = "NetScout Control Protocol";
      break;

    case 396: 
      serviceName = "Novell Netware over IP";
      break;

    case 397: 
      serviceName = "Multi Protocol Trans. Net";
      break;

    case 398: 
      serviceName = "Kryptolan";
      break;

    case 399: 
      serviceName = "ISO-TSAP-C2";
      break;

    case 400: 
      serviceName = "Oracle Secure Backup";
      break;

    case 401: 
      serviceName = "Uninterruptible Power Supply";
      break;

    case 402: 
      serviceName = "Genie Protocol";
      break;

    case 403: 
      serviceName = "decap";
      break;

    case 404: 
      serviceName = "nced";
      break;

    case 405: 
      serviceName = "ncld";
      break;

    case 406: 
      serviceName = "IMSP";
      break;

    case 407: 
      serviceName = "Timbuktu";
      break;

    case 408: 
      serviceName = "PRM-SM";
      break;

    case 409: 
      serviceName = "PRM-NM";
      break;

    case 410: 
      serviceName = "DECLadebug";
      break;

    case 411: 
      serviceName = "Remote MT Protocol";
      break;

    case 412: 
      serviceName = "Trap Convention Port";
      break;

    case 413: 
      serviceName = "SMSP";
      break;

    case 414: 
      serviceName = "InfoSeek";
      break;

    case 415: 
      serviceName = "BNet";
      break;

    case 416: 
      serviceName = "Silverplatter";
      break;

    case 417: 
      serviceName = "Onmux";
      break;

    case 418: 
      serviceName = "Hyper-G";
      break;

    case 419: 
      serviceName = "Ariel 1";
      break;

    case 420: 
      serviceName = "SMPTE";
      break;

    case 421: 
      serviceName = "Ariel 2";
      break;

    case 422: 
      serviceName = "Ariel 3";
      break;

    case 423: 
      serviceName = "OPC-Job-Start";
      break;

    case 424: 
      serviceName = "OPC-Job-Track";
      break;

    case 425: 
      serviceName = "ICAD";
      break;

    case 426: 
      serviceName = "smartsdp";
      break;

    case 427: 
      serviceName = "Server Location";
      break;

    case 428: 
      serviceName = "OCS_CMU";
      break;

    case 429: 
      serviceName = "OCS_AMU";
      break;

    case 430: 
      serviceName = "UTMPSD";
      break;

    case 431: 
      serviceName = "UTMPCD";
      break;

    case 432: 
      serviceName = "IASD";
      break;

    case 433: 
      serviceName = "NNSP";
      break;

    case 434: 
      serviceName = "MobileIP-Agent";
      break;

    case 435: 
      serviceName = "MobilIP-MN";
      break;

    case 436: 
      serviceName = "DNA-CML";
      break;

    case 437: 
      serviceName = "comscm";
      break;

    case 438: 
      serviceName = "dsfgw";
      break;

    case 439: 
      serviceName = "dasp";
      break;

    case 440: 
      serviceName = "sgcp";
      break;

    case 441: 
      serviceName = "decvms-sysmgt";
      break;

    case 442: 
      serviceName = "cvc_hostd";
      break;

    case 443: 
      serviceName = "HTTPS";
      break;

    case 444: 
      serviceName = "SNPP";
      break;

    case 445: 
      serviceName = "Microsoft-DS";
      break;

    case 446: 
      serviceName = "DDM-RDB";
      break;

    case 447: 
      serviceName = "DDM-DFM";
      break;

    case 448: 
      serviceName = "DDM-SSL";
      break;

    case 449: 
      serviceName = "AS Server Mapper";
      break;

    case 450: 
      serviceName = "TServer";
      break;

    case 451: 
      serviceName = "Cray Network Semaphore srvr";
      break;

    case 452: 
      serviceName = "Cray SFS config server";
      break;

    case 453: 
      serviceName = "CreativeServer";
      break;

    case 454: 
      serviceName = "ContentServer";
      break;

    case 455: 
      serviceName = "CreativePartnr";
      break;

    case 456: 
      serviceName = "macon-tcp";
      break;

    case 457: 
      serviceName = "scohelp";
      break;

    case 458: 
      serviceName = "apple quick time";
      break;

    case 459: 
      serviceName = "ampr-rcmd";
      break;

    case 460: 
      serviceName = "skronk";
      break;

    case 461: 
      serviceName = "DataRampSrv";
      break;

    case 462: 
      serviceName = "DataRampSrvSec";
      break;

    case 463: 
      serviceName = "alpes";
      break;

    case 464: 
      serviceName = "kpasswd";
      break;

    case 465: 
      serviceName = "IGMP over UDP for SSM";
      break;

    case 466: 
      serviceName = "digital-vrc";
      break;

    case 467: 
      serviceName = "mylex-mapd";
      break;

    case 468: 
      serviceName = "proturis";
      break;

    case 469: 
      serviceName = "Radio Control Protocol";
      break;

    case 470: 
      serviceName = "scx-proxy";
      break;

    case 471: 
      serviceName = "Mondex";
      break;

    case 472: 
      serviceName = "ljk-login";
      break;

    case 473: 
      serviceName = "hybrid-pop";
      break;

    case 474: 
      serviceName = "tn-tl-w1";
      break;

    case 475: 
      serviceName = "tcpnethaspsrv";
      break;

    case 476: 
      serviceName = "tn-tl-fd1";
      break;

    case 477: 
      serviceName = "ss7ns";
      break;

    case 478: 
      serviceName = "spsc";
      break;

    case 479: 
      serviceName = "iafserver";
      break;

    case 480: 
      serviceName = "iafdbase";
      break;

    case 481: 
      serviceName = "Ph service";
      break;

    case 482: 
      serviceName = "bgs-nsi";
      break;

    case 483: 
      serviceName = "ulpnet";
      break;

    case 484: 
      serviceName = "Integra-SME";
      break;

    case 485: 
      serviceName = "Air Soft Power Burst";
      break;

    case 486: 
      serviceName = "avian";
      break;

    case 487: 
      serviceName = "SAFT";
      break;

    case 488: 
      serviceName = "gss-http";
      break;

    case 489: 
      serviceName = "nest-protocol";
      break;

    case 490: 
      serviceName = "micom-pfs";
      break;

    case 491: 
      serviceName = "go-login";
      break;

    case 492: 
      serviceName = "TICF-1";
      break;

    case 493: 
      serviceName = "TICF-2";
      break;

    case 494: 
      serviceName = "POV-Ray";
      break;

    case 495: 
      serviceName = "intecourier";
      break;

    case 496: 
      serviceName = "PIM-RP-DISC";
      break;

    case 497: 
      serviceName = "Retrospect";
      break;

    case 498: 
      serviceName = "siam";
      break;

    case 499: 
      serviceName = "ISO ILL Protocol";
      break;

    case 500: 
      serviceName = "isakmp";
      break;

    case 501: 
      serviceName = "STMF";
      break;

    case 502: 
      serviceName = "Modbus Application Protocol";
      break;

    case 503: 
      serviceName = "Intrinsa";
      break;

    case 504: 
      serviceName = "citadel";
      break;

    case 505: 
      serviceName = "mailbox-lm";
      break;

    case 506: 
      serviceName = "ohimsrv";
      break;

    case 507: 
      serviceName = "crs";
      break;

    case 508: 
      serviceName = "xvttp";
      break;

    case 509: 
      serviceName = "snare";
      break;

    case 510: 
      serviceName = "FirstClass Protocol";
      break;

    case 511: 
      serviceName = "PassGo";
      break;

    case 512: 
      serviceName = "remote process execution";
      break;

    case 513: 
      serviceName = "remote login a la telnet";
      break;

    case 514: 
      serviceName = "cmd like exec";
      break;

    case 515: 
      serviceName = "spooler";
      break;

    case 516: 
      serviceName = "videotex";
      break;

    case 517: 
      serviceName = "like tenex link";
      break;

    case 518: 
      serviceName = "Ntalk";
      break;

    case 519: 
      serviceName = "unixtime";
      break;

    case 520: 
      serviceName = "local routing process";
      break;

    case 521: 
      serviceName = "ripng";
      break;

    case 522: 
      serviceName = "ULP";
      break;

    case 523: 
      serviceName = "IBM-DB2";
      break;

    case 524: 
      serviceName = "NCP";
      break;

    case 525: 
      serviceName = "timeserver";
      break;

    case 526: 
      serviceName = "newdate";
      break;

    case 527: 
      serviceName = "Stock IXChange";
      break;

    case 528: 
      serviceName = "Customer IXChange";
      break;

    case 529: 
      serviceName = "IRC-SERV";
      break;

    case 530: 
      serviceName = "rpc";
      break;

    case 531: 
      serviceName = "chat";
      break;

    case 532: 
      serviceName = "readnews";
      break;

    case 533: 
      serviceName = "for emergency broadcasts";
      break;

    case 534: 
      serviceName = "windream Admin";
      break;

    case 535: 
      serviceName = "iiop";
      break;

    case 536: 
      serviceName = "opalis-rdv";
      break;

    case 537: 
      serviceName = "NMSP";
      break;

    case 538: 
      serviceName = "gdomap";
      break;

    case 539: 
      serviceName = "Apertus Idp";
      break;

    case 540: 
      serviceName = "uucpd";
      break;

    case 541: 
      serviceName = "uucp-rlogin";
      break;

    case 542: 
      serviceName = "commerce";
      break;

    case 543: 
      serviceName = "klogin";
      break;

    case 544: 
      serviceName = "krcmd";
      break;

    case 545: 
      serviceName = "appleqtcsrvr";
      break;

    case 546: 
      serviceName = "DHCPv6 Client";
      break;

    case 547: 
      serviceName = "DHCPv6 Server";
      break;

    case 548: 
      serviceName = "AFP over TCP";
      break;

    case 549: 
      serviceName = "IDFP";
      break;

    case 550: 
      serviceName = "new-who";
      break;

    case 551: 
      serviceName = "cybercash";
      break;

    case 552: 
      serviceName = "DeviceShare";
      break;

    case 553: 
      serviceName = "pirp";
      break;

    case 554: 
      serviceName = "RTSP";
      break;

    case 555: 
      serviceName = "dsf";
      break;

    case 556: 
      serviceName = "rfs server";
      break;

    case 557: 
      serviceName = "openvms-sysipc";
      break;

    case 558: 
      serviceName = "SDNSKMP";
      break;

    case 559: 
      serviceName = "TEEDTAP";
      break;

    case 560: 
      serviceName = "rmonitord";
      break;

    case 561: 
      serviceName = "monitor";
      break;

    case 562: 
      serviceName = "chcmd";
      break;

    case 563: 
      serviceName = "nntp protocol over TLS/SSL";
      break;

    case 564: 
      serviceName = "plan 9 file service";
      break;

    case 565: 
      serviceName = "whoami";
      break;

    case 566: 
      serviceName = "streettalk";
      break;

    case 567: 
      serviceName = "banyan-rpc";
      break;

    case 568: 
      serviceName = "microsoft shuttle";
      break;

    case 569: 
      serviceName = "microsoft rome";
      break;

    case 570: 
      serviceName = "demon";
      break;

    case 571: 
      serviceName = "udemon";
      break;

    case 572: 
      serviceName = "sonar";
      break;

    case 573: 
      serviceName = "banyan-vip";
      break;

    case 574: 
      serviceName = "FTP Software Agent System";
      break;

    case 575: 
      serviceName = "VEMMI";
      break;

    case 576: 
      serviceName = "ipcd";
      break;

    case 577: 
      serviceName = "vnas";
      break;

    case 578: 
      serviceName = "ipdd";
      break;

    case 579: 
      serviceName = "decbsrv";
      break;

    case 580: 
      serviceName = "SNTP HEARTBEAT";
      break;

    case 581: 
      serviceName = "Bundle Discovery Protocol";
      break;

    case 582: 
      serviceName = "SCC Security";
      break;

    case 583: 
      serviceName = "Philips Video-Conferencing";
      break;

    case 584: 
      serviceName = "Key Server";
      break;

    case 585: 
      serviceName = "De-registered";
      break;

    case 586: 
      serviceName = "Password Change";
      break;

    case 587:
      if(serviceInfo != "UNKNOWN"){
	    serviceName = serviceInfo;
	  }
      else	
        serviceName = "Message Submission*";
      break;

    case 588: 
      serviceName = "CAL";
      break;

    case 589: 
      serviceName = "EyeLink";
      break;

    case 590: 
      serviceName = "TNS CML";
      break;

    case 591: 
      serviceName = "FileMaker";
      break;

    case 592: 
      serviceName = "Eudora Set";
      break;

    case 593: 
      serviceName = "HTTP RPC Ep Map";
      break;

    case 594: 
      serviceName = "TPIP";
      break;

    case 595: 
      serviceName = "CAB Protocol";
      break;

    case 596: 
      serviceName = "SMSD";
      break;

    case 597: 
      serviceName = "PTC Name Service";
      break;

    case 598: 
      serviceName = "SCO Web Server Manager 3";
      break;

    case 599: 
      serviceName = "Aeolon Core Protocol";
      break;

    case 600: 
      serviceName = "Sun IPC server";
      break;

    case 601: 
      serviceName = "Reliable Syslog Service";
      break;

    case 602: 
      serviceName = "XML-RPC over BEEP";
      break;

    case 603: 
      serviceName = "IDXP";
      break;

    case 604: 
      serviceName = "TUNNEL";
      break;

    case 605: 
      serviceName = "SOAP over BEEP";
      break;

    case 606: 
      serviceName = "Unified Resource Manager";
      break;

    case 607: 
      serviceName = "nqs";
      break;

    case 608: 
      serviceName = "Sift-uft";
      break;

    case 609: 
      serviceName = "npmp-trap";
      break;

    case 610: 
      serviceName = "npmp-local";
      break;

    case 611: 
      serviceName = "npmp-gui";
      break;

    case 612: 
      serviceName = "HMMP Indication";
      break;

    case 613: 
      serviceName = "HMMP Operation";
      break;

    case 614: 
      serviceName = "SSLshell";
      break;

    case 615: 
      serviceName = "sco-inetmgr";
      break;

    case 616: 
      serviceName = "sco-sysmgr";
      break;

    case 617: 
      serviceName = "sco-dtmgr";
      break;

    case 618: 
      serviceName = "DEI-ICDA";
      break;

    case 619: 
      serviceName = "Compaq EVM";
      break;

    case 620: 
      serviceName = "SCO WebServer Manager";
      break;

    case 621: 
      serviceName = "ESCP";
      break;

    case 622: 
      serviceName = "Collaborator";
      break;

    case 623: 
      serviceName = "ASF RMCP";
      break;

    case 624: 
      serviceName = "Crypto Admin";
      break;

    case 625: 
      serviceName = "DEC DLM";
      break;

    case 626: 
      serviceName = "ASIA";
      break;

    case 627: 
      serviceName = "PassGo Tivoli";
      break;

    case 628: 
      serviceName = "QMQP";
      break;

    case 629: 
      serviceName = "3Com AMP3";
      break;

    case 630: 
      serviceName = "RDA";
      break;

    case 631: 
      serviceName = "IPP";
      break;

    case 632: 
      serviceName = "bmpp";
      break;

    case 633: 
      serviceName = "Service Status update";
      break;

    case 634: 
      serviceName = "ginad";
      break;

    case 635: 
      serviceName = "RLZ DBase";
      break;

    case 636: 
      serviceName = "ldap protocol over TLS/SSL";
      break;

    case 637: 
      serviceName = "lanserver";
      break;

    case 638: 
      serviceName = "mcns-sec";
      break;

    case 639: 
      serviceName = "MSDP";
      break;

    case 640: 
      serviceName = "entrust-sps";
      break;

    case 641: 
      serviceName = "repcmd";
      break;

    case 642: 
      serviceName = "ESRO-EMSDP V1.3";
      break;

    case 643: 
      serviceName = "SANity";
      break;

    case 644: 
      serviceName = "dwr";
      break;

    case 645: 
      serviceName = "PSSC";
      break;

    case 646: 
      serviceName = "LDP";
      break;

    case 647: 
      serviceName = "DHCP Failover";
      break;

    case 648: 
      serviceName = "Registry Registrar Proto";
      break;

    case 649: 
      serviceName = "Cadview-3d";
      break;

    case 650: 
      serviceName = "OBEX";
      break;

    case 651: 
      serviceName = "IEEE MMS";
      break;

    case 652: 
      serviceName = "HELLO_PORT";
      break;

    case 653: 
      serviceName = "RepCmd";
      break;

    case 654: 
      serviceName = "AODV";
      break;

    case 655: 
      serviceName = "TINC";
      break;

    case 656: 
      serviceName = "SPMP";
      break;

    case 657: 
      serviceName = "RMC";
      break;

    case 658: 
      serviceName = "TenFold";
      break;

    case 659: 
      serviceName = "Removed";
      break;

    case 660: 
      serviceName = "MacOS Server Admin";
      break;

    case 661: 
      serviceName = "HAP";
      break;

    case 662: 
      serviceName = "PFTP";
      break;

    case 663: 
      serviceName = "PureNoise";
      break;

    case 664: 
      serviceName = "ASF Secure RMCP";
      break;

    case 665: 
      serviceName = "Sun DR";
      break;

    case 666: 
      serviceName = "doom Id Software";
      break;

    case 667: 
      serviceName = "Disclose";
      break;

    case 668: 
      serviceName = "MeComm";
      break;

    case 669: 
      serviceName = "MeRegister";
      break;

    case 670: 
      serviceName = "VACDSM-SWS";
      break;

    case 671: 
      serviceName = "VACDSM-APP";
      break;

    case 672: 
      serviceName = "VPPS-QUA";
      break;

    case 673: 
      serviceName = "CIMPLEX";
      break;

    case 674: 
      serviceName = "ACAP";
      break;

    case 675: 
      serviceName = "DCTP";
      break;

    case 676: 
      serviceName = "VPPS Via";
      break;

    case 677: 
      serviceName = "Virtual Presence Protocol";
      break;

    case 678: 
      serviceName = "GGF-NCP";
      break;

    case 679: 
      serviceName = "MRM";
      break;

    case 680: 
      serviceName = "entrust-aaas";
      break;

    case 681: 
      serviceName = "entrust-aams";
      break;

    case 682: 
      serviceName = "XFR";
      break;

    case 683: 
      serviceName = "CORBA IIOP";
      break;

    case 684: 
      serviceName = "CORBA IIOP SSL";
      break;

    case 685: 
      serviceName = "MDC Port Mapper";
      break;

    case 686: 
      serviceName = "HCP Wismar";
      break;

    case 687: 
      serviceName = "asipregistry";
      break;

    case 688: 
      serviceName = "ApplianceWare mgnt protocol";
      break;

    case 689: 
      serviceName = "NMAP";
      break;

    case 690: 
      serviceName = "VATP";
      break;

    case 691: 
      serviceName = "MS Exchange Routing";
      break;

    case 692: 
      serviceName = "Hyperwave-ISP";
      break;

    case 693: 
      serviceName = "almanid Connection Endpoint";
      break;

    case 694: 
      serviceName = "ha-cluster";
      break;

    case 695: 
      serviceName = "IEEE-MMS-SSL";
      break;

    case 696: 
      serviceName = "RUSHD";
      break;

    case 697: 
      serviceName = "UUIDGEN";
      break;

    case 698: 
      serviceName = "OLSR";
      break;

    case 699: 
      serviceName = "Access Network";
      break;

    case 700: 
      serviceName = "EPP";
      break;

    case 701: 
      serviceName = "Link Management Protocol";
      break;

    case 702: 
      serviceName = "IRIS over BEEP";
      break;

    case 703: 
      serviceName = "Unassigned";
      break;

    case 704: 
      serviceName = "errlog copy/server daemon";
      break;

    case 705: 
      serviceName = "AgentX";
      break;

    case 706: 
      serviceName = "SILC";
      break;

    case 707: 
      serviceName = "Borland DSJ";
      break;

    case 708: 
      serviceName = "Unassigned";
      break;

    case 709: 
      serviceName = "Entrust KMSH";
      break;

    case 710: 
      serviceName = "Entrust ASH";
      break;

    case 711: 
      serviceName = "Cisco TDP";
      break;

    case 712: 
      serviceName = "TBRPF";
      break;

    case 713: 
      serviceName = "IRIS over XPC";
      break;

    case 714: 
      serviceName = "IRIS over XPCS";
      break;

    case 715: 
      serviceName = "IRIS-LWZ";
      break;

    case 716: 
      serviceName = "PANA Messages";
      break;

    case 717: 
      serviceName = "Unassigned";
      break;

    case 718: 
      serviceName = "Unassigned";
      break;

    case 719: 
      serviceName = "Unassigned";
      break;

    case 720: 
      serviceName = "Unassigned";
      break;

    case 721: 
      serviceName = "Unassigned";
      break;

    case 722: 
      serviceName = "Unassigned";
      break;

    case 723: 
      serviceName = "Unassigned";
      break;

    case 724: 
      serviceName = "Unassigned";
      break;

    case 725: 
      serviceName = "Unassigned";
      break;

    case 726: 
      serviceName = "Unassigned";
      break;

    case 727: 
      serviceName = "Unassigned";
      break;

    case 728: 
      serviceName = "Unassigned";
      break;

    case 729: 
      serviceName = "NetView DM1";
      break;

    case 730: 
      serviceName = "NetView DM2";
      break;

    case 731: 
      serviceName = "NetView DM3";
      break;

    case 732: 
      serviceName = "Unassigned";
      break;

    case 733: 
      serviceName = "Unassigned";
      break;

    case 734: 
      serviceName = "Unassigned";
      break;

    case 735: 
      serviceName = "Unassigned";
      break;

    case 736: 
      serviceName = "Unassigned";
      break;

    case 737: 
      serviceName = "Unassigned";
      break;

    case 738: 
      serviceName = "Unassigned";
      break;

    case 739: 
      serviceName = "Unassigned";
      break;

    case 740: 
      serviceName = "Unassigned";
      break;

    case 741: 
      serviceName = "netGW";
      break;

    case 742: 
      serviceName = "Network based Rev";
      break;

    case 743: 
      serviceName = "Unassigned";
      break;

    case 744: 
      serviceName = "Flexible License Manager";
      break;

    case 745: 
      serviceName = "Unassigned";
      break;

    case 746: 
      serviceName = "Unassigned";
      break;

    case 747: 
      serviceName = "Fujitsu Device Control";
      break;

    case 748: 
      serviceName = "RIS-CM";
      break;

    case 749: 
      serviceName = "kerberos administration";
      break;

    case 750: 
      serviceName = "kerberos version iv";
      break;

    case 751: 
      serviceName = "pump";
      break;

    case 752: 
      serviceName = "qrh";
      break;

    case 753: 
      serviceName = "rrh";
      break;

    case 754: 
      serviceName = "send";
      break;

    case 755: 
      serviceName = "Unassigned";
      break;

    case 756: 
      serviceName = "Unassigned";
      break;

    case 757: 
      serviceName = "NULL";
      break;

    case 758: 
      serviceName = "nlogin";
      break;

    case 759: 
      serviceName = "con";
      break;

    case 760: 
      serviceName = "ns";
      break;

    case 761: 
      serviceName = "rxe";
      break;

    case 762: 
      serviceName = "quotad";
      break;

    case 763: 
      serviceName = "cycleserv";
      break;

    case 764: 
      serviceName = "omserv";
      break;

    case 765: 
      serviceName = "webster";
      break;

    case 766: 
      serviceName = "Unassigned";
      break;

    case 767: 
      serviceName = "phone";
      break;

    case 768: 
      serviceName = "Unassigned";
      break;

    case 769: 
      serviceName = "vid";
      break;

    case 770: 
      serviceName = "cadlock";
      break;

    case 771: 
      serviceName = "rtip";
      break;

    case 772: 
      serviceName = "cycleserv2";
      break;

    case 773: 
      serviceName = "submit";
      break;

    case 774: 
      serviceName = "rpasswd";
      break;

    case 775: 
      serviceName = "entomb";
      break;

    case 776: 
      serviceName = "wpages";
      break;

    case 777: 
      serviceName = "Multiling HTTP";
      break;

    case 778: 
      serviceName = "Unassigned";
      break;

    case 779: 
      serviceName = "Unassigned";
      break;

    case 780: 
      serviceName = "wpgs";
      break;

    case 781: 
      serviceName = "Unassigned";
      break;

    case 782: 
      serviceName = "Unassigned";
      break;

    case 783: 
      serviceName = "Unassigned";
      break;

    case 784: 
      serviceName = "Unassigned";
      break;

    case 785: 
      serviceName = "Unassigned";
      break;

    case 786: 
      serviceName = "Unassigned";
      break;

    case 787: 
      serviceName = "Unassigned";
      break;

    case 788: 
      serviceName = "Unassigned";
      break;

    case 789: 
      serviceName = "Unassigned";
      break;

    case 790: 
      serviceName = "Unassigned";
      break;

    case 791: 
      serviceName = "Unassigned";
      break;

    case 792: 
      serviceName = "Unassigned";
      break;

    case 793: 
      serviceName = "Unassigned";
      break;

    case 794: 
      serviceName = "Unassigned";
      break;

    case 795: 
      serviceName = "Unassigned";
      break;

    case 796: 
      serviceName = "Unassigned";
      break;

    case 797: 
      serviceName = "Unassigned";
      break;

    case 798: 
      serviceName = "Unassigned";
      break;

    case 799: 
      serviceName = "Unassigned";
      break;

    case 800: 
      serviceName = "mdbs-daemon";
      break;

    case 801: 
      serviceName = "device";
      break;

    case 802: 
      serviceName = "Modbus Protocol Secure";
      break;

    case 803: 
      serviceName = "Unassigned";
      break;

    case 804: 
      serviceName = "Unassigned";
      break;

    case 805: 
      serviceName = "Unassigned";
      break;

    case 806: 
      serviceName = "Unassigned";
      break;

    case 807: 
      serviceName = "Unassigned";
      break;

    case 808: 
      serviceName = "Unassigned";
      break;

    case 809: 
      serviceName = "Unassigned";
      break;

    case 810: 
      serviceName = "FCP";
      break;

    case 811: 
      serviceName = "Unassigned";
      break;

    case 812: 
      serviceName = "Unassigned";
      break;

    case 813: 
      serviceName = "Unassigned";
      break;

    case 814: 
      serviceName = "Unassigned";
      break;

    case 815: 
      serviceName = "Unassigned";
      break;

    case 816: 
      serviceName = "Unassigned";
      break;

    case 817: 
      serviceName = "Unassigned";
      break;

    case 818: 
      serviceName = "Unassigned";
      break;

    case 819: 
      serviceName = "Unassigned";
      break;

    case 820: 
      serviceName = "Unassigned";
      break;

    case 821: 
      serviceName = "Unassigned";
      break;

    case 822: 
      serviceName = "Unassigned";
      break;

    case 823: 
      serviceName = "Unassigned";
      break;

    case 824: 
      serviceName = "Unassigned";
      break;

    case 825: 
      serviceName = "Unassigned";
      break;

    case 826: 
      serviceName = "Unassigned";
      break;

    case 827: 
      serviceName = "Unassigned";
      break;

    case 828: 
      serviceName = "itm-mcell-s";
      break;

    case 829: 
      serviceName = "PKIX-3 CA/RA";
      break;

    case 830: 
      serviceName = "NETCONF over SSH";
      break;

    case 831: 
      serviceName = "NETCONF over BEEP";
      break;

    case 832: 
      serviceName = "NETCONF over HTTPS";
      break;

    case 833: 
      serviceName = "NETCONF over BEEP";
      break;

    case 834: 
      serviceName = "Unassigned";
      break;

    case 835: 
      serviceName = "Unassigned";
      break;

    case 836: 
      serviceName = "Unassigned";
      break;

    case 837: 
      serviceName = "Unassigned";
      break;

    case 838: 
      serviceName = "Unassigned";
      break;

    case 839: 
      serviceName = "Unassigned";
      break;

    case 840: 
      serviceName = "Unassigned";
      break;

    case 841: 
      serviceName = "Unassigned";
      break;

    case 842: 
      serviceName = "Unassigned";
      break;

    case 843: 
      serviceName = "Unassigned";
      break;

    case 844: 
      serviceName = "Unassigned";
      break;

    case 845: 
      serviceName = "Unassigned";
      break;

    case 846: 
      serviceName = "Unassigned";
      break;

    case 847: 
      serviceName = "DHCP-Failover 2";
      break;

    case 848: 
      serviceName = "GDOI";
      break;

    case 849: 
      serviceName = "Unassigned";
      break;

    case 850: 
      serviceName = "Unassigned";
      break;

    case 851: 
      serviceName = "Unassigned";
      break;

    case 852: 
      serviceName = "Unassigned";
      break;

    case 853: 
      serviceName = "Unassigned";
      break;

    case 854: 
      serviceName = "Unassigned";
      break;

    case 855: 
      serviceName = "Unassigned";
      break;

    case 856: 
      serviceName = "Unassigned";
      break;

    case 857: 
      serviceName = "Unassigned";
      break;

    case 858: 
      serviceName = "Unassigned";
      break;

    case 859: 
      serviceName = "Unassigned";
      break;

    case 860: 
      serviceName = "iSCSI";
      break;

    case 861: 
      serviceName = "OWAMP-Control";
      break;

    case 862: 
      serviceName = "TWAMP Control";
      break;

    case 863: 
      serviceName = "Unassigned";
      break;

    case 864: 
      serviceName = "Unassigned";
      break;

    case 865: 
      serviceName = "Unassigned";
      break;

    case 866: 
      serviceName = "Unassigned";
      break;

    case 867: 
      serviceName = "Unassigned";
      break;

    case 868: 
      serviceName = "Unassigned";
      break;

    case 869: 
      serviceName = "Unassigned";
      break;

    case 870: 
      serviceName = "Unassigned";
      break;

    case 871: 
      serviceName = "Unassigned";
      break;

    case 872: 
      serviceName = "Unassigned";
      break;

    case 873: 
      serviceName = "rsync";
      break;

    case 874: 
      serviceName = "Unassigned";
      break;

    case 875: 
      serviceName = "Unassigned";
      break;

    case 876: 
      serviceName = "Unassigned";
      break;

    case 877: 
      serviceName = "Unassigned";
      break;

    case 878: 
      serviceName = "Unassigned";
      break;

    case 879: 
      serviceName = "Unassigned";
      break;

    case 880: 
      serviceName = "Unassigned";
      break;

    case 881: 
      serviceName = "Unassigned";
      break;

    case 882: 
      serviceName = "Unassigned";
      break;

    case 883: 
      serviceName = "Unassigned";
      break;

    case 884: 
      serviceName = "Unassigned";
      break;

    case 885: 
      serviceName = "Unassigned";
      break;

    case 886: 
      serviceName = "ICL coNETion locate server";
      break;

    case 887: 
      serviceName = "ICL coNETion server info";
      break;

    case 888: 
      serviceName = "CD Database Protocol";
      break;

    case 889: 
      serviceName = "Unassigned";
      break;

    case 890: 
      serviceName = "Unassigned";
      break;

    case 891: 
      serviceName = "Unassigned";
      break;

    case 892: 
      serviceName = "Unassigned";
      break;

    case 893: 
      serviceName = "Unassigned";
      break;

    case 894: 
      serviceName = "Unassigned";
      break;

    case 895: 
      serviceName = "Unassigned";
      break;

    case 896: 
      serviceName = "Unassigned";
      break;

    case 897: 
      serviceName = "Unassigned";
      break;

    case 898: 
      serviceName = "Unassigned";
      break;

    case 899: 
      serviceName = "Unassigned";
      break;

    case 900: 
      serviceName = "OMG Initial Refs";
      break;

    case 901: 
      serviceName = "SMPNAMERES";
      break;

    case 902: 
      serviceName = "self documenting Telnet Door";
      break;

    case 903: 
      serviceName = "Self Documenting Panic Door";
      break;

    case 904: 
      serviceName = "Unassigned";
      break;

    case 905: 
      serviceName = "Unassigned";
      break;

    case 906: 
      serviceName = "Unassigned";
      break;

    case 907: 
      serviceName = "Unassigned";
      break;

    case 908: 
      serviceName = "Unassigned";
      break;

    case 909: 
      serviceName = "Unassigned";
      break;

    case 910: 
      serviceName = "KINK";
      break;

    case 911: 
      serviceName = "xact-backup";
      break;

    case 912: 
      serviceName = "APEX relay-relay service";
      break;

    case 913: 
      serviceName = "APEX endpoint-relay service";
      break;

    case 914: 
      serviceName = "Unassigned";
      break;

    case 915: 
      serviceName = "Unassigned";
      break;

    case 916: 
      serviceName = "Unassigned";
      break;

    case 917: 
      serviceName = "Unassigned";
      break;

    case 918: 
      serviceName = "Unassigned";
      break;

    case 919: 
      serviceName = "Unassigned";
      break;

    case 920: 
      serviceName = "Unassigned";
      break;

    case 921: 
      serviceName = "Unassigned";
      break;

    case 922: 
      serviceName = "Unassigned";
      break;

    case 923: 
      serviceName = "Unassigned";
      break;

    case 924: 
      serviceName = "Unassigned";
      break;

    case 925: 
      serviceName = "Unassigned";
      break;

    case 926: 
      serviceName = "Unassigned";
      break;

    case 927: 
      serviceName = "Unassigned";
      break;

    case 928: 
      serviceName = "Unassigned";
      break;

    case 929: 
      serviceName = "Unassigned";
      break;

    case 930: 
      serviceName = "Unassigned";
      break;

    case 931: 
      serviceName = "Unassigned";
      break;

    case 932: 
      serviceName = "Unassigned";
      break;

    case 933: 
      serviceName = "Unassigned";
      break;

    case 934: 
      serviceName = "Unassigned";
      break;

    case 935: 
      serviceName = "Unassigned";
      break;

    case 936: 
      serviceName = "Unassigned";
      break;

    case 937: 
      serviceName = "Unassigned";
      break;

    case 938: 
      serviceName = "Unassigned";
      break;

    case 939: 
      serviceName = "Unassigned";
      break;

    case 940: 
      serviceName = "Unassigned";
      break;

    case 941: 
      serviceName = "Unassigned";
      break;

    case 942: 
      serviceName = "Unassigned";
      break;

    case 943: 
      serviceName = "Unassigned";
      break;

    case 944: 
      serviceName = "Unassigned";
      break;

    case 945: 
      serviceName = "Unassigned";
      break;

    case 946: 
      serviceName = "Unassigned";
      break;

    case 947: 
      serviceName = "Unassigned";
      break;

    case 948: 
      serviceName = "Unassigned";
      break;

    case 949: 
      serviceName = "Unassigned";
      break;

    case 950: 
      serviceName = "Unassigned";
      break;

    case 951: 
      serviceName = "Unassigned";
      break;

    case 952: 
      serviceName = "Unassigned";
      break;

    case 953: 
      serviceName = "Unassigned";
      break;

    case 954: 
      serviceName = "Unassigned";
      break;

    case 955: 
      serviceName = "Unassigned";
      break;

    case 956: 
      serviceName = "Unassigned";
      break;

    case 957: 
      serviceName = "Unassigned";
      break;

    case 958: 
      serviceName = "Unassigned";
      break;

    case 959: 
      serviceName = "Unassigned";
      break;

    case 960: 
      serviceName = "Unassigned";
      break;

    case 961: 
      serviceName = "Unassigned";
      break;

    case 962: 
      serviceName = "Unassigned";
      break;

    case 963: 
      serviceName = "Unassigned";
      break;

    case 964: 
      serviceName = "Unassigned";
      break;

    case 965: 
      serviceName = "Unassigned";
      break;

    case 966: 
      serviceName = "Unassigned";
      break;

    case 967: 
      serviceName = "Unassigned";
      break;

    case 968: 
      serviceName = "Unassigned";
      break;

    case 969: 
      serviceName = "Unassigned";
      break;

    case 970: 
      serviceName = "Unassigned";
      break;

    case 971: 
      serviceName = "Unassigned";
      break;

    case 972: 
      serviceName = "Unassigned";
      break;

    case 973: 
      serviceName = "Unassigned";
      break;

    case 974: 
      serviceName = "Unassigned";
      break;

    case 975: 
      serviceName = "Unassigned";
      break;

    case 976: 
      serviceName = "Unassigned";
      break;

    case 977: 
      serviceName = "Unassigned";
      break;

    case 978: 
      serviceName = "Unassigned";
      break;

    case 979: 
      serviceName = "Unassigned";
      break;

    case 980: 
      serviceName = "Unassigned";
      break;

    case 981: 
      serviceName = "Unassigned";
      break;

    case 982: 
      serviceName = "Unassigned";
      break;

    case 983: 
      serviceName = "Unassigned";
      break;

    case 984: 
      serviceName = "Unassigned";
      break;

    case 985: 
      serviceName = "Unassigned";
      break;

    case 986: 
      serviceName = "Unassigned";
      break;

    case 987: 
      serviceName = "Unassigned";
      break;

    case 988: 
      serviceName = "Unassigned";
      break;

    case 989: 
      serviceName = "ftp data over TLS/SSL";
      break;

    case 990: 
      serviceName = "ftp control over TLS/SSL";
      break;

    case 991: 
      serviceName = "Netnews Administration Systm";
      break;

    case 992: 
      serviceName = "telnet over TLS/SSL";
      break;

    case 993: 
      serviceName = "imap4 over TLS/SSL";
      break;

    case 994: 
      serviceName = "Reserved";
      break;

    case 995: 
      serviceName = "pop3 protocol over TLS/SSL";
      break;

    case 996: 
      serviceName = "vsinet";
      break;

    case 997: 
      serviceName = "maitrd";
      break;

    case 998: 
      serviceName = "busboy";
      break;

    case 999: 
      serviceName = "Applix ac";
      break;

    case 1000: 
      serviceName = "Cadlock2";
      break;

    case 1001: 
      serviceName = "Unassigned";
      break;

    case 1002: 
      serviceName = "Unassigned";
      break;

    case 1003: 
      serviceName = "Unassigned";
      break;

    case 1004: 
      serviceName = "Unassigned";
      break;

    case 1005: 
      serviceName = "Unassigned";
      break;

    case 1006: 
      serviceName = "Unassigned";
      break;

    case 1007: 
      serviceName = "Unassigned";
      break;

    case 1008: 
      serviceName = "Unassigned";
      break;

    case 1009: 
      serviceName = "Unassigned";
      break;

    case 1010: 
      serviceName = "Surf";
      break;

    case 1011: 
      serviceName = "Reserved";
      break;

    case 1012: 
      serviceName = "Reserved";
      break;

    case 1013: 
      serviceName = "Reserved";
      break;

    case 1014: 
      serviceName = "Reserved";
      break;

    case 1015: 
      serviceName = "Reserved";
      break;

    case 1016: 
      serviceName = "Reserved";
      break;

    case 1017: 
      serviceName = "Reserved";
      break;

    case 1018: 
      serviceName = "Reserved";
      break;

    case 1019: 
      serviceName = "Reserved";
      break;

    case 1020: 
      serviceName = "Reserved";
      break;

    case 1021: 
      serviceName = "RFC3692-style Experiment 1";
      break;

    case 1022: 
      serviceName = "RFC3692-style Experiment 2";
      break;

    case 1023: 
      serviceName = "Reserved";
      break;

    case 1024: 
      serviceName = "Reserved";
      break;
  }

  return serviceName;
}