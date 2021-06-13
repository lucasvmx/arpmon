/* Simple ARP Sniffer.                                                   */ 
/* Author: Luis Martin Garcia. luis.martingarcia [.at.] gmail [d0t] com  */
/* To compile: gcc arpsniffer.c -o arpsniff -lpcap                       */
/* Run as root!                                                          */ 
/*                                                                       */
/* This code is distributed under the GPL License. For more info check:  */
/* http://www.gnu.org/copyleft/gpl.html                                  */

/* 
/* Modified by: Lucas Vieira de Jesus. lucas.engen.cc@gmail.com
*/

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short u_short;

#include <stdlib.h> 
#include <stdio.h>
#include <string.h> 
#include <stdint.h>
#include <sys/types.h>
#include <pcap.h>
#include <time.h>
#include <strings.h>
#include <errno.h>
#include <json-c/json.h>
#include <ctype.h>

/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 

// Maximum bytes to capture
#define MAXBYTES2CAPTURE 2048 

// Specifies the packet buffer timeout
#define BUFFER_TIMEOUT_MS 512

// Maximum size of IPV4 in chars
#define IPV4_STR_MAX_LEN 16

// Maximum size of MAC address in chars
#define MAC_STR_MAX_LEN 18

// Maximum size of a name to the host
#define MAX_NAME_SZ 256

// Filename that contains macaddresses map to machine names
#define MACHINE_DATA_FILE	"machines.json"

typedef struct arphdr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
}arphdr_t; 


typedef struct machine_info {
	char mac[MAC_STR_MAX_LEN];
	char name[MAX_NAME_SZ];
} machine_info_t;

// Contains information about all mapped machines
machine_info_t machineInfo[UINT8_MAX + 1];

#define count(x) (sizeof(x)/sizeof(x[0]))



typedef enum AddressTypes {
	MAC_ADDR,
	IP_ADDR
} AddrTypes;

static char *addr_to_string(u_char *address, size_t len, AddrTypes address_type)
{
	char *addr = NULL;
	size_t amount = sizeof(char) * ((address_type == MAC_ADDR) ? MAC_STR_MAX_LEN : IPV4_STR_MAX_LEN);
	
	addr = (char*)malloc(amount);
	if(!addr) {
		printf("Failed to allocate memory!\n");
		exit(1);
	}

	// Erase buffer
	bzero(addr, sizeof(addr));
	
	if(address_type == IP_ADDR) {
		snprintf(addr, IPV4_STR_MAX_LEN, "%d.%d.%d.%d", address[0], address[1], address[2], address[3]);
	} else if(address_type == MAC_ADDR) {
		snprintf(addr, MAC_STR_MAX_LEN, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", address[0], address[1], address[2], address[3], address[4], address[5]);
	} else {
		free(addr);
		return NULL;
	}
	

	return addr;
}

char *strlwr(char *s)
{
	for(char *p=s; *p; p++) *p=tolower(*p);

  	return s;
}

static void read_identifications()
{
	struct json_object *parsed_json = json_object_from_file(MACHINE_DATA_FILE);

	if(parsed_json == NULL) {
		fprintf(stdout, "[ERROR] Failed to parse JSON!\n");
		exit(1);
	}

	printf("[INFO] Reading configuration ...\n");
	
	struct json_object *machines_arr = json_object_object_get(parsed_json, "machines");
	size_t machines_cnt = json_object_array_length(machines_arr);

	printf("[INFO] %d machines detected\n", machines_cnt);

	for(size_t i = 0; i < machines_cnt; i++) 
	{
		json_object *machine, *name, *mac;
		
		machine = json_object_array_get_idx(machines_arr, i);
		name = json_object_object_get(machine, "name");
		mac = json_object_object_get(machine, "mac");

		const char *m_name = json_object_get_string(name);
		const char *m_mac = json_object_get_string(mac);

		strncpy(machineInfo[i].name, m_name, sizeof(machineInfo[i].name) / sizeof(char));
		strncpy(machineInfo[i].mac, m_mac, sizeof(machineInfo[i].mac) / sizeof(char));

		printf("[INFO] %s is mapped to %s\n", machineInfo[i].mac, machineInfo[i].name);
	}
}

static char *find_device_name(const char *mac)
{
	for(int i = 0; i < count(machineInfo); i++)
	{
		if(strncasecmp(mac, machineInfo[i].mac, MAC_STR_MAX_LEN) == 0) {
			return &machineInfo[i].name[0];
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	int i = 0; 
	bpf_u_int32 netaddr=0, mask=0;    /* To Store network address and netmask   */ 
	struct bpf_program filter;        /* Place to store the BPF filter program  */ 
	char errbuf[PCAP_ERRBUF_SIZE];    /* Error buffer                           */ 
	pcap_t *descr = NULL;             /* Network interface handler              */ 
	struct pcap_pkthdr pkthdr;        /* Packet information (timestamp,size...) */ 
	const unsigned char *packet=NULL; /* Received raw data                      */ 
	arphdr_t *arpheader = NULL;       /* Pointer to the ARP header              */
	char gateway_ip[IPV4_STR_MAX_LEN];
	
	memset(errbuf, 0, PCAP_ERRBUF_SIZE); 

	if (argc != 3){ 
		printf("usage: %s <interface> <gateway IPV4>\n", argv[0]);
		printf("\tinterface: name of interface to be used\n");
		printf("\tgateway IPV4: address of the gateway for current network\n\n");
		exit(1); 
	}

	// Parse machine identifications
	read_identifications();

	// Save IP address
	strncpy(gateway_ip, argv[2], IPV4_STR_MAX_LEN);

	 /* Open network device for packet capture */ 
	if ((descr = pcap_open_live(argv[1], MAXBYTES2CAPTURE, 0, BUFFER_TIMEOUT_MS, errbuf)) == NULL) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(1);
	}
		
	/* Look up info from the capture device. */ 
	if( pcap_lookupnet( argv[1] , &netaddr, &mask, errbuf) == -1){
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(1);
	}

	/* Compiles the filter expression into a BPF filter program */ 
	if ( pcap_compile(descr, &filter, "arp", 1, mask) == -1){
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
		exit(1);
	}

	/* Load the filter program into the packet capture device. */ 
	if (pcap_setfilter(descr,&filter) == -1){
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
		exit(1);
	}

	fprintf(stdout, "[+] Monitoring ARP requests ...\n");

	while(1)
	{
		if((packet = pcap_next(descr, &pkthdr)) == NULL)
		{  
			/* Get one packet */ 
			fprintf(stderr, "ERROR: Error getting the packet: %s\n", errbuf);
			exit(1);
		}

		arpheader = (struct arphdr*)(packet+14); /* Point to the ARP header */
	 
		/* If is Ethernet and IPv4, print packet contents */ 
		if(ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800)
		{
			char *sender_ip, *sender_mac, *target_mac, *target_ip;
			
			sender_mac = addr_to_string(arpheader->sha, count(arpheader->sha), MAC_ADDR);
			sender_ip = addr_to_string(arpheader->spa, count(arpheader->spa), IP_ADDR);
			target_mac = addr_to_string(arpheader->tha, count(arpheader->tha), MAC_ADDR);
			target_ip = addr_to_string(arpheader->tpa, count(arpheader->tpa), IP_ADDR);

			// Ignore requests from router
			if(strncmp(sender_ip, gateway_ip, IPV4_STR_MAX_LEN) != 0)
			{
				char *sender_name, *target_name;

				sender_name = find_device_name(sender_mac);
				target_name = find_device_name(target_mac);

				fprintf(stdout, "ARP packet from: %s (%s, %s) to %s (%s, %s)\n", sender_mac, 
				sender_ip, 
				sender_name == NULL ? "Desconhecido" : sender_name,
				target_mac,
				target_ip,
				target_name == NULL ? "Desconhecido" : target_name);
			}

			// Free memory used
			free(sender_mac);
			free(sender_ip);
			free(target_mac);
			free(target_ip);
		}
	}

	return 0; 
}
