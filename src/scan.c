#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#define ICMP_PORT 0
#define ICMP_TTL  64
#define RECV_WAIT 250

/**
 * @desc Calculate 16-bit CRC Checksum
 * @param {void*} raw - Data to calculate checksum from
 * @param {int} length - Number of bytes in the raw data
 * @return {uint16_t} Checksum value for the data
 */
uint16_t checksum(void* raw, int length) {
	uint16_t* data = raw;
	uint16_t sum = 0;

	// Sum data by 16-bit chunks
	while(length > 1) {
		sum += *data++;
		length -= sizeof(uint16_t);
	}
	// Append leftover data
	if(length == 1) {
		sum += *(unsigned char*) data;
	}

  // Carry
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += sum >> 16;
	
	return ~sum;
}

/**
 * @desc Sends an ICMP packet to an address
 * @param {int} fd - ICMP Socket file descriptor
 * @param {int} sequence - ICMP sequence number
 * @param {struct in_addr} address - Network order binary format IP address
 * @return {bool} Returns true on success and false on failure
 */
int ping(int fd, int sequence, struct in_addr address) {
	struct sockaddr_in req = {
		.sin_family = AF_INET,
		.sin_port = htons(ICMP_PORT),
		.sin_addr = address
	};
	struct sockaddr_in res;
	struct icmphdr packet = {
		.type = ICMP_ECHO,
		.code = 0,
		.un.echo.id = 0,
		.un.echo.sequence = sequence,
		.checksum = checksum(&packet, sizeof(packet))
	};
	socklen_t length = sizeof(res);

	if(sendto(fd, &packet, sizeof(struct icmphdr), 0, (struct sockaddr*) &req, sizeof(struct sockaddr)) < 0) {
		return 0;
	}
	if(recvfrom(fd, &packet, sizeof(struct icmphdr), 0, (struct sockaddr*) &res, &length) < 0) {
		return 0;
	}

	return 1;
}

/**
 * @desc Scans over all IP addresses for a given Interface
 * @param {struct ifaddrs*} ifa - A pointer to the interface to scan
 */
void scan_ipv4(struct ifaddrs* ifa) {
	int fd;
	int ttl = ICMP_TTL;
	struct sockaddr_in* addr = (struct sockaddr_in*) ifa->ifa_addr; // Interface IP address
	struct sockaddr_in* mask = (struct sockaddr_in*) ifa->ifa_netmask; // Interface subnet mask
	struct in_addr base = {
		.s_addr = addr->sin_addr.s_addr & mask->sin_addr.s_addr
	};
	struct timeval time = {
		.tv_sec = RECV_WAIT / 1000,
		.tv_usec = (RECV_WAIT % 1000) * 1000 
	};
	uint32_t range = UINT32_MAX - ntohl(mask->sin_addr.s_addr); // Number of IP addresses in mask range
	
	// Initalizes socket
	if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)) < 0) {
		printf("%s\n", strerror(errno));
		close(fd);
		exit(-1);
	}
	// Packet time to live timeout
	if(setsockopt(fd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
		printf("%s\n", strerror(errno));
		close(fd);
		exit(-1);
	}
	// Packet response wait timeout
	if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &time, sizeof(time)) < 0) {
		printf("%s\n", strerror(errno));
		close(fd);
		exit(-1);
	}

	printf("Interface:      %s\n", ifa->ifa_name);
	printf("IPv4 Address:   %s\n", inet_ntoa(addr->sin_addr));
	printf("IP Subnet Mask: %s\n", inet_ntoa(mask->sin_addr));
	printf("\n");

	for(uint32_t i = 0; i <= range; i++) {
		struct in_addr next = {
			.s_addr = base.s_addr + htonl(i)
		};
		
		if(ping(fd, i, next)) {
			printf("%s\n", inet_ntoa(next));
		}
	}

	close(fd);
}

/*
 * @desc Driver function that finds the target Interface
 * @param {int} argc - Ignored
 * @param {char**} argv - Target Interface name
 * @return {int} Exit code
 */
int main(int argc, char** argv) {
	char* interface = argv[1];
	struct ifaddrs* ifas = NULL;
	struct ifaddrs* target = NULL;
	sa_family_t ip_version = AF_INET;

	(void) argc;

	if(getifaddrs(&ifas) < 0) {
		printf("%s\n", strerror(errno));

		return -1;
	}
	for(struct ifaddrs* ifa = ifas; ifa; ifa = ifa->ifa_next) {
		if(ifa->ifa_addr == NULL) {
			continue;
		}
		if(ifa->ifa_addr->sa_family != ip_version) {
			continue;
		}
		if(strcmp(ifa->ifa_name, interface) == 0) {
			target = ifa;

			break;
		}
	}

	scan_ipv4(target);

	freeifaddrs(ifas);

	return 0;
}
