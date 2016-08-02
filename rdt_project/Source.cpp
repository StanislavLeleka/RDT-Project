#include <pcap.h>
#include <WinSock2.h>

char * iptos(u_long in);
pcap_if_t* print_devices_list(int &i);

/*
* 4 bytes IP address
*/

typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;

/*
* IPv4 header
*/

typedef struct ip_header {
	u_char ver_ihl;
	u_char tos;
	u_short tlen;
	u_short identification;
	u_short flags_fo;
	u_char ttl;
	u_char proto;
	u_short crc;
	ip_address saddr;
	ip_address daddr;
	u_int op_pad;
} ip_header;

/*
* UDP header
*/

typedef struct udp_header {
	u_short sport;
	u_short dport;
	u_short len;
	u_short crc;
} udp_header;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()
{
	pcap_if_t *all_devs;
	pcap_if_t *d;
	pcap_t *adhandle;

	char errbuf[PCAP_ERRBUF_SIZE];
	int i;

	char packet_filter[] = "ip and tcp";
	u_int netmask;
	struct bpf_program fcode;

	all_devs = print_devices_list(i);
	
	if (all_devs != NULL)
	{
		int inum;

		printf("Enter the device interface number (1-%d):", i);
		scanf_s("%d", &inum);

		if (inum < 1 || inum > i)
		{
			printf("\nInterface number out of range.\n");
			pcap_freealldevs(all_devs);
		}
		else
		{
			for (d = all_devs, i = 0; i < inum - 1; d = d->next, i++);

			if ((adhandle = pcap_open(d->name,          // name of the device
				65536,            // portion of the packet to capture
								  // 65536 guarantees that the whole packet will be captured on all the link layers
				PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
				1000,             // read timeout
				NULL,             // authentication on the remote machine
				errbuf            // error buffer
				)) == NULL)
			{
				fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
				/* Free the device list */
				pcap_freealldevs(all_devs);
			}
			else
			{
				if (pcap_datalink(adhandle) != DLT_EN10MB)
				{
					fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
					pcap_freealldevs(all_devs);
					return -1;
				}

				if (d->addresses != NULL)
				{
					netmask = ((struct sockaddr_in *) (d->addresses->netmask))->sin_addr.S_un.S_addr;
				}
				else
				{
					netmask = 0xffffff;
				}

				if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
				{
					fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
					pcap_freealldevs(all_devs);
					return -1;
				}

				if (pcap_setfilter(adhandle, &fcode) < 0)
				{
					fprintf(stderr, "\nError setting the filter.\n");
					pcap_freealldevs(all_devs);
					return -1;
				}

				printf("\nlistening on %s...", d->description);

				pcap_freealldevs(all_devs);

				pcap_loop(adhandle, 0, packet_handler, NULL);
			}
		}
	}

	return 0;
}

pcap_if_t* print_devices_list(int &i)
{
	pcap_if_t *device;
	pcap_if_t *all_devs;
	i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_addr_t *addr;

	/*Retrive the device list*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &all_devs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		return NULL;
	}

	for (device = all_devs; device != NULL; device = device->next)
	{
		printf("%d. %s", ++i, device->name);
		if (device->description)
		{
			printf(" (%s)\n", device->description);

			for (addr = device->addresses; addr = addr->next;)
			{
				printf("\tAddress Family: #%d\n", addr->addr->sa_family);

				switch (addr->addr->sa_family)
				{
				case AF_INET:
					printf("\tAddress Family Name: AF_INET\n");
					if (addr->addr)
						printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)addr->addr)->sin_addr.s_addr));
					if (addr->netmask)
						printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)addr->netmask)->sin_addr.s_addr));
					if (addr->broadaddr)
						printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)addr->broadaddr)->sin_addr.s_addr));
					if (addr->dstaddr)
						printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)addr->dstaddr)->sin_addr.s_addr));
					break;
				default:
					break;
				}
			}
		}
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found!\n");
		return NULL;
	}

	return all_devs;
}

#define IPTOSBUFFERS    12
char * iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;

	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);

	return output[which];
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	(VOID)(param);

	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	ih = (ip_header *)(pkt_data + 14);

	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *)((u_char*)ih + ip_len);

	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);
	
	struct addrinfo hints;
	struct addrinfo *s_res = 0;
	struct addrinfo *d_res = 0;

	int status;

	WSADATA wsadata;
	int statuswsadata;

	if ((statuswsadata = WSAStartup(MAKEWORD(2, 2), &wsadata)) != 0)
	{
		printf("WSAStartup failed: %d\n", statuswsadata);
	}

	hints.ai_family = AF_INET;

	char *source_ip = (char *)malloc(16 * sizeof(char));
	char *dest_ip = (char *)malloc(16 * sizeof(char));

	sprintf(source_ip, "%d.%d.%d.%d",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4);

	sprintf(dest_ip, "%d.%d.%d.%d",
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4);

	char source_host[512], dest_host[512];

	status = getaddrinfo(source_ip, 0, 0, &s_res);
	getnameinfo(s_res->ai_addr, s_res->ai_addrlen, source_host, sizeof source_host, 0, 0, 0);
	
	
	status = getaddrinfo(dest_ip, 0, 0, &d_res);
	if (d_res != NULL) 
	{
		getnameinfo(d_res->ai_addr, d_res->ai_addrlen, dest_host, sizeof dest_host, 0, 0, 0);
	}

	freeaddrinfo(d_res);

	printf("%s:%d---%s -> %s:%d---%s\n",
			source_ip,
			sport,
			source_host,
			dest_ip,
			dport,
			dest_host);	
}