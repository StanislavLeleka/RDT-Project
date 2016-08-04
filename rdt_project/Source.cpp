#include <pcap.h>
#include <WinSock2.h>
#include <iostream>
#include <string>

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

typedef struct tcp_header
{
	unsigned short source_port;  // source port
	unsigned short dest_port;    // destination port
	unsigned int   sequence;     // sequence number - 32 bits
	unsigned int   acknowledge;  // acknowledgement number - 32 bits

	unsigned char  ns : 1;          //Nonce Sum Flag Added in RFC 3540.
	unsigned char  reserved_part1 : 3; //according to rfc
	unsigned char  data_offset : 4;    //number of dwords in the TCP header.

	unsigned char  fin : 1;      //Finish Flag
	unsigned char  syn : 1;      //Synchronise Flag
	unsigned char  rst : 1;      //Reset Flag
	unsigned char  psh : 1;      //Push Flag
	unsigned char  ack : 1;      //Acknowledgement Flag
	unsigned char  urg : 1;      //Urgent Flag

	unsigned char  ecn : 1;      //ECN-Echo Flag
	unsigned char  cwr : 1;      //Congestion Window Reduced Flag

	unsigned short window;          // window
	unsigned short checksum;        // checksum
	unsigned short urgent_pointer;  // urgent pointer
}   tcp_hdr;

typedef struct ethernet_header
{
	UCHAR dest[6];
	UCHAR source[6];
	USHORT type;
}   ETHER_HDR, *PETHER_HDR, FAR * LPETHER_HDR, ETHERHeader;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void print_data(u_char *data, int size);
void print_all_data(u_char *data, int size);

void parse_data(std::string data);

FILE *file;

int main()
{
	pcap_if_t *all_devs;
	pcap_if_t *d;
	pcap_t *adhandle;

	char errbuf[PCAP_ERRBUF_SIZE];
	int i;

	char packet_filter[] = "tcp";
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

				file = fopen("dump.txt", "w");

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
	tcp_hdr *tcp_header;
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
	int e = sizeof(ETHER_HDR);
	tcp_header = (tcp_hdr*)(pkt_data + sizeof(ETHER_HDR));
	int tcp_header_len = tcp_header->data_offset * 4;

	sport = ntohs(tcp_header->source_port);
	dport = ntohs(tcp_header->dest_port);
	
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

	printf("%s:%d---%s -> %s:%d---%s\n",
			source_ip,
			sport,
			source_host,
			dest_ip,
			dport,
			dest_host);	

	//printf("DATA Payload\n");

	u_char *data;
	data = (u_char*)(pkt_data + tcp_header_len + ip_len/4);

	int data_size = (header->len - ip_len/4 - tcp_header_len);

	print_all_data((u_char*)(pkt_data + tcp_header_len), header->len - tcp_header_len);

	freeaddrinfo(d_res);
}

void print_data(u_char *data, int size)
{
	unsigned char a, line[17], c;
	int j;

	for (int i = 0; i < size; i++)
	{
		c = data[i];
		//fprintf(file, " %.2x", (unsigned int)c);

		a = (c >= 32 && c <= 128) ? ((unsigned char)c) : '.';

		line[i % 16] = a;

		if ((i != 0 && (i + 1) % 16 == 0) || i == size - 1)
		{
			line[i % 16 + 1] = '\0';
			//fprintf(file, "			");

			for (j = sizeof line; j < 16; j++)
			{
				fprintf(file, "	");
			}

			fprintf(file, "%s", line);
		}
	}

	fprintf(file, "\n");
}

void print_all_data(u_char *data, int size)
{
	unsigned char a, line[17], c;
	int j;

	std::string str_data = "";

	for (int i = 0; i < size; i++)
	{
		c = data[i];
		//fprintf(file, " %.2x", (unsigned int)c);

		a = (c >= 32 && c <= 128) ? ((unsigned char)c) : '.';

		line[i % 16] = a;

		if ((i != 0 && (i + 1) % 16 == 0) || i == size - 1)
		{
			line[i % 16 + 1] = '\0';
			//fprintf(file, "			");

			for (j = sizeof line; j < 16; j++)
			{
				fprintf(file, "	");
			}

			//fprintf(file, "%s", line);

			std::string str((char*)line);
			str_data += str;
		}
	}

	//fprintf(file, "\n\n");
	parse_data(str_data);
}

struct http_headers
{
	std::string method;
	std::string path;
	std::string host;
	std::string connection;
	std::string cache_control;
	std::string user_agent;
	std::string accept;
	std::string referer;
	std::string accept_encoding;
	std::string accept_language;
	std::string cookie[4];
	std::string if_none_match;
	std::string if_modified_since;
};



void print_headers(http_headers headers);

void parse_data(std::string data)
{
	http_headers headers;
	int data_length = data.length();

	for (int i = 0; i < data_length; i++)
	{
		if(i < data_length - 2)
		{
			if ((data[i] == 'G') & (data[i + 1] == 'E') & (data[i + 2] == 'T'))
			{
				headers.method = "GET";

				for (int j = i + 4; j < data_length; j++)
				{
					if (data[j] == ' ') break;
					headers.path += data[j];
				}

				int pos = data.find("Host");
				std::string header_data = "";
				for (int j = pos + 6; j < data_length; j++)
				{
					if (data[j] == '.' & data[j + 1] == '.') break;
					header_data += data[j];
				}
				headers.host = header_data;

				header_data = "";

				pos = data.find("Connection");
				for (int j = pos + 12; j < data_length; j++)
				{
					if (data[j] == '.' & data[j + 1] == '.') break;
					header_data += data[j];
				}
				headers.connection = header_data;

				header_data = "";

				pos = data.find("Cache-Control");
				for (int j = pos + 15; j < data_length; j++)
				{
					if (data[j] == '.' & data[j + 1] == '.') break;
					header_data += data[j];
				}
				headers.cache_control = header_data;

				header_data = "";

				pos = data.find("User-Agent");
				for (int j = pos + 12; j < data_length; j++)
				{
					if (data[j] == '.' & data[j + 1] == '.') break;
					header_data += data[j];
				}
				headers.user_agent = header_data;

				header_data = "";

				pos = data.find("Accept");
				for (int j = pos + 8; j < data_length; j++)
				{
					if (data[j] == '.' & data[j + 1] == '.') break;
					header_data += data[j];
				}
				headers.accept = header_data;

				header_data = "";

				pos = data.find("Referer");
				for (int j = pos + 9; j < data_length; j++)
				{
					if (data[j] == '.' & data[j + 1] == '.') break;
					header_data += data[j];
				}
				headers.referer = header_data;

				header_data = "";

				pos = data.find("Accept-Encoding");
				for (int j = pos + 17; j < data_length; j++)
				{
					if (data[j] == '.' & data[j + 1] == '.') break;
					header_data += data[j];
				}
				headers.accept_encoding = header_data;

				header_data = "";

				pos = data.find("Accept-Language");
				for (int j = pos + 17; j < data_length; j++)
				{
					if (data[j] == '.' & data[j + 1] == '.') break;
					header_data += data[j];
				}
				headers.accept_language = header_data;

				header_data = "";

				pos = data.find("If-None-Match");
				for (int j = pos + 15; j < data_length; j++)
				{
					if (data[j] == '.' & data[j + 1] == '.') break;
					header_data += data[j];
				}
				headers.if_none_match = header_data;

				header_data = "";

				pos = data.find("If-Modified-Since");
				for (int j = pos + 19; j < data_length; j++)
				{
					if (data[j] == '.' & data[j + 1] == '.') break;
					header_data += data[j];
				}
				headers.if_modified_since = header_data;

				header_data = "";

				pos = data.find("Cookie");
				int c_cnt = 0;
				std::string c_name = "";
				for (int j = pos + 8; j < data_length; j++)
				{
					if (data[j] == '.' & data[j + 1] == '..') break;

					if (data[j] == '=')
					{
						headers.cookie[c_cnt] = c_name + "=";
						for (int k = j + 1; k < data_length; k++)
						{
							if (data[k] == '.' & data[k + 1] == '.') break;

							if (data[k] == ';')
							{
								j = k + 2;
								break;
							}
							headers.cookie[c_cnt] += data[k];
							j = k;
						}
						
						c_name = "";
						c_cnt++;
					}
					c_name += data[j];
				}
			}
		}
	}

	print_headers(headers);
}

void print_headers(http_headers headers)
{
	if (headers.method != "")
	{
		std::cout << headers.method << " " << headers.path << std::endl;
		std::cout << "Host: " << headers.host << std::endl;
		std::cout << "Connection: " << headers.connection << std::endl;
		std::cout << "Cache-Control: " << headers.cache_control << std::endl;
		std::cout << "User-Agent: " << headers.user_agent << std::endl;
		std::cout << "Accept: " << headers.accept << std::endl;
		std::cout << "Referer: " << headers.referer << std::endl;
		std::cout << "Accept-Encoding: " << headers.accept_encoding << std::endl;
		std::cout << "Accept-Language: " << headers.accept_language << std::endl;

		std::cout << "Cookie: \n";

		for (int i = 0; i < (sizeof(headers.cookie) / sizeof(*headers.cookie)); i++)
		{
			std::cout << "\t" << headers.cookie[i] << std::endl;
		}

		std::cout << "If-None-Match: " << headers.if_none_match << std::endl;
		std::cout << "If-Modified-Since: " << headers.if_modified_since << std::endl;
	}
}