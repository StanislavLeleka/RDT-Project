#include "network_listener.h"

#define IPTOSBUFFERS    12

network_listener::network_listener(bool listen_specified_host = false, std::string host = "", char* filter = "tcp")
{
	//this->nl = nl;
	this->listen_specified_host = listen_specified_host;
	this->host_to_listen = host;
	this->filter = filter;
}

void network_listener::packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	char timestr[16];
	ip_header *ih;
	tcp_header *tcp_hdr;
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
	tcp_hdr = (tcp_header*)(pkt_data + sizeof(ETHER_HDR));
	int tcp_header_len = tcp_hdr->data_offset * 4;

	sport = ntohs(tcp_hdr->source_port);
	dport = ntohs(tcp_hdr->dest_port);

	struct addrinfo hints;
	struct addrinfo *s_res = 0;
	struct addrinfo *d_res = 0;

	int status;

	WSADATA wsadata;
	int statuswsadata;

	if ((statuswsadata = WSAStartup(MAKEWORD(2, 2), &wsadata)) != 0)
	{
		std::cout << "WSAStartup failed: " << statuswsadata << std::endl;
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
	getnameinfo(d_res->ai_addr, d_res->ai_addrlen, dest_host, sizeof dest_host, 0, 0, 0);

	printf("%s:%d---%s -> %s:%d---%s\n",
			source_ip,
			sport,
			source_host,
			dest_ip,
			dport,
			dest_host);

	u_char *data;
	data = (u_char*)(pkt_data + tcp_header_len + ip_len / 4);

	int data_size = (header->len - ip_len / 4 - tcp_header_len);

	parse_data((u_char*)(pkt_data + tcp_header_len), header->len - tcp_header_len);

	freeaddrinfo(d_res);
	freeaddrinfo(s_res);
}

void network_listener::start_listening(bool show_output, bool save_to_file, FILE* file = NULL)
{
	this->show_output = show_output;
	this->save_output = save_to_file;
	this->file = file;

	pcap_if_t *all_devs;
	pcap_if_t *device;
	pcap_t *adhandle;
	struct bpf_program fcode;

	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	int i;

	all_devs = print_devices(i);

	if (all_devs != NULL)
	{
		int inum;

		std::cout << "Enter the device interface number (1-" << i << "):" << std::endl;
		std::cin >> inum;

		if (inum < 1 || inum > i)
		{
			std::cout << "\nInterface number out of range.\n";
			pcap_freealldevs(all_devs);
			return;
		}
		else
		{
			for (device = all_devs, i = 0; i < inum - 1; device = device->next, i++);

			if ((adhandle = pcap_open(device->name, 
				65536,
				PCAP_OPENFLAG_PROMISCUOUS,
				1000,
				NULL,
				errbuf
				)) == NULL)
			{
				std::cout << "\nUnable to open the adapter." << device->name << " is not supported by WinPcap\n";
				pcap_freealldevs(all_devs);
			}
			else
			{
				if (pcap_datalink(adhandle) != DLT_EN10MB)
				{
					std::cout << "\nThis program works only on Ethernet networks.\n";
					pcap_freealldevs(all_devs);
					return;
				}

				if (device->addresses != NULL)
				{
					netmask = ((struct sockaddr_in *) (device->addresses->netmask))->sin_addr.S_un.S_addr;
				}
				else
				{
					netmask = 0xffffff;
				}

				if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
				{
					std::cout << "\nUnable to compile the packet filter. Check the syntax.\n";
					pcap_freealldevs(all_devs);
					return;
				}

				if (pcap_setfilter(adhandle, &fcode) < 0)
				{
					std::cout << "\nError setting the filter.\n";
					pcap_freealldevs(all_devs);
					return;
				}

				std::cout << "\nlistening on " << device->description << std::endl;

				pcap_freealldevs(all_devs);
					
				pcap_loop(adhandle, 0, network_listener::packet_handler, NULL);
			}
		}
	}
}	

void network_listener::parse_data(u_char* data, int size)
{
	unsigned char a, line[17], c;
	int j;

	std::string str_data = "";

	for (int i = 0; i < size; i++)
	{
		c = data[i];

		a = (c >= 32 && c <= 128) ? ((unsigned char)c) : '.';

		line[i % 16] = a;

		if ((i != 0 && (i + 1) % 16 == 0) || i == size - 1)
		{
			line[i % 16 + 1] = '\0';

			std::string str((char*)line);
			str_data += str;
		}
	}

	parse_headers(str_data);
}

void network_listener::parse_headers(std::string data)
{
	http_headers headers;
	int data_length = data.length();

	for (int i = 0; i < data_length; i++)
	{
		if (i < data_length - 2)
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

	//headers_col.push_back(headers);

	print_headers(headers);
}

void network_listener::print_headers(http_headers headers)
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

pcap_if_t* network_listener::print_devices(int &i)
{
	pcap_if_t *device;
	pcap_if_t *all_devs;
	pcap_addr_t *addr;

	char errbuf[PCAP_ERRBUF_SIZE];

	i = 0;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &all_devs, errbuf) == -1)
	{
		std::cout << "Error in pcap_findalldevs_ex: " << errbuf << std::endl;
		return NULL;
	}

	for (device = all_devs; device != NULL; device = device->next)
	{
		std::cout << ++i << ": " << device->name << std::endl;
		if (device->description)
		{
			std::cout << device->description << std::endl;

			for (addr = device->addresses; addr = addr->next;)
			{
				std::cout << "\tAddress Family: #" << addr->addr->sa_family << std::endl;

				switch (addr->addr->sa_family)
				{
				case AF_INET:
					std::cout << "\tAddress Family Name: AF_INET\n";
					if (addr->addr)
						std::cout << "\tAddress: " << iptos(((struct sockaddr_in *)addr->addr)->sin_addr.s_addr) << std::endl;
					if (addr->netmask)
						std::cout << "\tNetmask: " << iptos(((struct sockaddr_in *)addr->netmask)->sin_addr.s_addr) << std::endl;
					if (addr->broadaddr)
						std::cout << "\tBroadcast Address: " << iptos(((struct sockaddr_in *)addr->broadaddr)->sin_addr.s_addr) << std::endl;
					if (addr->dstaddr)
						std::cout << "\tDestination Address: " << iptos(((struct sockaddr_in *)addr->dstaddr)->sin_addr.s_addr) << std::endl;
					break;
				default:
					break;
				}
			}
		}
		else
			std::cout << " (No description available)\n";
	}

	if (i == 0)
	{
		std::cout << "\nNo interfaces found!\n";
		return NULL;
	}

	return all_devs;
}

char * network_listener::iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;

	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);

	return output[which];
}