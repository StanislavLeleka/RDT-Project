#include <pcap.h>
#include <WinSock2.h>
#include <iostream>
#include <string>
#include <vector>

typedef struct ethernet_header
{
	UCHAR dest[6];
	UCHAR source[6];
	USHORT type;
}   ETHER_HDR;

struct tcp_header
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int   sequence;
	unsigned int   acknowledge;

	unsigned char  ns : 1;
	unsigned char  reserved_part1 : 3;
	unsigned char  data_offset : 4;

	unsigned char  fin : 1;
	unsigned char  syn : 1;
	unsigned char  rst : 1;
	unsigned char  psh : 1;
	unsigned char  ack : 1;
	unsigned char  urg : 1;

	unsigned char  ecn : 1;
	unsigned char  cwr : 1;

	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
};

struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
};

struct ip_header {
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
};

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

class network_listener
{
public:
	bool listen_specified_host;
	std::string host_to_listen;
	char* filter;

	network_listener(bool, std::string, char*);
	~network_listener(){}
	pcap_if_t* print_devices(int&);
	void start_listening(bool, bool, FILE*);

private:
	bool show_output;
	bool save_output;
	FILE* file;
	//static std::vector<http_headers> headers_col;

	static void packet_handler(u_char*, const struct pcap_pkthdr*, const u_char*);
	static void parse_data(u_char*, int);
	static void parse_headers(std::string);
	static void print_headers(http_headers);
	char * iptos(u_long);
};