#include <stdio.h>
#include "pcap.h"
#include "structs.h"

void print_raw_packet(const unsigned char *pkt_data, bpf_u_int32 len);
void print_ether_header(struct ether_header *eth_header);
void print_ip_header(struct iphdr *ip_header, const unsigned char *pkt_data);
void print_tcp_header(struct tcphdr *tcp_header);
void print_data(const unsigned char *pkt_data, int dataAddr, int len);

int main() {
	pcap_if_t *alldevs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	// find all network adapters
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("dev find failed\n");
		return -1;
	}
	if (alldevs == NULL) {
		printf("no devs found\n");
		return -1;
	}
	// print them
	pcap_if_t *d; int i;
	for (d = alldevs, i = 0; d != NULL; d = d->next) {
		printf("%d-th dev: %s ", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	int inum;
	printf("enter the interface number: ");
	scanf("%d", &inum);
	for (d = alldevs, i = 0; i<inum - 1; d = d->next, i++); // jump to the inum-th dev

															// open
	pcap_t  *fp;
	if ((fp = pcap_open_live(d->name,      // name of the device
		65536,                   // capture size
		1,  // promiscuous mode
		20,                    // read timeout
		errbuf
	)) == NULL) {
		printf("pcap open failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("pcap open successful\n");

	struct bpf_program  fcode;
	if (pcap_compile(fp,  // pcap handle
		&fcode,  // compiled rule
		"dst port 80",  // filter rule
		1,            // optimize
		NULL) < 0) {
		printf("pcap compile failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_setfilter(fp, &fcode) <0) {
		printf("pcap setfilter failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("filter setting successful\n");

	// capture. you have to implement print_raw_packet, print_ether_header, etc.
	pcap_freealldevs(alldevs); // we don't need this anymore

	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	int res, dataAddr;
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {// 1 if success
		if (res == 0) continue; // 0 if time-out
		struct ether_header *eth_header = (struct ether_header *)pkt_data;	//Struct for Ethernet Header
		struct iphdr *ip_header = (struct iphdr *)(pkt_data + sizeof(*eth_header)); //Struct for IP Header
		struct tcphdr *tcp_header = (struct tcphdr *)(pkt_data+sizeof(*eth_header)+((ip_header->ihl)*4)); //Struct for TCP Header
				
		dataAddr = sizeof(tcp_header) + sizeof(ip_header) + sizeof(eth_header); //Set index for print Data(String)
		print_raw_packet(pkt_data, header->caplen);
		print_ether_header(eth_header);
		print_ip_header(ip_header, pkt_data);
		print_tcp_header(tcp_header);
		print_data(pkt_data, dataAddr, header->len);
		
		struct timeval this_ts = header->ts; // timestamp of this packet
		double pkt_time = this_ts.tv_sec + this_ts.tv_usec / 1.0e6; // time value of this packet

		char timestr[256];
		sprintf(timestr, "%d.%06d", (int)this_ts.tv_sec, (int)this_ts.tv_usec);  // disply sec and usec
		printf("sec and usec:%s\n", timestr);
		printf("packet timestamp:%f\n", pkt_time); // display timestamp

	}


	return 0;
}

//Print raw packet
void print_raw_packet(const unsigned char *pkt_data, bpf_u_int32 len)
{
	printf("===========================================\n");
	for (int i = 0; i < len; i++)
	{
		printf("0x%0x ", *(pkt_data + i));
		if (i % 30 == 0 && i != 0)
			printf("\n");
	}
	printf("\n");
}

//Print Ether type, Src/Dst MAC addr
void print_ether_header(struct ether_header *eth_header)
{
	
	printf("Ether Type : ");
	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
		printf("IP\n");
	else
		printf("UNKNOWN\n");
	printf("Src MAC Addr : ");
	for(int i = 0; i < 6; i ++)
	{
		printf("%02x", *((eth_header->ether_shost) + i));
		if (i < 5)
			printf(":");
	}
	printf("\n");
	printf("Dst MAC Addr : ");
	for (int i = 0; i < 6; i++)
	{
		printf("%02x", *((eth_header->ether_dhost) + i));
		if (i < 5)
			printf(":");
	}
	printf("\n");
}

//print IPv, IP Header Length, Protocol, Src/Dst IP addr
void print_ip_header(struct iphdr *ip_header, const unsigned char *pkt_data)
{
	printf("IP Version : %d\n", ip_header->version);
	printf("IP Header Length : %d\n", ip_header->tot_len);
	printf("Protocol : ");
	if (ip_header->protocol == IPPROTO_TCP)
		printf("TCP\n");
	printf("Src IP : ");
	for (int i = 26; i < 30; i++)
		printf("%d.", *(pkt_data + i));
	printf("\b \n");
	printf("Dst IP : ");
	for (int i = 30; i < 34; i++)
		printf("%d.", *(pkt_data + i));
	printf("\b \n");
}

//print Src & Dst Port
void print_tcp_header(struct tcphdr *tcp_header)
{
	printf("Src Port : %d\n", ntohs(tcp_header->source));
	printf("Dst Port : %d\n", ntohs(tcp_header->dest));
}

//print Data(String)
void print_data(const unsigned char *pkt_data, int dataAddr,int len)
{
	for (int i = dataAddr; i < len; i++)
		printf("%c", *(pkt_data + i));
	printf("\n\n");
}