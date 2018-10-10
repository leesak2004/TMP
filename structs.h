#pragma once
#define	ETHERTYPE_IP	0x0800
#define IPPROTO_TCP		6
#define IPPROTO_UDP		17
#define IPPROTO_ICMP	1
#define IP_V4			4
#define IP_V6			6


struct	ether_header {
	unsigned char	ether_dhost[6];
	unsigned char	ether_shost[6];
	unsigned short	ether_type;
};

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u_int8_t	ihl : 4,
		version : 4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	u_int8_t	version : 4,
		ihl : 4;
#else

#endif
	u_int8_t	ihl:4;
	u_int8_t	version:4;
	u_int8_t	tos;
	u_int16_t	tot_len;
	u_int16_t	id;
	u_int16_t	frag_off;
	u_int8_t	ttl;
	u_int8_t	protocol;
	u_int16_t	check;
	u_int32_t	saddr;
	u_int32_t	daddr;
	/*The options start here. */
};

struct tcphdr {
	u_int16_t   source;
	u_int16_t   dest;
	u_int32_t   seq;
	u_int32_t   ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u_int16_t   res1 : 4,
		doff : 4,
		fin : 1,
		syn : 1,
		rst : 1,
		psh : 1,
		ack : 1,
		urg : 1,
		ece : 1,
		cwr : 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u_int16_t   doff : 4,
		res1 : 4,
		cwr : 1,
		ece : 1,
		urg : 1,
		ack : 1,
		psh : 1,
		rst : 1,
		syn : 1,
		fin : 1;
#else
#endif  
	u_int16_t   window;
	u_int16_t   check;
	u_int16_t   urg_ptr;
};
