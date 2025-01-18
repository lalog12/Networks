#ifndef TRACE_H
#define TRACE_H
#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>

typedef struct my_pcap my_pcap_t;

// Initialize the tracing system
pcap_t *trace_init(char argv[]);

void header_print(pcap_t *ptr);

void ethernet_print(pcap_t *ptr, uint16_t count, const u_int8_t *data, struct pcap_pkthdr *header);

void IP_print(const u_int8_t *data);

void TCP_print(const u_int8_t *data,const uint16_t total_length,const uint16_t IP_header_length);

uint16_t *TCP_pseudoheader(const u_int8_t *data);

uint16_t *TCP_checksum_buffer(const u_int8_t *data,uint16_t *pseudoheader);

void UDP_print(const u_int8_t *data,const uint16_t total_length,const uint16_t IP_header_length);

void ICMP_print(const u_int8_t *data,const uint16_t total_length,const uint16_t IP_header_length);

char *get_port(uint16_t port);

void ARP_print(const u_int8_t *data);

void print_port(uint16_t port);

char *get_yes_no(uint16_t flag);

char *get_protocol(uint8_t protocol);

char *get_checksum(unsigned short *addr, int len);


#endif /* TRACE_H */