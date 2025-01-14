#ifndef TRACE_H
#define TRACE_H
#include <stdio.h>
#include <pcap.h>
#include <stdint.h>


typedef struct my_pcap my_pcap_t;

// Initialize the tracing system
pcap_t *trace_init(char argv[]);

void header_print(pcap_t *ptr);

void ethernet_print(pcap_t *ptr, uint16_t count, const u_int8_t *data, struct pcap_pkthdr *header);

void IP_print(const u_int8_t *data);

void TCP_print(pcap_t *ptr);

void UDP_print(const u_int8_t *data);

void ICMP_print(pcap_t *ptr);

void ARP_print(pcap_t *ptr);

char *get_protocol(uint8_t protocol);

char *get_checksum(unsigned short *addr, int len, unsigned short checksum);


#endif /* TRACE_H */