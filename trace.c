#include "trace.h"
#include "checksum.h"

int main(int argc, char *argv[]){

    pcap_t *pointer = trace_init(argv[1]);

    header_print(pointer);

    return 0;
}

void IP_print(const u_int8_t *data){

    printf("\tIP Header\n");
    printf("\t\tIP Version: %d\n", data[14] >> 4);
    printf("\t\tHeader Len (bytes): %d\n", (data[14] & 0x0f) * 4);
    printf("\t\tTOS subfields:\n");
    printf("\t\t   Diffserv bits: %d\n", data[15] >> 2);
    printf("\t\t   ECN bits: %d\n", data[15] & 0x03);
    printf("\t\tTTL: %d\n", data[22]);
    printf("\t\tProtocol: %s\n", get_protocol(data[23]));
    printf("\t\tChecksum: %s (0x%04x)\n", get_checksum((unsigned short*)&data[14], (data[14] & 0x0f) * 4, data[24]), data[24] << 8 | data[25]);
    printf("\t\tSender IP: %s\n", inet_ntoa(*(struct in_addr*)&data[26]));
    printf("\t\tDest IP: %d.%d.%d.%d\n\n", data[30], data[31], data[32], data[33]);

    
}

char *get_checksum(unsigned short *addr, int len, unsigned short checksum){

    if(in_cksum(addr, len) == 0)
        return "Correct";
    else
        return "Incorrect";
}

char *get_protocol(uint8_t protocol){
        if (protocol == IPPROTO_ICMP)
            return "ICMP";
        else if(protocol == IPPROTO_TCP)
            return "TCP";
        else if (protocol == IPPROTO_UDP)
            return "UDP";
        else
            return "Unknown";
}


void header_print(pcap_t *ptr){
    struct pcap_pkthdr *header;
    const uint8_t *data;

    uint16_t count = 1;
    while(pcap_next_ex(ptr, &header, &data) != PCAP_ERROR_BREAK){

        ethernet_print(ptr, count, data, header);

        if(data[12] == 0x08 && data[13] == 0x00){
            printf("\t\tType: IP\n\n");
            IP_print(data);      // IP
        }
        else{
            printf("\t\t Type: ARP\n\n");
            // ARP_print(ptr);     // ARP
        }

        if(data[23] == IPPROTO_ICMP){      // ICMP
             //ICMP_print(ptr);
         }
        // else if (data[24] == IPPROTO_TCP){    // TCP
        //     TCP_print(ptr);
        // }
        else if (data[23] == IPPROTO_UDP){   // UDP
             UDP_print(data);
         }
        count++;
    }
}



void ethernet_print(pcap_t *ptr, uint16_t count, const u_int8_t *data, struct pcap_pkthdr *header){
    printf("\nPacket number: %d  ", count);
    printf("Packet Len: %d\n\n\t", header -> len);
    printf("Ethernet Header\n");
    printf("\t\tDest MAC: %x:%x:%x:%x:%x:%x\n", data[0], data[1], data[2], data[3], data[4], data[5]);
    printf("\t\tSource MAC: %x:%x:%x:%x:%x:%x\n", data[6], data[7], data[8], data[9], data[10], data[11]);
}

pcap_t *trace_init(char* program){
    const char *filename = program;

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *pointer = pcap_open_offline(filename, errbuf); 

    if(pointer == NULL){
        fprintf(stderr, "Error: %s\n", errbuf);
        return (pcap_t*)1;
    }
    return pointer;
}


void UDP_print(const u_int8_t *data){
    uint16_t source_port = data[34] << 8 | data[35];
    uint16_t destination_port = data[36] << 8 | data[37];
    printf("\tUDP Header\n");
    if(source_port == 53){
        printf("\t\tSource Port:  %s\n", "DNS");
    }
    else{
        printf("\t\tSource Port:  %d\n", source_port);
    }

    if(destination_port == 53){
        printf("\t\tDest Port:  %s\n", "DNS");
    }
    else{
        printf("\t\tDest Port:  %d\n", destination_port);
    }

}