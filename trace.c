#include "trace.h"
#include "checksum.h"

int main(int argc, char *argv[]){

    pcap_t *pointer = trace_init(argv[1]);

    header_print(pointer);

    return 0;
}

void TCP_print(const u_int8_t *data){
    printf("\n\tTCP Header\n");
    printf("\t\tSource Port: %d\n", ntohs(*(uint16_t*)&data[34]));
    printf("\t\tDest Port: %d\n", ntohs(*(uint16_t*)&data[36]));
    printf("\t\tSequence Number: %d\n", ntohl(*(uint32_t*)&data[38]));
    printf("\t\tAck Number: %u\n", ntohl(*(u_int32_t*)&data[42]));
    printf("\t\tData Offset (bytes): %d\n", (data[14] & 0x0f) * 4);
    printf("\t\tSYN Flag: %s\n", get_yes_no(data[47] & 0x02));
    printf("\t\tRST Flag: %s\n", get_yes_no(data[47] & 0x04));
    printf("\t\tFIN Flag: %s\n", get_yes_no(data[47] & 0x01));
    printf("\t\tACK Flag: %s\n", get_yes_no(data[47] & 0x08));
    printf("\t\tWindow Size: %d\n", ntohs(*(uint16_t*)&data[48]));
    printf("\t\tChecksum: %s (0x%04x)\n", get_checksum(TCP_checksum(data), 12), data[50] << 8 | data[51]);
}

uint16_t *TCP_checksum(const u_int8_t *data) {
    // Twice as many uint16_t elements since each is 2 bytes
    static uint16_t TCP_pseudo_header[6];  // 12 bytes total (6 * 2 bytes)
    
    // Copy as 16-bit 
    TCP_pseudo_header[0] = ntohs(*(uint16_t*)&data[26]);    // First half of source IP
    TCP_pseudo_header[1] = ntohs(*(uint16_t*)&data[28]);    // Second half of source IP
    TCP_pseudo_header[2] = ntohs(*(uint16_t*)&data[30]);    // First half of dest IP
    TCP_pseudo_header[3] = ntohs(*(uint16_t*)&data[32]);    // Second half of dest IP
    
    // Zero and protocol as 16-bit value
    TCP_pseudo_header[4] = (0 << 8) | 6;    // Zero byte and protocol combined
    
    // TCP length as 16-bit value
    uint16_t TCP_segment_length = ntohs(*(uint16_t*)&data[16]) - ((data[14] & 0x0f) * 4);
    TCP_pseudo_header[5] = TCP_segment_length;

    return TCP_pseudo_header;
}


char *get_yes_no(uint8_t flag){
    if(flag != 0){
        return "Yes";
    }
    else{
        return "No";
    }
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
    printf("\t\tChecksum: %s (0x%04x)\n", get_checksum((unsigned short*)&data[14], (data[14] & 0x0f) * 4), data[24] << 8 | data[25]);
    printf("\t\tSender IP: %s\n", inet_ntoa(*(struct in_addr*)&data[26]));
    printf("\t\tDest IP: %d.%d.%d.%d\n", data[30], data[31], data[32], data[33]);

    
}

char *get_checksum(unsigned short *addr, int len){

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
            printf("\t\tType: ARP\n\n");
            ARP_print(data);     // ARP
            count++;
            continue;
        }

        if(data[23] == IPPROTO_ICMP){      // ICMP
            ICMP_print(data);
         }
        else if (data[23] == IPPROTO_TCP){    // TCP
            TCP_print(data);
         }
        else if (data[23] == IPPROTO_UDP){   // UDP
             UDP_print(data);
         }
        count++;
    }
}

void ARP_print(const u_int8_t *data){
    printf("\tARP header\n");
    if (data[21] !=  2)
    {
        printf("\t\tOpcode: %s\n", "Request");
    }
    else{
        printf("\t\tOpcode: %s\n", "Reply");
    }
    printf("\t\tSender MAC: %x:%x:%x:%x:%x:%x\n", data[22], data[23], data[24], data[25], data[26], data[27]);
    printf("\t\tSender IP: %d.%d.%d.%d\n", data[28], data[29], data[30], data[31]);
    printf("\t\tTarget MAC: %x:%x:%x:%x:%x:%x\n", data[32], data[33], data[34], data[35], data[36], data[37]);
    printf("\t\tTarget IP: %d.%d.%d.%d\n\n", data[38], data[39], data[40], data[41]);
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

void ICMP_print(const u_int8_t *data){
    printf("\n\tICMP Header\n");

    if ( ( ((data[14] & 0xf0) >> 4) != 4) && (((data[14] & 0xf0) >> 4) != 6) ){
        printf("\t\tType: %d\n", 109);
    }
    else if (data[34] == 0)
    {
       printf("\t\tType: %s\n", "Reply");
    }
    else if(data[34] == 8){
        printf("\t\tType: %s\n", "Request");
    }

    
}


void UDP_print(const u_int8_t *data){
    uint16_t source_port = data[34] << 8 | data[35];
    uint16_t destination_port = data[36] << 8 | data[37];
    printf("\n\tUDP Header\n");
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