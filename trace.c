#include "trace.h"
#include "checksum.h"

int main(int argc, char *argv[]){

    pcap_t *pointer = trace_init(argv[1]);

    header_print(pointer);

    return 0;
}

char *get_port(uint16_t port) {
    static char port_str[10];  // Static buffer to hold the port number string

    if (port == 53) {
        return "DNS";
    }
    else if (port == 80) {
        return "HTTP";
    }
    else if (port == 443) {
        return "HTTPS";
    }
    else {
        sprintf(port_str, "%u", port);  // Convert port number to string
        return port_str;
    }
}

void TCP_print(const u_int8_t *data, const uint16_t total_length, const uint16_t IP_header_length){
    printf("\n\tTCP Header\n");
    uint16_t TCP_start = 13 + IP_header_length;
    printf("\t\tSource Port:  %s\n", get_port(ntohs(*(uint16_t*)&data[TCP_start + 1])));
    printf("\t\tDest Port:  %s\n", get_port(ntohs(*(uint16_t*)&data[TCP_start + 3])));
    printf("\t\tSequence Number: %u\n", ntohl(*(uint32_t*)&data[TCP_start + 5]));
    printf("\t\tACK Number: %u\n", ntohl(*(u_int32_t*)&data[TCP_start + 9]));
    printf("\t\tData Offset (bytes): %u\n", ((data[TCP_start + 13] & 0xf0) >> 4) * 4);
    printf("\t\tSYN Flag: %s\n", get_yes_no(data[TCP_start + 14] & 0x02));
    printf("\t\tRST Flag: %s\n", get_yes_no(data[TCP_start + 14] & 0x04));
    printf("\t\tFIN Flag: %s\n", get_yes_no(data[TCP_start + 14] & 0x01));
    printf("\t\tACK Flag: %s\n", get_yes_no(data[TCP_start + 14] & 0x10));
    printf("\t\tWindow Size: %d\n", ntohs(*(uint16_t*)&data[TCP_start + 15]));
    uint16_t *pseudoheader = TCP_pseudoheader(data);

    
    uint16_t TCP_segment_length = total_length - IP_header_length;
    uint16_t TCP_checksum_buffer_len = 12 + TCP_segment_length;
    uint16_t TCP_checksum_buffer[TCP_checksum_buffer_len];
    memcpy(&TCP_checksum_buffer, pseudoheader, 12);
    memcpy(&TCP_checksum_buffer[6], &data[TCP_start + 1], TCP_segment_length);

    printf("\t\tChecksum: %s (0x%04x)\n", get_checksum((unsigned short*)&TCP_checksum_buffer, TCP_checksum_buffer_len), ntohs(*(uint16_t*)&data[TCP_start + 17]));
}




char *get_checksum(unsigned short *addr, int len){

    if(in_cksum(addr, len) == 0)
        return "Correct";
    else
        return "Incorrect";
}

uint16_t *TCP_pseudoheader(const u_int8_t *data) {
    static uint16_t TCP_pseudo_header[6];  
    
    // IP addresses stay in network order
    // Source IP Address
    memcpy(&TCP_pseudo_header[0], &data[26], 4);
    // Destination IP Address
    memcpy(&TCP_pseudo_header[2], &data[30], 4);


    // Reserved field and Protocol
    uint16_t var = htons(0x0006);
    memcpy(&TCP_pseudo_header[4], &var, 2);

    // TCP segment length
    uint16_t IP_total_length = ntohs(*(uint16_t*)&data[16]);
    uint16_t IP_header_length = (data[14] & 0x0f) * 4;
    uint16_t TCP_segment_length = htons(IP_total_length - IP_header_length);
    memcpy(&TCP_pseudo_header[5], &TCP_segment_length, 2);

    return TCP_pseudo_header;
}


char *get_yes_no(uint16_t flag){
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

        uint16_t total_length = ntohs(*(uint16_t*)&data[16]);
        uint16_t IP_header_length = (data[14] & 0x0f) * 4;
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
            ICMP_print(data, total_length, IP_header_length);
        }

        else if (data[23] == IPPROTO_TCP){    // TCP
            TCP_print(data, total_length, IP_header_length);
         }

        else if (data[23] == IPPROTO_UDP){   // UDP
             UDP_print(data, total_length, IP_header_length);
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

void ICMP_print(const u_int8_t *data, const uint16_t total_length, const uint16_t IP_header_length){
    printf("\n\tICMP Header\n");
    uint16_t ICMP_start = 13 + IP_header_length;

    if ( ( ((data[14] & 0xf0) >> 4) != 4) && (((data[14] & 0xf0) >> 4) != 6) ){
        printf("\t\tType: %d\n", 109);
    }
    else if (data[ICMP_start + 1] == 0)
    {
       printf("\t\tType: %s\n", "Reply");
    }
    else if(data[ICMP_start + 1] == 8){
        printf("\t\tType: %s\n", "Request");
    }

    
}


void UDP_print(const u_int8_t *data, const uint16_t total_length, const uint16_t IP_header_length){
    uint16_t UDP_start = 13 + IP_header_length;
    uint16_t source_port = ntohs(*(uint16_t*)(&data[UDP_start + 1]));
    uint16_t destination_port = ntohs(*(uint16_t*)(&data[UDP_start + 3]));
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