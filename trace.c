#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[]){

    char *filename = "ping.pcap";

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *pointer = pcap_open_offline(filename, errbuf); 

    if(pointer == NULL){
        fprintf(stderr, "Error: %s\n", errbuf);
    }
    
    return 0;
}