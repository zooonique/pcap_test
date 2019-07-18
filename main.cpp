#include <pcap.h>
#include <stdio.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

    /* Ethernet header */
    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    }sniff_ethernet;





void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_char * mac,int index){
    if(index==0)
        printf("Dmac ");
    else
        printf("Smac ");

    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void check_ip(const u_char* ether_type,int index){

    u_short res = ((ether_type[0]<<8) | ((ether_type[1])));

    if(res==0x0800)
    printf("ehternet header : %04x (IPv4)\n",res);

    else if(res==0x0806)
        printf("ehternet header : %04x (ARP)\n",res);

    else if(res==0x86DD)
        printf("ehternet header : %04x (IPv6)\n",res);

    else
        printf("Unknown\n");



    }

void check_protocol(const u_char* protocol, int index){

    if (protocol[0]==0x06)
        printf("protocol : TCP\n");

    else if (protocol[0]==0x11)
        printf("protocol : UDP\n");

    else printf("Unknown!   \n",protocol[0],protocol[0]);
}

void print_ip(const u_char * ip,int index){
    if(index==26)
        printf("s-ip ");

    else
        printf("d-ip ");

        printf("%d.%d.%d.%d \n",ip[0],ip[1],ip[2],ip[3]);

}

void print_port(const u_char * port,int index){
    if(index==34) printf("s-port ");

    else printf("d-port ");

    printf("%d\n", (port[0] << 8) | port[1]);
}


void print_data(const u_char * data, int index){

    u_short size = ((data[0]<<8) | ((data[1])))-40;

    printf("******tcp data *******\n");

    printf("data size : %d\n",size);

    int max = size;

    if(max<10){

        for (int i=39;i<39+max ;i++) {
            printf("%02x ",data[i]);
        }
    }
    else{
        for (int i=39;i<49 ;i++) {
            printf("%02x ",data[i]);
        }
    }
    printf("\n**********************\n");

}



int main(int argc, char* argv[]) {

    char track[]="컨설팅";
    char name[]="권혁준";

    printf("[bob8][%s]pcap_test[%s]",track,name);

  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }



  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    printf("==========================\n");

    for (int i =0;i<header->len;i++) {

        if(i==0||i==6) print_mac(&packet[i],i); // Dmac Smac

        if(i==12) check_ip(&packet[i],i);   //IP ARM IPv6

        if(i==16) print_data(&packet[i],i); //print_tcp_data

        if(i==23) check_protocol(&packet[i],i); //TCP UDP

        if(i==26||i==30) print_ip(&packet[i],i);    // Dip Sip

        if(i==34||i==36) print_port(&packet[i],i);  //  Dport   Sport


    }
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    printf("==========================\n");

  }

  pcap_close(handle);
  return 0;
}
