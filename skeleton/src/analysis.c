#include "analysis.h"


#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <pthread.h>

int xmas_count=0;
int arp_count=0;
int url_violation=0;


pthread_mutex_t xmas_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t arp_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t blacklist_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t count_lock = PTHREAD_MUTEX_INITIALIZER;

//_______________________________________________________________________________________________________________
//                                        PARSE FUNCTIONS



void parseEthernet(struct ether_header *eth_header, long pcount, int v){



//DEBUGGING CODE
  if (v){
    printf("\n\n === PACKET %ld ===", pcount);
    unsigned int i;
    printf("\n ==ETHERNET HEADER==");
    printf("\nSource MAC: ");
    for (i = 0; i < 6; ++i) {
      printf("%02x", eth_header->ether_shost[i]);
      if (i < 5) {
        printf(":");
      }
    }
    printf("\nDestination MAC: ");
    for (i = 0; i < 6; ++i) {
      printf("%02x", eth_header->ether_dhost[i]);
      if (i < 5) {
        printf(":");
      }
    }
    if(ntohs(eth_header->ether_type) == ETHERTYPE_IP){
      printf("\nTYPE:      %s\n","IP" );
    }else if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
      printf("\nTYPE:      %s\n","ARP" );
    }else if(ntohs(eth_header->ether_type) == ETHERTYPE_REVARP){
      printf("\nTYPE:      %s\n","REVERSE ARP" );
    }
  }
//END OF DEBUGGING CODE

}

void parseIP(struct ip * ip_header, int v){
//DEBUGGING CODE
  if(v){
    printf("\n ===IP HEADER ===");
    char src_ip_addr[INET_ADDRSTRLEN];
    char des_ip_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), des_ip_addr, INET_ADDRSTRLEN);
    printf("\nSource IP Address: ");
    printf("%s", src_ip_addr);
    printf("\nDestination IP Address: ");
    printf("%s", des_ip_addr);
  }
//END OF DEBUGGING CODE
}

int parseTCP(struct tcphdr* tcp_header, int v){
//DEBUGGING CODE
  if(v){
    printf("\n ===TCP HEADER ===");
    printf("\nSource port: ");
    printf("%d", ntohs(tcp_header->source));
    printf("\nDestination port: ");
    printf("%d", ntohs(tcp_header->dest));
  }
//END OF DEBUGGING CODE
//CHECK FOR FLAGS
    if((tcp_header->fin) && (tcp_header->psh) && (tcp_header->urg)){
      pthread_mutex_lock(&xmas_lock);
      xmas_count++;
      pthread_mutex_unlock(&xmas_lock);
      printf("\nXMAS SCAN PACKET\n");
      return 1;

    }
    return 0;
}

int parseARP(struct ether_arp* arp_header, int pcount, int v){
    unsigned int i;
//DEBUGGING CODE
  if(v){
    printf("\n===ARP NUMBER %ld HEADER===\n",pcount);
    printf("SENDER HARDWARE ADDRESS: ");
    for (i = 0; i < 6; ++i) {
      printf("%02x", arp_header->arp_sha[i]);
      if (i < 5) {
        printf(":");
      }
    }
    printf("\nSENDER PROTOCOL ADDRESS: ");
    for (i = 0; i < 4; ++i) {
      printf("%02x", arp_header->arp_spa[i]);
      if (i < 3) {
        printf(":");
      }
    }
    printf("\nTARGET HARDWARE ADDRESS: ");
    for (i = 0; i < 6; ++i) {
      printf("%02x", arp_header->arp_tha[i]);
      if (i < 5) {
        printf(":");
      }
    }
    printf("\nTARGET PROTOCOL ADDRESS :");
    for (i = 0; i < 4; ++i) {
      printf("%02x", arp_header->arp_sha[i]);
      if (i < 3) {
        printf(":");
      }
    }
  }
//END OF DEBUGGING CODE

//CHECK WHETHER ARP OPERATION IS A REPLY
    if (arp_header -> arp_op == htons(ARPOP_REPLY)) {
      pthread_mutex_lock(&arp_lock);
      arp_count++;
      pthread_mutex_unlock(&arp_lock);
      printf("\nARP CACHE POISONING\n");
    }
    return 1;
}
int blacklistedURL(unsigned char* payload){

  if(strstr(payload,"Host: www.bbc.co.uk")!=NULL){
  pthread_mutex_lock(&blacklist_lock);
    url_violation++;
    pthread_mutex_unlock(&blacklist_lock);
    printf("Blacklisted URL violation\n");
    return 1;
  }
  return 0;
}
void sig_handler(int signo){
  if(signo == SIGINT){
    //Construct a report and stop execution
    cleanMemory();
    printf("\n\n\n\nFOUND FOLLOWING SIGNS OF INTRUSION: \n %lu XMAS TREE PACKETS \n %lu ARP CACHE POISONING \n %lu blacklisted URL violations \n", xmas_count,arp_count,url_violation);
    exit(0);
  }
}

//_______________________________________________________________________________________________________________
//                          END OF PARSE FUNCTIONS




void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {

    static unsigned long pcount = 0;
//struct the outer header and check if the packet is an ARP response
    struct ether_header *eth_header = (struct ether_header *) packet;
    if(ntohs(eth_header->ether_type)== ETHERTYPE_ARP){
      struct ether_arp * arp_header = (struct ether_arp *) (packet+ETH_HLEN);
      parseEthernet(eth_header,pcount,verbose);
      parseARP(arp_header,pcount, verbose);

    }else{
//If not an ARP packet, construct the other headers and check whether packet follows TCP protocol
      struct ip *ip_header = (struct ip*) (packet + ETH_HLEN);
      struct tcphdr *tcp_header = (struct tcphdr*)( packet + ETH_HLEN +(ip_header->ip_hl*4));

      if(ip_header->ip_p == IPPROTO_TCP){

            if(ntohs(tcp_header->dest)==80){ //Check if packet is an HTTP request
              //GET THE PAYLOAD
              int data_offset = tcp_header->doff;
              int tcp_length = sizeof(struct tcphdr);
              int eth_and_ip_length = packet+ETH_HLEN+(ip_header->ip_hl*4);
              unsigned char *payload = (unsigned char *)(eth_and_ip_length+tcp_length+data_offset);
              blacklistedURL((unsigned char *)payload);
            }
            parseEthernet(eth_header,pcount,verbose);
            parseIP(ip_header,verbose);
            parseTCP(tcp_header,verbose);

      }else{
        printf("NOT A TCP PROTOCOL, skipping...\n");}

    }
    //Handle the signal
    if(signal(SIGINT,sig_handler)==SIG_ERR) printf("\nCan't catch signal\n");
    //INCREMENT PACKET COUNT SAFELY
    pthread_mutex_lock(&count_lock);
    pcount++;
    pthread_mutex_unlock(&count_lock);
    //Destroy the locks
    pthread_mutex_destroy(&count_lock);
    pthread_mutex_destroy(&xmas_lock);
    pthread_mutex_destroy(&arp_lock);
    pthread_mutex_destroy(&blacklist_lock);


}
