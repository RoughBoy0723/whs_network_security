#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  printf("==========================================================\n");
  time_t timer = time(NULL);
  struct tm* t = localtime(&timer);
  printf("time : %d/%d/%d   %d:%d:%d \n", t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

  struct ethheader *eth = (struct ethheader *)packet;
  
  u_int8_t *dst_mac = eth->ether_dhost;
  u_int8_t *src_mac = eth->ether_shost;

  printf("-----------------------------------------------------------\n");
  printf("mac source : %02x:%02x:%02x:%02x:%02x:%02x\n",src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
  printf("mac dest   : %02x:%02x:%02x:%02x:%02x:%02x\n",dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
 

  struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

  printf("-----------------------------------------------------------\n");
  printf("ip source : %s\n", inet_ntoa(ip->iph_sourceip));   
  printf("ip dest   : %s\n", inet_ntoa(ip->iph_destip));    


  struct tcpheader *tcp =(struct tcpheader *)(packet + sizeof(struct ethheader)+sizeof(struct ipheader));

  printf("----------------------------------------------------------\n");
  printf("tcp source : %d\n",ntohs(tcp->tcp_sport));
  printf("tcp dest   : %d\n",ntohs(tcp->tcp_dport));
	    
  uint8_t ethheader_len = sizeof(struct ethheader);
  uint8_t ipheader_len = sizeof(struct ipheader);
  uint8_t tcpheader_len = sizeof(struct tcpheader);
  uint16_t ip_len = ntohs(ip->iph_len);
  int data_len = ip_len-ipheader_len-tcpheader_len;

  if(data_len > 0){
    unsigned char * real_data = (unsigned char *)(packet + ethheader_len  + ipheader_len + tcpheader_len);
    printf("----------------------------------------------------------\n");
    for(int i = 0; i< data_len; i++){
      printf("%02X ", real_data[i]);
        
      if(i % 16 == 0){
        printf("\n");
      }
    }
  }
  printf("\n");
  return;
}

int main(){
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);
  return 0;
}
