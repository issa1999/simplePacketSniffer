#include<bits/stdc++.h>
#include<netinet/in.h> // for networrk & sockets
#include<errno.h> // for handling errors
#include<netdb.h> // for network database
#include<stdlib.h> // for malloc
#include<stdio.h> // for standard functions and in/out 
#include<string.h> // for strings functions like strlen

#include<netinet/ip_icmp.h> // provides declarations for icmp header
#include<netinet/udp.h> // declarations for udp header
#include<netinet/tcp.h> // declarations for tcp header
#include<netinet/if_ether.h> // for eth_p_all
#include<netinet/ip.h> // declaration for ip header
#include<net/ethernet.h> // declaration for ethernet header
#include<sys/socket.h> // for sockets to use
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
using namespace std;
/**
 * @brief  PACKET DESCRIPTION
 * ETH: header|start_delimiter|destination|source|opt|length|payload|checksum|interpacket_gap
 * IP: version|header_len|tot_len|id|flags|offset|ttl|protocol|checksum|source|desti|opt|data|
 * ICMP: TYPE|CODE|CHECKSUM|--|DATA
 * TCP: sourcePort|destPort|seqNum|ACK_NUM|DO|RSV|FLAGS|WINDOW|CHECKSUM|URG_POINTER|OPT
 * UDP: sourceADRR|destADRR|zero|prot|udplen|{{sourceport|destport|length|checksum}}
 * 
 */
/**
 * @brief Types to use 
 * 
 */
typedef  struct iphdr iphdr ;
typedef struct sockaddr_in sockaddr_in;
typedef struct ethhdr ethhdr;
typedef struct sockaddr sockaddr; // generic socket address :address family and data
typedef struct tcphdr tcphdr;
typedef struct udphdr udphdr;
typedef struct icmphdr icmphdr;
/**
 * @brief function to use in main 
 * 
 */
void ProcessPacket(unsigned char*, int);
void print_ip_header(unsigned char*,int);
void print_tcp_packet(unsigned char*,int);
void print_udp_packet(unsigned char*,int);
void print_icmp_pakcet(unsigned char*,int);
void printData(unsigned char*,int);
/**
 * @brief global variables 
 * 
 */
struct sockaddr_in source,dest;
map<string,int> packets;
ofstream  logfile("logfile.txt"); // logfile to put the result

int main(){
    int saddr_size,data_size;
    unsigned char* buffer = (unsigned char*) malloc(INT_MAX);
    sockaddr saddr;
    if(!logfile.is_open()){cout<<"FILE NOT OPEN",exit(1);}
     cout<<"Starting ...\n";
//cout<<packets["icmp"];
     // create the listening socket which will capture all packet types 
int sock_raw = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(sock_raw<0) {perror("Error");exit(EXIT_FAILURE);}
    while(1){
        saddr_size = sizeof(saddr);
        //receive a packet
        data_size = recvfrom(sock_raw,buffer,65536,0,&saddr,(socklen_t*)&saddr_size);
        if(data_size<0){
            perror("recvfrom error, can't get packets\n");
            exit(EXIT_FAILURE);
        }
        //NOW WE CAN PROCESS THE PACKET AND START CAPTURING PACKETS
        ProcessPacket(buffer,data_size);
    }
    close(sock_raw);
    cout<<"Finished ^^"<<'\n';
    return 0;
} 
void ProcessPacket(unsigned char* buffer,int size){
    //get the IP header part of the packet, exclude the ethernet header
    struct iphdr *ip_header = (struct iphdr*)(buffer + sizeof(ethhdr));
    ++packets["total"];
    switch (ip_header->protocol)
    {
    case 1: // ICMP
        ++packets["ICMP"];
        print_icmp_pakcet(buffer,size);
        break;
    case 2: //IGMP
        ++packets["IGMP"];
        break;
    case 6: // TCP
    ++packets["TCP"];
    print_tcp_packet(buffer,size);
    break;
    case 17: // UDP
    ++packets["UDP"];
    print_udp_packet(buffer,size);
    break;
    default:
    ++packets["OTHERS"];
        break;
    }
    cout<<"TCP\t:  "<<packets["TCP"]<<"\tICMP\t:   "<<packets["ICMP"]<<"\tUDP\t:   "<<packets["UDP"]<<"\tOTHERS\t:  "<<packets["OTHERS"]<<"\tTOTAL\t"<<packets["total"]<<"\r";

}
void print_ethernet_header(unsigned char * buffer, int size){
    ethhdr *eth = (ethhdr*) buffer;
    logfile << "\n"<<"Ethernet Header\n";
    logfile<<setbase(16)<<"|-DESTINATION_ADDRESS: \t\n"<<eth->h_dest[0]<<"-"<<eth->h_dest[1]<<"-"<<eth->h_dest[2]<<"-"<<eth->h_dest[3]<<"-"<<eth->h_dest[4]<<"-"<<eth->h_dest[5]<<"-"<<eth->h_dest[6]<<'\n'
    <<"|-SOURCE ADDRESS: \t\n"<<eth->h_source[0]<<"-"<<eth->h_source[1]<<"-"<<eth->h_source[2]<<"-"<<eth->h_source[3]<<"-"<<eth->h_source[4]<<"-"<<eth->h_source[5]<<"-"<<eth->h_source[6]<<'\n'
    <<"|- PROTOCOL:\t\n"<<(unsigned short)eth->h_proto<<'\n';
}   
void print_ip_header(unsigned char* buffer,int size){
print_ethernet_header(buffer,size);
unsigned short ip_header_len;
struct iphdr *ip_header = (struct iphdr*)(buffer + sizeof(ethhdr));
ip_header_len = ip_header->ihl * 4; // block of bytes
memset(&source,0,sizeof(source)); // make all source socket fields to 0
source.sin_addr.s_addr = ip_header->saddr; // configure source address
memset(&dest,0,sizeof(dest));
dest.sin_addr.s_addr = ip_header->daddr;
logfile<<"\n|-IP HEADER\n"<<"|- IP VERSION: \t\n"<<ip_header->version<<"IP HEADER LENGTH: \t\n"<<(unsigned int)ip_header->ihl*4
<<"\n|-TYPE OF SERVICE: \t\n"<<ip_header->tos<<"\n|-IP TOTAL LENGTH :\t"<<(unsigned int) htons(ip_header->tot_len)<<"\n|- Identification  :\t"<<ntohs(ip_header->id)
<<"\n|-TTL : \t"<<(unsigned int) ip_header->ttl<<"\n|-PROTOCOL\t :"<<(unsigned int) ip_header->protocol<<"\n|-CHECKSUM :\t"<<ntohs(ip_header->check)<<"\n|-SOURCE IP :\t"<<inet_ntoa(source.sin_addr)<<"\n|-DESTINATION IP :\t"<<inet_ntoa(dest.sin_addr)<<'\n';
}

void print_tcp_packet(unsigned char* buffer,int size){
    unsigned short ip_header_len;
    struct iphdr *ip_header = (struct iphdr*)(buffer + sizeof(ethhdr));
    ip_header_len = ip_header->ihl *4;
    tcphdr * tcp_header = (tcphdr*)(buffer + ip_header_len + sizeof(ethhdr));
    int header_size = tcp_header->doff*4 + ip_header_len + sizeof(ethhdr);
    logfile <<"\n\n************************************TCP PAACKET*************************\n\n";
    print_ip_header(buffer,size); // calculate and write the ip header infos to th file before getting to tcp infos
    logfile<<"\n"<<"\nTCP HEADER\n\n"<<"\t |-SOURCE PORT:\t"<<ntohs(tcp_header->source)<<"\n\t|-DETINATION PORT:\t"<<ntohs(tcp_header->dest)
    <<"\n\t|-SEQUENCE NUMBER:\t"<<ntohl(tcp_header->seq)<<"\n\t|-ACK NUMBER:\t"<<ntohl(tcp_header->ack_seq)
    <<"\n\t|-HEADER LENGTH:\t"<<(unsigned int)tcp_header->doff*4
    <<"\n\t|-URG FLAG:\t"<<(unsigned int) tcp_header->urg<<"\n\t|-PSH FLAG:\t"<<(unsigned int)tcp_header->psh
    <<"\n\t|-RST FLAG:\t"<<(unsigned int)tcp_header->rst<<"\n\t|-SYN FLAG:\t"<<(unsigned int)tcp_header->syn
    <<"\n\t|-FIN FLAG:\t"<<(unsigned int)tcp_header->fin
    <<"\n\t|-Window:\t"<<ntohs(tcp_header->window)<<"\n\t|-CHECKSUM:\t"<<ntohs(tcp_header->check)<<"\n\t|-URG POINTER:\t"<<tcp_header->urg_ptr<<"\n\n\t\t\tDATA DUMP\t\t\t\n\n\t\t IP HEADER\n\n";
    printData(buffer,ip_header_len);
    logfile<<"TCP HEADER\n\n";
    printData(buffer + header_size,size - header_size);
    logfile<<"\n\n**********************************************************************\n\n";
}
    void print_udp_packet(unsigned char* buffer, int size){
        unsigned short ip_header_len;
        struct iphdr *ip_header = (struct iphdr*)(buffer + sizeof(ethhdr));
        ip_header_len = ip_header->ihl*4;
        udphdr* udp_header = (udphdr*)(buffer + ip_header_len  + sizeof(ethhdr));
        int header_size = sizeof(ethhdr) + ip_header_len + sizeof(udp_header);
        logfile<<"\n\n************************UDP PACKET******************\n\n";
        print_ip_header(buffer,size);
        logfile<<"\n\nUDP HEADER\n\n"<<"\n\n\t\t|-SOURCE PORT"<<ntohs(udp_header->source)
       <<"\n\n\t\t|-DESTINATION PORT"<<ntohs(udp_header->dest)<<"\n\n\t\t|-UDP LENGTH"<<ntohs(udp_header->len)
       <<"\n\n\t\t|-UDP CHECKSUM"<<ntohs(udp_header->check)<<"\n\nUDP HEADER\n\n";
       printData(buffer,ip_header_len);
       logfile<<"UDP HEADER\n\n";
       printData(buffer+ip_header_len,sizeof(udp_header));
       logfile<<"\nDATA PAYLOAD\n\n";
       printData(buffer + header_size,size-header_size);
           logfile<<"\n\n**********************************************************************\n\n";
    }
    void print_icmp_pakcet(unsigned char* buffer,int size){
            unsigned short ip_header_len;
            struct iphdr * ip_header = (struct iphdr*)(buffer + sizeof(ethhdr));
            ip_header_len = ip_header->ihl * 4;
            icmphdr* icmp_header = (icmphdr*)(buffer + sizeof(ethhdr) + ip_header_len);
            int header_size = sizeof(ethhdr) + ip_header_len + sizeof(icmp_header);
            logfile<<"\n\n*********************************ICMP PACKET**************************\n\n";
            print_ip_header(buffer,size);
            logfile<<"\n\nICMP HEADER\n\n\t|-TYPE:\t"<<(unsigned int) icmp_header->type;
            if((unsigned int)(icmp_header->type)==ICMP_ECHOREPLY){
                logfile<<"\t( ICMP ECHO/REPLY )\n";
            }
            else if((unsigned int)(icmp_header->type)==11){
                                logfile<<"\t( TTL EXPIRED )\n";
            }
            logfile<<"\n\t|-CODE:\t"<<(unsigned int) icmp_header->code<<"\n\t|CHECKSUM:\t"<<ntohs(icmp_header->checksum)
            <<"\n\nIP HEADER\n\n";
            printData(buffer,ip_header_len);
            logfile<<"\n\nICMP HEADER\n\n";
            printData(buffer+ip_header_len,sizeof(icmp_header));
            logfile<<"\n\n DATA PAYLOAD\n\n";
            printData(buffer+header_size,size-header_size);
           logfile<<"\n\n**********************************************************************\n\n";
    }
void printData(unsigned char* data,int size){
    for(int i=0;i<size;i++){
        if(i!=0 && i%16==0) // one line of hexx printing is complete
        {
            logfile<<"\t\t";
            for(int j = i-16;j<i;j++){
                if(data[j]>=32 && data[j]<=128){
                    logfile<<(unsigned char)data[j]; // if it is a number or alphabet
                }else {
                    logfile<<"."; // otherwise print a dot
                }
                logfile<<"\n";
            }
            if(i%16==0) logfile<<"\t\t";
            logfile<<std::hex<<setfill('0')<<setw(2)<<(unsigned int)data[i];
            if(i==size-1) // print the last spaces
            {
                for(int j=0;j<15-i%16;j++){
                    logfile<<"\t\t";//extra spaces
                }
                logfile<<"\t\t";
                for(int j=i-i%16;j<=i;j++){
                    if(data[j]>=32 && data[j]<=128){
                        logfile<<(unsigned char)data[j];
                    }
                    else {logfile<<'.';}
                }
                logfile<<'\n';

            }
        }
    }
}



 