//Chris Shorter
//cws68
//proj4.c
//11/10/18
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define ERROR 1
#define BUFLEN 2048
#define MINI_BUFLEN 32
#define TIMELEN 4
#define CAPLEN 2

#define MIN_ETHERNET 14
#define TYPELEN 2
#define ETH_BEGIN 12


#define MIN_IP 34
#define IPV4_VALUE 40
#define IPHLEN 1
#define IPLEN 2
#define PROTOLEN 1
#define IP_MIDLEN 4
#define IP_CHECKSUM_LEN 2
#define IP_ADDR_LEN 4
#define TTL_LEN 1
#define PORTLEN 2
#define ADDR1 0
#define ADDR2 1
#define ADDR3 2
#define ADDR4 3

#define TCP_BEGIN 8
#define SEQLEN 4
#define ACKLEN 4
#define WINDOWLEN 2
#define TCP_PORT 2
#define UDPLEN 8

#define SKIP_TO_TCP 8

#define ASCII_NUM 48
#define HEX_VAL 16




//If there's any sort of error the program exits immediately.
int errexit (char *format, char *arg){
    fprintf (stdout,format,arg);
    fprintf (stdout,"\n");
    exit (ERROR);
}

int printHex(unsigned char hex[], int n){
	int i = 0;
	for(; i< n; i++){
		printf("%02x", hex[i]);
	}
	printf("\n");

	return i;
}

int hexToInt(unsigned char* hex, int byte_flip){
	char int_str[IP_ADDR_LEN];
	int integer;
	int x, y;
	sprintf(int_str, "%02x", hex[0]);

	if(byte_flip == 1){
		x = 1;
		y = HEX_VAL;
	}
	else{
		x = HEX_VAL;
		y = 1;
	}
	if(int_str[0] >= '0' && int_str[0] <= '9'){
		integer = x*(((int) int_str[0])-ASCII_NUM);
	}
	else{
	switch(int_str[0]){
		case 'a':
			integer = x*10;
			break;
		case 'b':
			integer = x*11;
			break;
		case 'c':
			integer = x*12;
			break;
		case 'd':
			integer = x*13;
			break;
		case 'e':
			integer = x*14;
			break;
		case 'f':
			integer = x*15;
			break;
		}
	}

	if(int_str[1] >= '0' && int_str[1] <= '9'){
		integer += y*(((int) int_str[1])-ASCII_NUM);
	}
	else{
	switch(int_str[1]){
		case 'a':
			integer += y*10;
			break;
		case 'b':
			integer += y*11;
			break;
		case 'c':
			integer += y*12;
			break;
		case 'd':
			integer += y*13;
			break;
		case 'e':
			integer += y*14;
			break;
		case 'f':
			integer += y*15;
			break;
		}
	}
	return integer;
}

bool compareHex(unsigned char hex1[], unsigned char hex2[], int n){
	bool same = true;
	int i = 0;
    for(; i< n; i++){
    	if(hex1[i] != hex2[i])
    		same = false;
    }
    return same;
}

char* processPacket(FILE* trace_file){
	char* processed_packet = malloc(MINI_BUFLEN);
	bzero(processed_packet, MINI_BUFLEN);

	unsigned char buffer[BUFLEN];
	unsigned char time_stamp[TIMELEN];
	unsigned char caplen[CAPLEN];
	unsigned char iplen[IPLEN];
	unsigned char iphlen[IPHLEN];
	unsigned char type[TYPELEN];
	unsigned char proto[PROTOLEN];
	unsigned char trans_hl[1]; 
	unsigned char src_ip[IP_ADDR_LEN];
	unsigned char dest_ip[IP_ADDR_LEN];
	unsigned char src_port[PORTLEN];
	unsigned char dest_port[PORTLEN];
	unsigned char ttl[TTL_LEN];
	unsigned char seq[SEQLEN];
	unsigned char ack[ACKLEN];

	bool ip = true;

	unsigned char IP[] = {0x08, 0x00};
	unsigned char TCP[] = {0x06};
	unsigned char UDP[] = {0x11};
	int packet_length;
	int ip_length = -1;
	int iph_length = -1;
	int trans_hl_length = 0;
	unsigned int addr_byte[IP_ADDR_LEN];
	int source_port;
	int destination_port;
	int time_to_live;
	int sequence;
	int ack_num;

	int time;
	int millis;
	int payload_len = 0;
	double real_time = 0;

	char str_iphl[MINI_BUFLEN];
	char str_trans_hl[MINI_BUFLEN];
	char source_ip[MINI_BUFLEN];
	char destination_ip[MINI_BUFLEN];

	char protocol = '-';

	bzero(buffer, BUFLEN);

	if(fread(buffer, 1, CAPLEN, trace_file)>0){
		//find out how long packet is;
		memcpy(caplen, buffer, CAPLEN);
		memcpy(&packet_length, caplen,CAPLEN);
	   	packet_length = ntohs(packet_length);

	   	//read out ignored bytes
	   	bzero(buffer, BUFLEN);
	   	fread(buffer, 1, CAPLEN, trace_file);
   		bzero(buffer, BUFLEN);

   		//read out the time in seconds
    	fread(buffer, 1, TIMELEN, trace_file);
    	memcpy(time_stamp, buffer, TIMELEN);
	   	memcpy(&time, time_stamp,TIMELEN);
	   	time = ntohl(time);		   	
	   	
	   	//Read out time in milliseconds
	   	bzero(buffer, BUFLEN);
	    fread(buffer, 1, TIMELEN, trace_file);
	    memcpy(time_stamp, buffer, TIMELEN);
	   	memcpy(&millis, time_stamp,TIMELEN);
	   	millis = ntohl(millis);
	   	real_time = time + ((double) millis)/1000000;
	    
	    int index = 0;
	    
	    //if the packet is long enough to have ethernet header use it
	    if(packet_length > MIN_ETHERNET){
		    //ignore beginning of ethernet header
		    fread(buffer, 1, ETH_BEGIN, trace_file);
		    index += ETH_BEGIN;
		    bzero(buffer, BUFLEN);

		    //Read type field from Ethernet header
		    fread(buffer, 1, TYPELEN, trace_file);
		    memcpy(type, buffer, TYPELEN);
		    bzero(buffer, BUFLEN);
		    index += TYPELEN;
		    
		    ip = compareHex(IP, type, TYPELEN);

		    //If the packet is long enough to have IP header use it
		    if(ip && packet_length >= MIN_IP){
		    	int ip_index = 0;

		    	fread(buffer, 1, IPHLEN, trace_file);
		    	memcpy(iphlen, buffer, IPHLEN);
		    	sprintf(str_iphl, "%02x", iphlen[0]);
		    	iph_length = (atoi(str_iphl)-IPV4_VALUE)*TIMELEN;  
		    	index += IPHLEN;
		    	ip_index += IPHLEN;

		   		//ignore middle bytes of header
		   		fread(buffer, 1, PROTOLEN, trace_file);
		   		bzero(buffer, BUFLEN);
		   		index += PROTOLEN;
		   		ip_index += PROTOLEN;

		    	//Read in value of IP length
		    	fread(buffer, 1, IPLEN, trace_file);
		    	memcpy(iplen, buffer, IPLEN);
		    	memcpy(&ip_length, iplen,IPLEN);
		   		ip_length = ntohs(ip_length);
		   		bzero(buffer, BUFLEN);
		   		index += IPLEN;
		   		ip_index += IPLEN;

		   		//ignore middle bytes of header
		   		fread(buffer, 1, IP_MIDLEN, trace_file);
		   		bzero(buffer, BUFLEN);
		   		index += IP_MIDLEN;
		   		ip_index += IP_MIDLEN;

		   		//Read TTL
   				fread(buffer, 1, TTL_LEN, trace_file);
		    	memcpy(ttl, buffer, TTL_LEN);
		   		time_to_live = hexToInt(ttl, 1);
		   		bzero(buffer, BUFLEN);
		   		index += TTL_LEN;
		   		ip_index += TTL_LEN;

		   		//Read protocol field from ip header
		   		fread(buffer, 1, PROTOLEN, trace_file);
		   		memcpy(proto, buffer, PROTOLEN);
		   		if(compareHex(TCP, proto, PROTOLEN)){
		   			protocol = 'T';
		   		}
		   		else{
		   			if(compareHex(UDP, proto, PROTOLEN)){
		   				protocol = 'U';
		   			}
		   			else{
		   				protocol = '?';
		   			}

		   		}
		   		bzero(buffer, BUFLEN);
		   		index += PROTOLEN;
		   		ip_index += PROTOLEN;

		   		//ignore checksum value of IP header
		   		fread(buffer, 1, IP_CHECKSUM_LEN, trace_file);
		   		bzero(buffer, BUFLEN);
		   		index += IP_CHECKSUM_LEN;
		   		ip_index += IP_CHECKSUM_LEN;

		   		//read out source IP Address
		   		int i = 0;
		   		for(; i<IP_ADDR_LEN; i++){
			   		fread(buffer, 1, 1, trace_file);
				    memcpy(src_ip, buffer, 1);
			   		addr_byte[i] = hexToInt(src_ip, 0);
				   	bzero(buffer, BUFLEN);
			   		index ++;
			   		ip_index ++;
			   	}
			   	sprintf(source_ip, "%d.%d.%d.%d", addr_byte[ADDR1], addr_byte[ADDR2], addr_byte[ADDR3], addr_byte[ADDR4]);

		   		//read out destination IP address
		   		i = 0;
		   		for(; i<IP_ADDR_LEN; i++){
			   		fread(buffer, 1, 1, trace_file);
				    memcpy(dest_ip, buffer, 1);
			   		addr_byte[i] = hexToInt(dest_ip, 0);
				   	bzero(buffer, BUFLEN);
			   		index ++;
			   		ip_index ++;
			   	}
			   	sprintf(destination_ip, "%d.%d.%d.%d", addr_byte[ADDR1], addr_byte[ADDR2], addr_byte[ADDR3], addr_byte[ADDR4]);

				//ignore rest of IP Bytes
		   		fread(buffer, 1, iph_length - ip_index, trace_file);
		   		bzero(buffer, BUFLEN);
		   		index += iph_length - ip_index;
		   		ip_index += iph_length - ip_index;


		   		//read out the 'offset' value for trans_hl_length
		   		if(protocol != 'T' && protocol != 'U'){
		   			trans_hl_length = -1;
		   			payload_len = -1;
		   		}
		   		else{
		   			if(protocol == 'T'){
		   				//Read Source port
		   				fread(buffer, 1, PORTLEN, trace_file);
				    	memcpy(src_port, buffer, PORTLEN);
				    	memcpy(&source_port, src_port,PORTLEN);
				   		source_port = ntohs(source_port);
				   		bzero(buffer, BUFLEN);
				   		index += PORTLEN;

				   		//Read destination port
				   		fread(buffer, 1, PORTLEN, trace_file);
				    	memcpy(dest_port, buffer, PORTLEN);
				    	memcpy(&destination_port, dest_port,PORTLEN);
				   		destination_port = ntohs(destination_port);
				   		bzero(buffer, BUFLEN);
				   		index += PORTLEN;

				   		//Read sequence number
				   		fread(buffer, 1, SEQLEN, trace_file);
				    	memcpy(seq, buffer, SEQLEN);
				    	memcpy(&sequence, seq, SEQLEN);
				   		bzero(buffer, BUFLEN);
				   		index += SEQLEN;

				   		//Read ack number
				   		fread(buffer, 1, ACKLEN, trace_file);
				    	memcpy(ack, buffer, ACKLEN);
				    	memcpy(&ack_num, ack, ACKLEN);
				   		bzero(buffer, BUFLEN);
				   		index += ACKLEN;

				   		//Read offset value from tcp
			   			fread(buffer, 1, 1, trace_file);
			    		memcpy(trans_hl, buffer, 1);
			    		sprintf(str_trans_hl, "%02x", trans_hl[0]);
			    		trans_hl_length = (atoi(str_trans_hl)/10)*4;
			    		bzero(buffer, BUFLEN);
			    		index += 1;
			    	}
			    	else{
			    		trans_hl_length = UDPLEN;
			    	}
			    	payload_len = ip_length - iph_length - trans_hl_length;
		   		}
		    }
	    }

	    //read remaining packet data
	    while(index<packet_length){
	    	bzero(buffer, BUFLEN);
	    	if(BUFLEN>(packet_length-index)){
	    		fread(buffer, 1, (packet_length-index), trace_file);
	    		index += (packet_length-index);
	    	}
	    	else{
	    		fread(buffer, 1, BUFLEN, trace_file);
	    		index += BUFLEN;
	    	}
	    }
	    sprintf(processed_packet, "%lf,%d,%d,%d,%d,%c,%d,%d,%s,%s,%d,%d,%d,%d,%d,", real_time, ip, packet_length, ip_length, iph_length, protocol, trans_hl_length, payload_len,
	    	source_ip, destination_ip, source_port, destination_port, time_to_live, sequence, ack_num);
    }
    else{
    	return NULL;
    }

    return processed_packet;
    
}

int tcpPrint(char* filename){
	FILE* file = fopen(filename, "r");
    if(file == NULL){
    	printf("File not there");
    	fflush(stdout);
        return -1;
    }
    char* next = malloc(MINI_BUFLEN*2);
    char time[MINI_BUFLEN];
    char source_ip[MINI_BUFLEN];
    char dest_ip[MINI_BUFLEN];
    char source_port[MINI_BUFLEN];
    char dest_port[MINI_BUFLEN];
    char ttl[MINI_BUFLEN];
    char seq[MINI_BUFLEN];
    char ack[MINI_BUFLEN];

    bool tcp;

    while((next = processPacket(file)) != NULL){
    	tcp = false;
    	int index = 0;
    	int i = 0;
    	//printf("PP: %s\n", next);
		while(next[index] != ','){
			time[i] = next[index];
			i++;
			index++;
		}
		time[i] = '\0';

		
		while(next[index] != 0){
			if(next[index] == 'T')
				tcp = true;
			index++;
		}

		index=0;
		if(tcp){
			i = 0;
			for(; i<(SKIP_TO_TCP); i++){
				while(next[index] != ','){
					index++;
				}
				index++;
			}

    		i = 0;
			while(next[index] != ','){
			source_ip[i] = next[index];
			i++;
			index++;
			}
			source_ip[i] = '\0';

			index++;
    		i = 0;
			while(next[index] != ','){
			dest_ip[i] = next[index];
			i++;
			index++;
			}
			dest_ip[i] = '\0';

			index++;
    		i = 0;
			while(next[index] != ','){
			source_port[i] = next[index];
			i++;
			index++;
			}
			source_port[i] = '\0';

			index++;
    		i = 0;
			while(next[index] != ','){
			dest_port[i] = next[index];
			i++;
			index++;
			}
			dest_port[i] = '\0';

			index++;
    		i = 0;
			while(next[index] != ','){
			ttl[i] = next[index];
			i++;
			index++;
			}
			ttl[i] = '\0';

			index++;
    		i = 0;
			while(next[index] != ','){
			seq[i] = next[index];
			i++;
			index++;
			}
			seq[i] = '\0';

			index++;
    		i = 0;
			while(next[index] != ','){
			ack[i] = next[index];
			i++;
			index++;
			}
			ack[i] = '\0';

			printf("%s %s %s %s %s %s %s %s\n", time, source_ip, source_port, dest_ip, dest_port, ttl, seq, ack);




		}
	}
	return 0;

}

int length(char* filename){
    FILE* file = fopen(filename, "r");
    if(file == NULL){
    	printf("File not there");
    	fflush(stdout);
        return -1;
    }

	char* next = malloc(MINI_BUFLEN*2);
	char time[MINI_BUFLEN];
	char caplen[MINI_BUFLEN];
	char iplen[MINI_BUFLEN];
	char iphlen[MINI_BUFLEN];
	char trans_hl[MINI_BUFLEN];
	char payload_len[MINI_BUFLEN];
	char protocol;
	bool ip = false;; 

    while((next = processPacket(file)) != NULL){
    	int index = 0;
    	int i = 0;
		while(next[index] != ','){
			time[i] = next[index];
			i++;
			index++;
		}
		time[i] = '\0';

		index++;
		ip = (next[index] == '1');

		index += 2;
		i = 0;
		while(next[index] != ','){
			caplen[i] = next[index];
			i++;
			index++;
		}
		caplen[i] = '\0';

		index++;
		i = 0;
		if(next[index] == '-'){
			iplen[i] = '-';
			i++;
			index += 2;
		}
		else{
			while(next[index] != ','){
				iplen[i] = next[index];
				i++;
				index++;
			}
		}
		iplen[i] = '\0';

		index++;
		i = 0;
		if(next[index] == '-'){
			iphlen[i] = '-';
			i++;
			index += 2;
		}
		else{
			while(next[index] != ','){
				//printf("ind: %d, i: %d\n", index, i);
				iphlen[i] = next[index];
				i++;
				index++;
			}
		}
		iphlen[i] = '\0';

		index++;
		if(next[index] == '-'){
			protocol = '-';
			index++;
		}
		else{
			protocol = next[index];
			index++;
		}

		index++;
		i = 0;
		if(next[index] == '-'){
			trans_hl[i] = '?';
			i++;
			index += 2;
		}
		else{
			if(next[index] == '0'){
				trans_hl[i] = '-';
				i++;
				index++;
			}
			else{
				while(next[index] != ','){
					trans_hl[i] = next[index];
					i++;
					index++;
				}
			}
		}
		trans_hl[i] = '\0';

		index++;
		i = 0;
		if(next[index] == '-'){
			payload_len[i] = '?';
			i++;
			index += 2;
		}
		else{
			if(next[index] == '0'){
				payload_len[i] = '-';
				i++;
				index++;
			}
			else{
				while(next[index] != ','){
					payload_len[i] = next[index];
					i++;
					index++;
				}
			}
		}
		payload_len[i] = '\0';


		if(ip)
			printf("%s %s %s %s %c %s %s\n", time, caplen, iplen, iphlen, protocol, trans_hl, payload_len);
    }
    //if(fclose(file)<0)
       // errexit("Error closing file", NULL);
    return 0;
}

int summary(char* filename){
    FILE* file = fopen(filename, "r");
    if(file == NULL){
        return -1;
    }
    
    int packet_num = 0;
    char* first_time = malloc(MINI_BUFLEN);
  	char* last_time = malloc(MINI_BUFLEN);
    char* next = malloc(MINI_BUFLEN);
    int ip_packets = 0;
    while((next = processPacket(file)) != NULL){
    	int i = 0;
    	if(packet_num==0){
    		while(next[i] != ','){
    			first_time[i] = next[i];
    			i++;
    		}
    		first_time[i] = '\0';

    	}
    	while(next[i] != ','){
    			last_time[i] = next[i];
    			i++;
    		}
    		last_time[i] = '\0';
    		if(next[i+1] == '1')
    			ip_packets++;
    	packet_num++;
    }
    printf("TIME SPAN: %s - %s\nTOTAL PACKETS: %d\nIP PACKETS: %d\n", first_time, last_time, packet_num, ip_packets);
    fflush(stdout);
    //if(fclose(file)<0)
       // errexit("Error closing file", NULL);

    return 0;
}



//Here is the main method, it processes the command and runs the tool
int main(int argc, char *argv[]){
	//booleans to record which flags are present
    bool trace_present = false;        //-t is present, and is followed by a trace
    bool summary_mode = false;			//-s is present, meaning summary mode is activated
	bool length_analysis = false;		//-l is present, meaning length analysis is activated
	bool packet_printing = false;		//-p is present, which means packet printing is activated
	bool traffic_matrix = false; 		//-m is present, meaning traffic matrix mode is activated
	int valid_mode = 0;			// Exaclty one mode has been selected

	char* trace_file;

	int i=1;
	for(; argv[i] != NULL; i++){
		if(argv[i][0] == '-'){
			switch(argv[i][1]){
                case 't':
					i++;
					if(argv[i] != NULL && argv[i][0] != '-')
						trace_file = argv[i];
					else
						errexit("ERROR: Enter a trace file following the -t flag", NULL);
					trace_present = true;
					break;
				case 's':
					summary_mode = true;
					valid_mode++;
					break;
				case 'l':
					length_analysis = true;
					valid_mode++;
					break;
				case 'p':
					packet_printing = true;
					valid_mode++;
					break;
				case 'm':
					packet_printing = true;
					valid_mode++;
					break;
				default:
					errexit("ERROR: Invalid flag. Valid flags are -s, -l, -p, and -m", NULL);
					break;
			}
            
		}
        else{
            errexit("ERROR: Either no flags were entered or an invalid argument was passed", NULL);
		}
	}
	printf("%d\n%d\n%d\n%d\n%d\n%d\n", trace_present, summary_mode, length_analysis, packet_printing, traffic_matrix, valid_mode);
	fflush(stdout);
	if(!trace_present){
		printf("ERROR: The -t flag and a valid trace file must be included to use this tool\n");
		fflush(stdout);
	}
	if(valid_mode<1){
		printf("ERROR: Please use the -s, -l, -p, or -m flag to specify what mode you would like the program to run in\n");
		fflush(stdout);
	}
	if(valid_mode>1){
		printf("ERROR: Only one mode can be selected at a time.\n");
		fflush(stdout);
	}
	if(trace_present && valid_mode == 1){
		if(summary_mode){
			if(summary(trace_file)<0)
				errexit("ERROR: Summary mode failed. Could not find file speicified.", NULL);
		}
		if(length_analysis){
			if(length(trace_file)<0)
				errexit("ERROR: Summary mode failed. Could not find file speicified.", NULL);
		}
		if(packet_printing){
			if(tcpPrint(trace_file)<0)
				errexit("ERROR: Summary mode failed. Could not find file speicified.", NULL);
		}
	}	
	return 0;
}