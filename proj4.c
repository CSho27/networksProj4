//Chris Shorter
//cws68
//proj4.c
//11/10/18
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <math.h>

#define ERROR 1
#define BUFLEN 2048
#define MINI_BUFLEN 32
#define MILLIS_CONV 1000000

#define TIMELEN 4
#define CAPLEN 2

#define MIN_ETHERNET 14
#define TYPELEN 2
#define ETH_BEGIN 12


#define MIN_IP_LEN 34
#define MIN_IP 20
#define MIN_TCP 20
#define MIN_UDP 8
#define MAX_TCPIP 60

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
#define TRANS_HL_LEN 1
#define SEQLEN 4
#define ACKLEN 4
#define WINDOWLEN 2
#define TCP_PORT 2
#define UDPLEN 2
#define UDP_BEGIN 4
#define DEC_SHIFT 10
#define OFFSET_MULT 4

#define SKIP_TO_TCP 8
#define SKIP_TO_THL 6

#define ASCII_NUM 48
#define HEX_VAL 16
#define A_VAL 10
#define B_VAL 11
#define C_VAL 12
#define D_VAL 13
#define E_VAL 14
#define F_VAL 15




//If there's any sort of error the program exits immediately.
int errexit (char *format, char *arg){
    fprintf (stdout,format,arg);
    fprintf (stdout,"\n");
    exit (ERROR);
}

//This was a utility for testing values, so that I could see the actual bytes I was reading in
int printHex(unsigned char hex[], int n){
	int i = 0;
	for(; i< n; i++){
		printf("%02x", hex[i]);
	}
	printf("\n");

	return i;
}

//This converts bytes to a decimal long. I guess it's technically binary to int, but I find it easier to think about bytes in hex
long hexToInt(unsigned char* hex, int n, bool byte_flip){
	char hex_str[MINI_BUFLEN];
	long integer = 0;
	long x = 1;
	int i, j;
	bool done = false;

	if(byte_flip)
		i = 0;
	else
		i = n-1;

	while(!done){
		if(byte_flip)
			j = 0;
		else
			j = 1;

		bzero(hex_str, MINI_BUFLEN);
		sprintf(hex_str, "%02x", hex[i]);

		if(hex_str[j] >= '0' && hex_str[j] <= '9'){
			integer += x*(((int) hex_str[j])-ASCII_NUM);
		}
		else{
			switch(hex_str[j]){
				case 'a':
					integer += x*A_VAL;
					break;
				case 'b':
					integer += x*B_VAL;
					break;
				case 'c':
					integer += x*C_VAL;
					break;
				case 'd':
					integer += x*D_VAL;
					break;
				case 'e':
					integer += x*E_VAL;
					break;
				case 'f':
					integer += x*F_VAL;
					break;
				default:
					break;
				}
		}
		x = x*HEX_VAL;

		if(byte_flip)
			j++;
		else
			j--;

		if(hex_str[j] >= '0' && hex_str[j] <= '9'){
			integer += x*(((int) hex_str[j])-ASCII_NUM);
		}
		else{
			switch(hex_str[j]){
				case 'a':
					integer += x*A_VAL;
					break;
				case 'b':
					integer += x*B_VAL;
					break;
				case 'c':
					integer += x*C_VAL;
					break;
				case 'd':
					integer += x*D_VAL;
					break;
				case 'e':
					integer += x*E_VAL;
					break;
				case 'f':
					integer += x*F_VAL;
					break;
				default:
					break;
				}
		}
		x = x*HEX_VAL;

		if(byte_flip){
			i++;
			done = (i >= n);
		}
		else{
			i--;
			done = (i < 0);
		}
	}
	return integer;
}

int getOffset(unsigned char* hex){
	char hex_str[MINI_BUFLEN];
	long integer = 0;

	bzero(hex_str, MINI_BUFLEN);
	sprintf(hex_str, "%02x", hex[0]);

	if(hex_str[0] >= '0' && hex_str[0] <= '9'){
		integer = (((int) hex_str[0])-ASCII_NUM);
	}
	else{
		switch(hex_str[0]){
			case 'a':
				integer = A_VAL;
				break;
			case 'b':
				integer = B_VAL;
				break;
			case 'c':
				integer = C_VAL;
				break;
			case 'd':
				integer = D_VAL;
				break;
			case 'e':
				integer = E_VAL;
				break;
			case 'f':
				integer = F_VAL;
				break;
			default:
				break;
			}
	}
	return integer*OFFSET_MULT;
}

//This compares two sets of bytes and returns true if they are equal. Again, it's definitely actually comparing binary but whatever. 
bool compareHex(unsigned char hex1[], unsigned char hex2[], int n){
	bool same = true;
	int i = 0;
    for(; i< n; i++){
    	if(hex1[i] != hex2[i])
    		same = false;
    }
    return same;
}

//This method takes a packet and reads out all of the values the program should know in a big, long comma deliniated string. This is a gross and convoluted way of doing this, but it works.
//I've commented it thoroughly to try to clear things up. Esentially, it just goes through the whole packet piece by piece and picks out values, then writes those values to the final string.
int processPacket(FILE* trace_file, char* processed_packet, int buflen){
	bzero(processed_packet, buflen);

	//A space for each group of bytes to be held in. I realize now that this was probably an extraneous step, but it does work
	unsigned char buffer[BUFLEN];
	unsigned char time_stamp[TIMELEN];
	unsigned char caplen[CAPLEN];
	unsigned char iplen[IPLEN];
	unsigned char iphlen[IPHLEN];
	unsigned char type[TYPELEN];
	unsigned char proto[PROTOLEN];
	unsigned char trans_hl[TRANS_HL_LEN]; 
	unsigned char src_ip[IP_ADDR_LEN];
	unsigned char dest_ip[IP_ADDR_LEN];
	unsigned char src_port[PORTLEN];
	unsigned char dest_port[PORTLEN];
	unsigned char ttl[TTL_LEN];
	unsigned char seq[SEQLEN];
	unsigned char ack[ACKLEN];
	unsigned char window[WINDOWLEN];

	bool ip = false; // is it an IP packet

	//These are constants for me to use check if the bytes speicifying each protocol match up with IP, TCP, UDP
	unsigned char IP[] = {0x08, 0x00};
	unsigned char TCP[] = {0x06};
	unsigned char UDP[] = {0x11};

	//All the integer values that the unsigned chars will eventually be used to set
	int packet_length;
	int ip_length = -1;
	int iph_length = -1;
	int trans_hl_length = 0;
	int udp_len;
	unsigned int addr_byte[IP_ADDR_LEN];
	int source_port = 0;
	int destination_port = 0;
	int time_to_live = 0;
	unsigned long sequence = 0;
	unsigned long ack_num = 0;
	int window_size = 0;

	int time;
	int millis;
	int payload_len = -2;
	double real_time = 0;

	//These I build strings before printing them, because they have tricky format and this helps me get them right
	char str_iphl[MINI_BUFLEN];
	char source_ip[MINI_BUFLEN];
	char destination_ip[MINI_BUFLEN];

	//TCP, UDP, or ?
	char protocol = '-';

	bzero(buffer, BUFLEN);

	//
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
	   	real_time = time + ((double) millis)/MILLIS_CONV;
	    
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
		    if(ip && packet_length >= MIN_IP_LEN){
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
		   		time_to_live = hexToInt(ttl, 1, true);
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
			   		addr_byte[i] = hexToInt(src_ip, 1, false);
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
			   		addr_byte[i] = hexToInt(dest_ip, 1, false);
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


		   		//If it's a known protocol handle its values, otherwise return -1 for unknown things
		   		if(protocol != 'T' && protocol != 'U'){
		   			trans_hl_length = -1;
		   			payload_len = -1;
		   		}
		   		else{
		   			if(protocol == 'T' && (packet_length-index)>=MIN_TCP && (packet_length-index)<=MAX_TCPIP && iph_length>=MIN_IP && iph_length<=MAX_TCPIP){
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
				    	sequence = hexToInt(seq, SEQLEN, false);
				   		bzero(buffer, BUFLEN);
				   		index += SEQLEN;

				   		//Read ack number
				   		fread(buffer, 1, ACKLEN, trace_file);
				    	memcpy(ack, buffer, ACKLEN);
				    	ack_num = hexToInt(ack, ACKLEN, false);
				   		bzero(buffer, BUFLEN);
				   		index += ACKLEN;

				   		//Read offset value from tcp
			   			fread(buffer, 1, 1, trace_file);
			    		memcpy(trans_hl, buffer, 1);
			    		trans_hl_length = getOffset(trans_hl);
			    		bzero(buffer, BUFLEN);
			    		index += 1;

			    		//ignore checksum value of IP header
				   		fread(buffer, 1, 1, trace_file);
				   		bzero(buffer, BUFLEN);
				   		index ++;

				   		//Read destination port
				   		fread(buffer, 1, WINDOWLEN, trace_file);
				    	memcpy(window, buffer, WINDOWLEN);
				    	memcpy(&window_size, window,WINDOWLEN);
				   		window_size = ntohs(window_size);
				   		bzero(buffer, BUFLEN);
				   		index += WINDOWLEN;

				   		if(trans_hl_length>=MIN_TCP && trans_hl_length<=MAX_TCPIP)
				   			payload_len = ip_length - iph_length - trans_hl_length;
				   		else
				   			trans_hl_length = -2;
			    	}
			    	else{
			    		if(protocol == 'U' && packet_length-index >= MIN_UDP){
			    			//ignore beginning of UDP header
					   		fread(buffer, 1, UDP_BEGIN, trace_file);
					   		bzero(buffer, BUFLEN);
					   		index += UDP_BEGIN;

			    			//Read length value from UDP
				   			fread(buffer, 1, UDPLEN, trace_file);
				    		memcpy(trans_hl, buffer, UDPLEN);
				    		memcpy(&udp_len, trans_hl, UDPLEN);
				    		udp_len = ntohs(udp_len);
				    		bzero(buffer, BUFLEN);
				    		index += UDPLEN;

				    		if(udp_len>=MIN_UDP){
			    				trans_hl_length = MIN_UDP;
			    				payload_len = ip_length - iph_length - trans_hl_length;
				    		}
			    			else{
			    				trans_hl_length = -2;
			    				payload_len = -2;
			    			}
			    		}
			    		else{
			    			if(protocol == '?')
			    				payload_len = -1;
			    		}
			    	}
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
	    //Building the big nasty string I talked about at the beginning. I get that it is convoluted, but it works.
	    sprintf(processed_packet, "%lf,%d,%d,%d,%d,%c,%d,%d,%s,%s,%d,%d,%d,%d,%lu,%lu,", real_time, ip, packet_length, ip_length, iph_length, protocol, trans_hl_length, payload_len,
	    	source_ip, destination_ip, source_port, destination_port, time_to_live, window_size, sequence, ack_num);
    }
    else{
    	return 0;
    }
    return packet_length;
}

//Traffic matrix prints how much data has been sent from each set of sources and destinations. It skips through my big string to find the values it specifically needs and keeps 2 arrays to tell
//which source, dest pairs have been counted and how much traffic is being sent between them.
int trafficMatrix(char* filename){
	FILE* file = fopen(filename, "r");
    if(file == NULL){
        return -1;
    }

    char* next = malloc(BUFLEN);

    char source_ip[MINI_BUFLEN];
    char dest_ip[MINI_BUFLEN];
    char payload_len[MINI_BUFLEN];
    char pairs[BUFLEN][MINI_BUFLEN];
    int payloads[BUFLEN];
    char trans_hl[MINI_BUFLEN];

    int total_pairs;
    while(processPacket(file, next, BUFLEN) > 0){
    	bzero(trans_hl, MINI_BUFLEN);
    	bzero(payload_len, MINI_BUFLEN);
    	bool tcp = false;
    	int index = 0;
    	int i = 0;
		index=0;

		while(next[index] != 0){
			if(next[index] == 'T')
				tcp = true;
			index++;
		}

		index = 0;
		if(tcp){
			i = 0;
			for(; i<(SKIP_TO_THL); i++){
				while(next[index] != ','){
					index++;
				}
				index++;
			}

			i = 0;
			if(next[index] == '-'){
				trans_hl[i] = '0';
				i++;
				index += 2;
			}
			else{
				while(next[index] != ','){
					trans_hl[i] = next[index];
					i++;
					index++;
				}
			}
			trans_hl[i] = '\0';

			if(atoi(trans_hl)>=MIN_TCP){
				index++;
				i = 0;
				while(next[index] != ','){
						payload_len[i] = next[index];
						i++;
						index++;
				}
				payload_len[i] = '\0';

				index++;
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

				char current_pair[MINI_BUFLEN];
				sprintf(current_pair, "%s %s", source_ip, dest_ip);
				bool match = false;

				int pairs_index = 0;
				for(; pairs_index<total_pairs; pairs_index++){
					if(strcmp(current_pair, pairs[pairs_index]) == 0){
						//printf("%s = %d + %d (%d)\n", pairs[pairs_index], payloads[pairs_index], atoi(payload_len), atoi(trans_hl));
						payloads[pairs_index] += atoi(payload_len);
						match = true;
					}
				}
				if(!match){
					sprintf(pairs[pairs_index], "%s %s", source_ip, dest_ip);
					//printf("%s = %d (%d)\n", pairs[pairs_index], atoi(payload_len), atoi(trans_hl));
					payloads[pairs_index] = atoi(payload_len);
					total_pairs++;
				}
			}
		}
	}
	int j = 0;
	for(; j<total_pairs; j++){
		printf("%s %d\n", pairs[j], payloads[j]);
	}
	free(next);
	return 0;
}

//tcpPrint prints a bunch of TCP info about each packet. It picks through my big nasty string to find all the values it needs and then prints them.
int tcpPrint(char* filename){
	FILE* file = fopen(filename, "r");
    if(file == NULL){
        return -1;
    }
    char* next = malloc(BUFLEN);
    char time[MINI_BUFLEN];
    char source_ip[MINI_BUFLEN];
    char dest_ip[MINI_BUFLEN];
    char source_port[MINI_BUFLEN];
    char dest_port[MINI_BUFLEN];
    char ttl[MINI_BUFLEN];
    char window[MINI_BUFLEN];
    char seq[MINI_BUFLEN];
    char ack[MINI_BUFLEN];

    bool tcp;

    while(processPacket(file, next,BUFLEN) > 0){
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
			window[i] = next[index];
			i++;
			index++;
			}
			window[i] = '\0';

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


			printf("%s %s %s %s %s %s %s %s %s\n", time, source_ip, source_port, dest_ip, dest_port, ttl, window, seq, ack);
		}
	}
	free(next);
	return 0;
}

//length picks through my big nasty string to find a bunch of length data and then prints it.
int length(char* filename){
    FILE* file = fopen(filename, "r");
    if(file == NULL){
        return -1;
    }

	char* next = malloc(BUFLEN);
	char time[MINI_BUFLEN];
	char caplen[MINI_BUFLEN];
	char iplen[MINI_BUFLEN];
	char iphlen[MINI_BUFLEN];
	char trans_hl[MINI_BUFLEN];
	char payload_len[MINI_BUFLEN];
	char protocol;

    while(processPacket(file, next, BUFLEN) > 0){
    	int index = 0;
    	int i = 0;
		while(next[index] != ','){
			time[i] = next[index];
			i++;
			index++;
		}
		time[i] = '\0';

		index++;

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
			if(next[index+1] == '1')
				payload_len[i] = '?';
			else
				payload_len[i] = '-';
			i++;
			index += 2;
		}
		else{
			while(next[index] != ','){
				payload_len[i] = next[index];
				i++;
				index++;
			}
		}
		payload_len[i] = '\0';

		printf("%s %s %s %s %c %s %s\n", time, caplen, iplen, iphlen, protocol, trans_hl, payload_len);
    }
    free(next);
    return 0;
}

//Summary prints out basic data about the time range, number of packets, and number of IP packets. It picks through the first few values of my big nasty string to find these values.
int summary(char* filename){
    FILE* file = fopen(filename, "r");
    if(file == NULL){
        return -1;
    }
    
    long packet_num = 0;
    char* first_time = malloc(MINI_BUFLEN);
  	char* last_time = malloc(MINI_BUFLEN);
    char* next = malloc(BUFLEN);
    long ip_packets = 0;
    while(processPacket(file, next, BUFLEN) > 0){
    	int i = 0;
    	if(packet_num==0){
    		while(next[i] != ','){
    			first_time[i] = next[i];
    			i++;
    		}
    		first_time[i] = '\0';
    		memcpy(last_time, first_time, MINI_BUFLEN);

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
    printf("TIME SPAN: %s - %s\nTOTAL PACKETS: %ld\nIP PACKETS: %ld\n", first_time, last_time, packet_num, ip_packets);
    fflush(stdout);
    //if(fclose(file)<0)
       // errexit("Error closing file", NULL);
    free(first_time);
    free(last_time);
    free(next);
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
					traffic_matrix = true;
					valid_mode++;
					break;
				default:
					errexit("ERROR: Invalid flag. Valid flags are -s, -l, -p, and -m", NULL);
					break;
			}
            
		}
        else{
            errexit("ERROR: Either no flags were entered or an invalid argument was passed.\nMake sure the -t flag is always included.", NULL);
		}
	}
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
		if(traffic_matrix){
			if(trafficMatrix(trace_file)<0)
				errexit("ERROR: Summary mode failed. Could not find file speicified.", NULL);
		}
	}	
	return 0;
}