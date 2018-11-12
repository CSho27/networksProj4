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
#define BUFLEN 1024
#define TIMELEN 4
#define CAPLEN 2
#define TYPELEN 2
#define ETH_BEGIN 12
#define MINI_BUFLEN 32

//If there's any sort of error the program exits immediately.
int errexit (char *format, char *arg){
    fprintf (stdout,format,arg);
    fprintf (stdout,"\n");
    exit (ERROR);
}

char* processPacket(FILE* trace_file){
	char* processed_packet = malloc(MINI_BUFLEN);
	bzero(processed_packet, MINI_BUFLEN);

	char buffer[BUFLEN];
	char time_stamp[TIMELEN];
	char caplen[CAPLEN];
	unsigned char type[TYPELEN];
	bool ip = true;
	const int IP[] = {0x08, 0x00};
	int packet_length;
	int time;
	int millis;
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
	    
	    //ignore beginning of ethernet header
	    int index=0;
	    fread(buffer, 1, ETH_BEGIN, trace_file);
	    index = ETH_BEGIN;
	    bzero(buffer, BUFLEN);

	    fread(buffer, 1, TYPELEN, trace_file);
	    memcpy(type, buffer, TYPELEN);
	    index += TYPELEN;

	    
	    int i = 0;
	    for(; i< TYPELEN; i++){
	    	if(type[i] != IP[i])
	    		ip = false;
	    }
	    

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
	    sprintf(processed_packet, "%d.%d,%d,%d,", time, millis, ip, packet_length);
    }
    else{
    	return NULL;
    }

    return processed_packet;
    
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
	bool ip = false;; 

    while((next = processPacket(file)) != NULL){

    	int index = 0;
    	int i;
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

		if(ip)
			printf("%s %s\n", time, caplen);
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
	}	
	return 0;
}