//Chris Shorter
//cws68
//proj4.c
//11/10/18
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define ERROR 1
#define BUFLEN 1024
#define TIMELEN 4

//If there's any sort of error the program exits immediately.
int errexit (char *format, char *arg){
    fprintf (stdout,format,arg);
    fprintf (stdout,"\n");
    exit (ERROR);
}

unsigned char* summary(char* filename){
    FILE* file = fopen(filename, "r");
    if(file == NULL){
    	printf("File not there");
    	fflush(stdout);
        return NULL;
    }

    unsigned char buffer[BUFLEN];
    unsigned char time_stamp[TIMELEN];
    unsigned long first_time;
    bzero(buffer, BUFLEN);
    bool done = false;
    while(!done){
        fread(buffer, 1, TIMELEN, file);
   		bzero(buffer, BUFLEN);
    	fread(buffer, 1, TIMELEN, file);
    	int i=0;
    	for(; i<TIMELEN; i++){
    		printf("%02x", buffer[i]);
    	}
    	printf("\n");

    	bcopy(time_stamp, buffer, TIMELEN);

    	for(; i<TIMELEN; i++){
    		printf("%02x", time_stamp[i]);
    	}
    	printf("\n");

	   	first_time = (unsigned long) time_stamp;
	   	first_time = ntohl(first_time);
	    done = true;
	    //printf("%ld\n", first_time);
	    fflush(stdout);
	    
    }
    if(fclose(file)<0)
        errexit("Error closing file", NULL);
    return NULL;
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
			summary(trace_file);
		}
	}	
}