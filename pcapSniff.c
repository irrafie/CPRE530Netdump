#define ADAPTERCOUNT 10
#define RETSIGTYPE void

#include <sys/types.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE(*setsignal(int, RETSIGTYPE (*)(int)))
(int);
#endif

static pcap_t *pd1;
static pcap_t *pd2;
static pcap_t *pd3;
static pcap_t *pd4;
static pcap_t *pd5;
static pcap_t *pd6;
static pcap_t *pd7;
static pcap_t *pd8;
static pcap_t *pd9;
static pcap_t *pd10;

static volatile int run = 1;

int snaplen = 1500;
int verbose = -1;

int packettype;
int num_ip_packets = 0;
int num_arp_packets = 0;
int num_broadcast_packets = 0;
int num_icmp_packets = 0;
int num_tcp_packets = 0;
int num_smtp_packets = 0;
int num_pop_packets = 0;
int num_imap_packets = 0;
int num_http_packets = 0;
int num_dns_packets = 0;
int dataflag = 0;
int httpflag = 0;
uint16_t httpackflag[4];
int httpackflagged = 0;
extern int optind;
extern int opterr;
extern char *optarg;
int pflag = 0, aflag = 0;
int authflag = 0;
uint16_t acksave[4] = {};
uint16_t listacksave[4] = {};
int listflag = 0;

struct pcap_pkthdr header;
int sniff();
void exitHandler(){
	run = 0;
}

int main(int argc, char **argv)
{
    printf("\nSniffing Commence.\n");
    sniff(argv[1]);
}

//function to sniff packets on interfaces
int sniff(int verbose)
{
    int count = 0;
    struct bpf_program fcode;
    void (*oldhandler)(int);
    u_char *pcap_userdata;
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int devicesId[ADAPTERCOUNT];
    int i; //value to use for loops
    int snaplen = 1500;
    bpf_u_int32 localnet, netmask;
    char *cmdbuf;

    if (pcap_findalldevs(&alldevs, ebuf) < 0)
    {
        perror("Device scan failed.");
    }

    printf("Input up to %d devices to scan in the following format. <number\\n>To exit, enter any char.\n", ADAPTERCOUNT);
    cmdbuf = "";
    //scroll through adapters
    for (d = alldevs, i = 0; d; d = d->next)
    {
        printf("%d : %s\n", i++, d->name);
    }
    int getInput = 1;

    i = 0;
    int a = 0;
    int temp;
    int deviceEnteredCount = 0;
    while (getInput == 1)
    {
        if (scanf("%d", &temp) != 1)
        {
            break;
        }
        devicesId[deviceEnteredCount] = temp;
        deviceEnteredCount++;
    }
    for (a = 0; a < deviceEnteredCount; a++)
    {
        int o = 0;
        d = alldevs;
        while (o != devicesId[a])
        {
            d = d->next;
            o++;
        }
        
        fflush(stdout);
        if ((pd[a] = pcap_open_live(d->name, snaplen, 1, 1000, ebuf) == NULL))
        {
            perror(ebuf);
        }
        else if (verbose != -1)
        {
            printf("%s has been opened\n", d->name);
        }
        i = pcap_snapshot(pd[a]);

        if (pd[a] == NULL)
		  error("%s", ebuf);

        if (pcap_lookupnet(d->name, &localnet, &netmask, ebuf) < 0)
        {
            localnet = 0;
            netmask = 0;
        }

	    setuid(getuid());

        if (pcap_compile(pd[a], &fcode, cmdbuf, 1, netmask) < 0)
        {
            perror(ebuf);
        }
        else if (verbose != -1)
        {
            printf("Listening to %s\n", d->name);
        }

        // if (pcap_setfilter(pd1, &fcode) < 0)
        //     error("%s", pcap_geterr(pd1));


    }
    pcap_userdata = 0;
    const u_char *packet[ADAPTERCOUNT];
    signal(SIGINT, exitHandler);

	while(run){
        for(i = 0; i < deviceEnteredCount; i++){
            packet[i] = pcap_next(pd[i], &header);
		    raw_print(pcap_userdata, &header, packet[i]);
        }
		
	}
}


void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
        u_int length = h->len;
        u_int caplen = h->caplen;
	uint16_t e_type;
	uint16_t hardw_type;
	uint16_t protocol_type;
	uint16_t tot_len;
	
	printf("\nDEST Address = %02X:%02X:%02X:%02X:%02X:%02X\n", p[0],p[1],p[2],p[3],p[4],p[5]);
	printf("SRC Address = %02X:%02X:%02X:%02X:%02X:%02X\n", p[6],p[7],p[8],p[9],p[10],p[11]);
        
        if(p[0] == p[1] && p[1] == p[2] && p[2] == p[3] && p[3] == p[4] && p[4] == p[5] && p[5] == 0xFF){
        	num_broadcast_packets++;
        }
        
	e_type = ntohs((uint16_t) * &p[12]);
	printf("E_Type = %04X \n", e_type);
	printf("Payload");
	int src_port = (p[34]*256)+p[35] ;
	int dest_port = (p[36]*256)+p[37];
	
	if(e_type == 0x800){
		printf(" -> IP\n");
		num_ip_packets++;
		uint16_t version;
		uint16_t header_len;
		version = (0xF0 & p[14])/16;
		header_len = (0x0F & p[14])*4;
		printf("Version = %d\nHeader Length = %d\n", version, header_len);
		tot_len = p[16]*256 + p[17];
		printf("Total Length = %d \n", tot_len);
		printf("Identfication = %d\n", (p[18]*256)+p[19]);
		printf("Flags = 0x%x\n", (p[20]*256)+p[21]);
		printf("Time to Live = %d \n", p[22]);
		printf("Source IP: %d.%d.%d.%d\n",p[26], p[27], p[28], p[29]);
		printf("Destination IP: %d.%d.%d.%d\n",p[30], p[31], p[32], p[33]);
		
		printf("Protocol: ");
		if(p[23] == 0x6){
			printf("TCP\n");
			num_tcp_packets++;
			printf("Source Port = %d\n", src_port);
			printf("Destination Port = %d\n", dest_port);
			printf("Sequence No = %x%x%x%x\n", p[38], p[39], p[40], p[41]);
			printf("Acknowledgement No = %x%x%x%x\n", p[42], p[43], p[44], p[45]);
			printf("TCP Header Len = %d\n", p[46]*4);
			printf("(PSH,ACK) = 0x%x\n", p[47]);
			printf("Window size value = %d\n", (p[48]*256) + p[49]);
			printf("Checksum = %x%x\n", p[50], p[51]);
			printf("Urgent Pointer = %d\n", (p[52]*256) + p[53]);
			int i = 0;
			printf("Options:\n");
			printf("\tKind: 0x%02x\n", p[54]);
			printf("\tLength: 0x%02x\n", p[55]);
			printf("\tMSS Value: 0x%04x\n", (p[56]*256) + p[57]);
			printf("\tKind: 0x%02x\n", p[58]);
			printf("\tKind: 0x%02x\n", p[59]);
			printf("\tKind: 0x%02x\n", p[60]);
			printf("\tLength: 0x%02x\n", p[61]);
			/*
			Check ports first for SMTP, POP, IMAP, HTTP
			*/
			uint16_t temp[4];
				for(i = 0; i < 4; i++){
					if(p[66+i] <= 0x7a && p[66+i] >= 0x61){
						temp[i] = p[66+i] - 0x20;
					}
					else{
						temp[i] = p[66+i];
					}
				}
			if(src_port == 25 || dest_port == 25){	//if port 25
				//220, EHLO, 250, AUTH, HELO, 334
				
				if(	(temp[0] == 0x32 && temp[1] == 0x32 && temp[2] == 0x30) || 				//220
					(temp[0] == 0x45 && temp[1] == 0x48 && temp[2]  == 0x4c && temp[3]  == 0x4f) ||		//EHLO
					(temp[0] == 0x32 && temp[1] == 0x35 && temp[2]  == 0x30) || 				//250
					(temp[0] == 0x48 && temp[1] == 0x45 && temp[2]  == 0x4c && temp[3] == 0x4f) ||		//HELO
					(temp[0] == 0x41 && temp[1] == 0x55 && temp[2]  == 0x54 && temp[3] == 0x48) ||
					(authflag == 1) ||
					(temp[0] == 0x4d && temp[1] == 0x41 && temp[2]  == 0x49 && temp[3] == 0x4c) ||		//MAIL
					(temp[0] == 0x52 && temp[1] == 0x43 && temp[2]  == 0x50 && temp[3] == 0x54) ||		//RCPT
					(temp[0] == 0x44 && temp[1] == 0x41 && temp[2]  == 0x54 && temp[3] == 0x41) ||		//DATA
					(temp[0] == 0x33 && temp[1] == 0x35 && temp[2]  == 0x34) ||				//354
					(authflag == 1)
					){
					if((temp[0] == 0x32 && temp[1] == 0x35 && temp[2] == 0x30) && authflag == 1){
						authflag = 0;
						dataflag = 0;
					}
					if(authflag == 1 && acksave[0] != p[42] && acksave[1] != p[43] && acksave[2] != p[44] && acksave[3] != p[45] && dataflag == 1){
						goto breaktag;
					}
					if(authflag == 1 && dataflag == 0){
						for(i = 0; i < 4;i++){
							acksave[i] = p[42+i];
						}
						dataflag = 1;
					}
					
					printf("SMTP Data: ");
					for(i = 66; i < tot_len+14; i++){
						printf("%c",p[i]);
					}
					printf("\n");
					num_smtp_packets++;
					}
					
					if((temp[0] == 0x33 && temp[1]== 0x35 && temp[2]  == 0x34)){				//354
						authflag = 1;
					}
			}
			else if(src_port == 110 || dest_port == 110){
				//compare to char* possible but a bit too late to recode :/
								
				if((temp[0] == 0x2b && temp[1] == 0x4f && temp[2] == 0x4b) || 				//+OK
				(temp[0] == 0x55 && temp[1] == 0x53 && temp[2] == 0x45 && temp[3] == 0x52) || 			//USER
				(temp[0] == 0x50 && temp[1] == 0x41 && temp[2] == 0x53 && temp[3] == 0x53) || 			//PASS
				(temp[0] == 0x4c && temp[1] == 0x49 && temp[2] == 0x53 && temp[3] == 0x54) || 			//LIST
				(temp[0] == 0x52 && temp[1] == 0x45 && temp[2] == 0x54 && temp[3] == 0x52) || 			//RETR
				(temp[0] == 0x51 && temp[1] == 0x55 && temp[2] == 0x49 && temp[3] == 0x54) || 			//QUIT
				(temp[0] == 0x2d && temp[1] == 0x45 && temp[2] == 0x52 && temp[3] == 0x52) || 			//-ERR
				(listflag == 1 && listacksave[0] == p[42] && listacksave[1] == p[43] && listacksave[2] == p[44] && listacksave[3] == p[45]))
				{			//+OK,quit, user, pass
						if(listflag == 1){
							listflag = 0;
						}
						if((p[70] == 0x53 && p[71] == 0x63 && p[72] == 0x61 && p[73] == 0x6e)){		//?
							listflag = 1;
							for(i = 0; i < 4;i++){
								listacksave[i] = p[42+i];
							}

						}
						printf("POP Data: ");
						for(i = 66; i < tot_len+14; i++){
							printf("%c",p[i]);
						}
						num_pop_packets++;
					}
			}
			
			else if(src_port == 80 || dest_port == 80){
				
				if(httpflag == 1 && httpackflagged == 0 && (p[47] & 0x08) == 0x08 && src_port == 80){	//caught on TCP retransmission
					for(i = 0; i < 4; i++){
						httpackflag[i] = p[42+i];
					}
					httpackflagged = 1;

					goto printhttp;
				}
				else if(httpflag == 1 && httpackflag[0] == p[42] && httpackflag[1] == p[43] && httpackflag[2] == p[44] && httpackflag[3] == p[45]){

					if(p[47] == 0x11){
						httpflag = 0;
						for(i = 0; i < 4; i++){
							httpackflag[i] = -1;
						}
						goto breaktag;
					}
					else {
						printhttp:
						printf("HTTP Data: ");
						for(i = 66; i < tot_len+14; i++){
							printf("%c",p[i]);
						}
						num_http_packets++;
					}
				}
				else if((p[66] == 0x47 && p[67] == 0x45 && p[68] == 0x54) && httpflag == 0){
					httpflag = 1;
					goto printhttp;
				}


			}
			else if(src_port == 143 || dest_port == 143){
				//TODO
				if(p[16]*256 + p[17] > 40 && p[47] == 0x18){
					printf("IMAP Data: ");
					for(i = 66; i < tot_len + 14; i++){
						printf("%c",p[i]);
					}
					printf("\n");
					num_imap_packets++;
				}
				
			}
			else if(src_port == 53 || dest_port == 53){
				num_dns_packets++;
			}
			else{
				breaktag:
				printf("Payload = ");
				for(i = 54; i < tot_len+14; i++){
					printf("%02x",p[i]);
				}
				printf("\n");
			}
			
			
		}
		else if(p[23] == 0x11){
			printf("UDP\n");
			if(src_port == 53 || dest_port == 53){
				num_dns_packets++;
				printf("Payload -> DNS\n");
			}
		}
		else if(p[23] == 0x1){
			printf("ICMP\n");
			num_icmp_packets++;
			printf("Type: %d\nCode: %d\n", p[34],p[35]);
			printf("Checksum = 0x%0x\n", (p[36]*256) + p[37]);
			printf("Identifier(BE) = %d\nSequence no(BE) = %d\n", (p[38]*256)+p[39], (p[40]*256) + p[41]);
			printf("Identifier(LE) = %d\nSequence no(LE) = %d\n", (p[39]*256)+p[38], (p[41]*256) + p[40]);
			int i = 0;
			printf("Data = ");
			for(i = 50; i < tot_len+14; i++){
				printf("%02x",p[i]);
			}
			printf("\n");
		}
		
	}
	if(e_type == 0x806){
		printf(" -> ARP\n");
		num_arp_packets++;
		hardw_type = ntohs((uint16_t) * &p[14]);
		printf("Hardware Type = ");
		if(hardw_type == 0x1){
			printf("Ethernet.\n");
		}
		protocol_type = ntohs((uint16_t) * &p[16]);
		printf("Protocol Type = ");
		if(protocol_type == 0x800){
			printf("IPv4.\n");
		}
		printf("Hardware size = %d\nProtocol size = %d\n", p[19], p[20]);
		printf("Opcode: %d", (p[20]*256) + p[21]);
		printf("Source Address = %02X:%02X:%02X:%02X:%02X:%02X\n", p[22],p[23],p[24],p[25],p[26],p[27]);
		printf("Source IP: %d.%d.%d.%d\n",p[28], p[29], p[30], p[31]);
		printf("Target Address = %02X:%02X:%02X:%02X:%02X:%02X\n", p[32],p[33],p[34],p[35],p[36],p[37]);
		printf("Target IP: %d.%d.%d.%d\n",p[38], p[39], p[40], p[41]);
	}
	//send_packet(p, length);
        //default_print(p, caplen);
        putchar('\n');
}