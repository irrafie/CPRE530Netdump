#define RETSIGTYPE void
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <resolv.h>

#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif

char cpre580f98[] = "netdump";

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

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

char *program_name;

/* Externs */
extern void bpf_dump(const struct bpf_program *, int);

extern char *copy_argv(char **);

/* Forwards */
 void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1500;;

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;
int pflag = 0, aflag = 0;
int authflag = 0;
uint16_t acksave[4] = {};
uint16_t listacksave[4] = {};
int listflag = 0;

int
main(int argc, char **argv)
{
	int cnt, op, i, done = 0;
	bpf_u_int32 localnet, netmask;
	char *cp, *cmdbuf, *device;
	struct bpf_program fcode;
	 void (*oldhandler)(int);
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];

	cnt = -1;
	device = NULL;
	
	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((i = getopt(argc, argv, "pa")) != -1)
	{
		switch (i)
		{
		case 'p':
			pflag = 1;
		break;
		case 'a':
			aflag = 1;
		break;
		case '?':
		default:
			done = 1;
		break;
		}
		if (done) break;
	}
	if (argc > (optind)) cmdbuf = copy_argv(&argv[optind]);
		else cmdbuf = "";

	if (device == NULL) {
		device = pcap_lookupdev(ebuf);
		if (device == NULL)
			error("%s", ebuf);
	}
	pd = pcap_open_live(device, snaplen,  1, 1000, ebuf);
	if (pd == NULL)
		error("%s", ebuf);
	i = pcap_snapshot(pd);
	if (snaplen < i) {
		warning("snaplen raised from %d to %d", snaplen, i);
		snaplen = i;
	}
	if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
		localnet = 0;
		netmask = 0;
		warning("%s", ebuf);
	}
	/*
	 * Let user own process after socket has been opened.
	 */
	setuid(getuid());

	if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
		error("%s", pcap_geterr(pd));
	
	(void)setsignal(SIGTERM, program_ending);
	(void)setsignal(SIGINT, program_ending);
	/* Cooperate with nohup(1) */
	if ((oldhandler = setsignal(SIGHUP, program_ending)) != SIG_DFL)
		(void)setsignal(SIGHUP, oldhandler);

	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));
	pcap_userdata = 0;
	(void)fprintf(stderr, "%s: listening on %s\n", program_name, device);
	if (pcap_loop(pd, cnt, raw_print, pcap_userdata) < 0) {
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
		    program_name, pcap_geterr(pd));
		exit(1);
	}
	pcap_close(pd);
	exit(0);
}

/* routine is executed on exit */
void program_ending(int signo)
{
	struct pcap_stat stat;

	if (pd != NULL && pcap_file(pd) == NULL) {
		(void)fflush(stdout);
		putc('\n', stderr);
		if (pcap_stats(pd, &stat) < 0)
			(void)fprintf(stderr, "pcap_stats: %s\n",
			    pcap_geterr(pd));
		else {
			(void)fprintf(stderr, "%d packets received by filter\n",
			    stat.ps_recv);
			(void)fprintf(stderr, "%d packets dropped by kernel\n",
			    stat.ps_drop);
			printf("%d IP packets.\n", num_ip_packets);
			printf("%d ARP packets.\n", num_arp_packets);
			printf("%d broadcast packets.\n", num_broadcast_packets);
			printf("%d DNS packets.\n", num_dns_packets);
			printf("%d ICMP packets. \n", num_icmp_packets);
			printf("%d TCP packets. \n", num_tcp_packets);
			printf("%d SMTP packets. \n", num_smtp_packets);
			printf("%d POP packets. \n", num_pop_packets);
			printf("%d IMAP packets. \n", num_imap_packets);
			printf("%d HTTP packets. \n", num_http_packets);
		}
	}
	exit(0);
}


void send_packet(const u_char *p, int len)
{	
	u_char *a = p;
	struct ifreq if_idx;
	struct sockaddr_ll socket_address;
	int sockfd;
	char ipaddress[] = "route -n | grep -B0 255.255.255 | awk '{print $8}'";	//CORRECT
	char trgtmac[] = "ip neigh | grep -B0 255.255.255.255 | awk '{print $5}'";
	char srcmac[] = "ip neigh | grep -B0 255.255.255.255 | awk '{print $5}'";
	snprintf(ipaddress, sizeof(ipaddress), "route -n | grep -B0 %d.%d.%d | awk '{print $8}'", a[30], a[31], a[32]);

	FILE *fp = malloc(100);
	
	fp = popen(ipaddress,"r");
	char ifName[IFNAMSIZ];
	char *out = malloc(sizeof(char));
	int i = 0;
	while(fgets(out, sizeof(out), fp) != NULL){
		//printf("%s", out);
		//ifName[0] = out;
		sprintf(ifName, "%s", out);

	}
	//sprintf(ifName, "%s", out);
	pclose(fp);
	printf("%s\n",ifName);
	strtok(ifName, "\n");		//popen sends newline instead of NULL char -.-
	snprintf(srcmac, sizeof(ipaddress), "ifconfig | grep -B6 %s | grep ether | awk '{print $2}'", ifName);
	//strcpy(ifName, "eth0");
	//printf("%s\n",ifName);
	//printf("%s\n",out);
	if((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1){
		perror("Socket creation failed,");
	}
	strcpy(ifName, ifName);
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;
	socket_address.sll_addr[0] = a[0];
	socket_address.sll_addr[1] = a[1];
	socket_address.sll_addr[2] = a[2];
	socket_address.sll_addr[3] = a[3];
	socket_address.sll_addr[4] = a[4];
	socket_address.sll_addr[5] = a[5];
	
	a[22] = a[22] - 1;	//reduce TTL by 1
	int o = 0;
	int tot_len = a[16]*256 + a[17];
	
	
	/*
	 *
	 *	VALUE CHANGES HAPPENS HERE
	 *
	 */
	
	//change MAC source to current
	
	
				
	/*
	 * Send Packet
	 */
	if(sendto(sockfd, p, len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0){
		perror("Send Failed");
	}
	else{
		printf("Send Success\n");
	}
}

/*
insert your code in this routine

*/


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
	send_packet(p, length);
        //default_print(p, caplen);
        putchar('\n');
}


