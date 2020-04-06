#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

unsigned char dnsreply [4096];
char dnspayload [256];

char header [10]= {
			0x01,0x00, 		//Flags
			0x00,0x01,		//Questions
			0x00,0x00,		//AnswerRRs
			0x00,0x00,		//AuthorityRRs
			0x00,0x01};		//AdditionalRRs ->required for TXT and DNSSEC

char terminator [1]={0x00};

char footer_txt [4] ={ 
			0x00,0x10,		//Type ->this one is for TXT
			0x00,0x01};			//Class	

char footer_dnssec [4] ={ 
			0x00,0x01,		//Type ->this one is for DNSSEC
			0x00,0x01};			//Class	

char dns_additional_records_txt [23]= { 
			0x00,		//Root
			0x00,0x29,	//OPT=41
			0x10,0x00,	//UDP payload size=4096
			0x00,		//RCODE=0x00
			0x00,		//EDNS version=0
			0x00,0x00,	//Z=0x8000 for DNSSEC)
			0x00,0x0c,	//data length=12 bytes (cookie)
			0x00,0x0a,	//cookie - pseudorandom will do
			0x00,0x08,	//cookie
			0xb7,0xcd,	//cookie
			0x78,0xba,	//cookie
			0xd4,0x4a,	//cookie
			0x77,0x59 };	//cookie

char dns_additional_records_dnssec [23]= { 
			0x00,		//Root
			0x00,0x29,	//OPT=41
			0x10,0x00,	//UDP payload size=4096
			0x00,		//RCODE=0x00
			0x00,		//EDNS version=0
			0x80,0x00,	//Z=0x8000 for DNSSEC)
			0x00,0x0c,	//data length=12 bytes (cookie)
			0x00,0x0a,	//cookie - pseudorandom will do
			0x00,0x08,	//cookie
			0xb7,0xcd,	//cookie
			0x78,0xba,	//cookie
			0xd4,0x4a,	//cookie
			0x77,0x59 };	//cookie
					
int main(int argc, char *argv[])
{
	int domainname,i,sock,dot,k=0,t=0;
	unsigned short serverPort, domainprefixlen,domainsuffixlen;
	char suffix[256];
	char *serverIP;
	char *domainprefixname, *domainsuffixname;

struct sockaddr_in ServAddr;

if (argc!=4) {
	printf ("Usage is %s <domain> <DNS server IP address> [dnssec | txt]\n ",argv[0]);
	exit (1);
		}

	srand(time(NULL));

	domainname=strlen(argv[1]);

	unsigned short int TransactionID= rand();

	domainprefixname=strtok(argv[1], ".");
	domainprefixlen=strlen(domainprefixname);

if ( strncmp(argv[3],"dnssec",strlen(argv[3]))!=0 && strncmp(argv[3],"txt",strlen(argv[3]))!=0 )  {
	printf ("You must supply either 'dnssec' or 'txt' for the DNS record type \n");
	exit (1);
	}

//Copy TransactioID
memcpy (dnspayload,&TransactionID,sizeof(TransactionID));
//Copy header
memcpy (dnspayload+sizeof(TransactionID),header,10*sizeof(char));

//Copy domain prefix len
memcpy (dnspayload+sizeof(TransactionID)+10*sizeof(char), &domainprefixlen,1);

	strcpy (suffix, argv[1]);
	suffix [strlen(argv[1])]='\0';
	i=strlen (strtok(suffix,"."));

for (k=i+1;k!=domainname;k++)
	{
	suffix[t]=argv[1][k];	
	t++;
	}
	suffix[t]='\0';

	domainsuffixlen=t;
	domainsuffixname=suffix;

int dns_payload_size=19+strlen(domainprefixname)+strlen(domainsuffixname);

//Copy domain prefix name
memcpy (dnspayload+sizeof(TransactionID)+
	(10*sizeof(char))+1, 	
        domainprefixname,
	domainprefixlen);
//Copy suffix len
memcpy (dnspayload+sizeof(TransactionID)+
	(10*sizeof(char))+1+domainprefixlen, 	
        &domainsuffixlen,
	1);
//Copy suffix name
memcpy (dnspayload+sizeof(TransactionID)+
	(10*sizeof(char))+1+domainprefixlen+1, 	
        domainsuffixname,
	domainsuffixlen);
//Copy null terminator
memcpy (dnspayload+sizeof(TransactionID)+
	(10*sizeof(char))+1+domainprefixlen+1+domainsuffixlen, 	
        terminator,
	1);

if  (strncmp(argv[3],"dnssec",strlen(argv[3]))==0) 
{
//Copy footer for DNSSEC
memcpy (dnspayload+sizeof(TransactionID)+
	(10*sizeof(char))+1+domainprefixlen+1+domainsuffixlen+1, 	
        footer_dnssec,
	4*sizeof(char));


//Copy AdditionalRecords for DNSSEC
memcpy (dnspayload+sizeof(TransactionID)+
	(10*sizeof(char))+1+domainprefixlen+1+domainsuffixlen+1+4, 	
        dns_additional_records_dnssec,
	23*sizeof(char));
}
else if (strncmp(argv[3],"txt",strlen(argv[3]))==0) 
{
//Copy footer for TXT
memcpy (dnspayload+sizeof(TransactionID)+
	(10*sizeof(char))+1+domainprefixlen+1+domainsuffixlen+1, 	
        footer_txt,
	4*sizeof(char));
//Copy AdditionalRecords for TXT
memcpy (dnspayload+sizeof(TransactionID)+
	(10*sizeof(char))+1+domainprefixlen+1+domainsuffixlen+1+4, 	
        dns_additional_records_txt,
	23*sizeof(char));
}

	serverIP=argv[2];
	serverPort=53;

if ((sock=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0)
	{
	printf ("Error creating UDP socket!\n");
	exit (1);
	}

	memset(&ServAddr,0,sizeof(ServAddr));
	ServAddr.sin_family=AF_INET;
	ServAddr.sin_addr.s_addr=inet_addr(serverIP);
	ServAddr.sin_port=htons(serverPort); 

int sendresult=0;

	sendresult=sendto (sock,dnspayload,dns_payload_size+23,
			   0,(struct sockaddr *)&ServAddr,sizeof(ServAddr));

if (sendresult==-1) 
	{
		printf ("[-] Error sending UDP payload\n");
		exit (1);
	}

int recvresult=recv (sock,dnsreply,4096,0);

if (recvresult==-1)
	{
		printf ("[-] Error receiving DNS reply \n");
		exit (1);
	}
	else if (recvresult<512)
	{
		printf ("[-] Insufficient data received (<512 bytes). Result inconclusive\n");
		exit (1);
	}

printf ("[+] Received %d bytes\n", recvresult);
printf ("[+] Flags is %02x\n", (unsigned short int) dnsreply[2]);

int edns_flag=dnsreply[2]&0x02;

if ( edns_flag == 2)
	printf ("[+] Truncated flag set - not EDNS compatible\n");


close (sock);
}


