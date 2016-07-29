#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include<math.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>

#define BUF_SIZE 1024
#define SRV_PORT 53
#define TIMEOUT 5//Define timeout=5 seconds

typedef unsigned short U16;

const char srv_ip[] = "8.8.8.8";//Default DNS server ip
int expected_TTL=-1,expected_RTT=-1;//expected TTL and RTT used to judge whether reply is reliable
int len=-1,retry=1,time_left=0;//length of received buf
int gotAnyReply=0,DNSSEC_OK=0;
float ttlRatio=1.5;//parameter used to confirm TTL,2.0 may be the optimal choice in my PC
float rttRatio=0.1;//parameter used to confirm RTT, 0.1 may be the optimal choice in my PC
char bufSend[BUF_SIZE],bufRecv[BUF_SIZE];//buffer used to send query and receive reply
char queryURL[100];

typedef struct _DNS_HDR//DNS Header Struct
{
    U16 id;
    U16 tag;
    U16 numq;
    U16 numa;
    U16 numa1;
    U16 numa2;
}DNS_HDR;

typedef struct _DNS_QER//DNS Query Struct
{
    U16 type;
    U16 classes;
}DNS_QER;

int Ping()//Use ping.sh to test if the network is linked and get the TTL and RTT for reference
{
    printf("\nPing %s...\n",srv_ip);
    int Ping_RTT=-1,Ping_TTL=-1;
    FILE   *stream;
    FILE   *wstream;
    FILE *file;
    char buf[1024];
    char str_ping[100];
    memset( buf, '\0', sizeof(buf) );//initialize buf

    stream = popen( "./ping.sh", "r" ); //open a shell and get the output
    wstream = fopen( "ping_output.txt", "w+"); //open a file
    fread( buf, sizeof(char), sizeof(buf), stream); //read the output
    fwrite( buf, 1, sizeof(buf), wstream );//write the buf into file

    pclose( stream );
    fclose( wstream );
    file =fopen("ping_output.txt","r");//open the output file
    int i=0;
    while(1)
    {
        i++;
        if(fgets(str_ping,80,file)==NULL)//read an available line
            break;

        char *pos;
        if(i==3)//get the TTL of ping output
        {
            pos=strstr(str_ping,"ttl=");
            if(pos==NULL)
                return -1;
            Ping_TTL=Ping_RTT=0;
            pos+=4;
            int j=0,k;
            char c=*(pos+j);
            while(c<='9'&&c>='0')
            {
                j++;
                c=*(pos+j);
            }
            k=--j;
            while(k>=0)
            {
                Ping_TTL+=(*(pos+k)-'0')*pow(10,j-k);
                k--;
            }
        }
        if(strstr(str_ping,"min")!=NULL)//get the RTT of the ping output
        {
            pos=strstr(str_ping,"=")+2;
            int j=0,k;
            char c=*(pos+j);
            while(c<='9'&&c>='0')
            {
                j++;
                c=*(pos+j);
            }
            k=--j;
            while(k>=0)
            {
                Ping_RTT+=(*(pos+k)-'0')*pow(10,j-k);
                k--;
            }
            break;
        }
    }
    printf("\n-------------Info From Ping-----------\n");
    printf("Ping RTT: %d ms,Ping TTL: %d\n",Ping_RTT,Ping_TTL);
    printf("--------------------------------------\n\n");
    fclose(file);
	return 0;
}

int getExpectedTTL_RTT()//send a DNS query without sensitive keyword and get the reply
{
    printf("Sending Test Request to %s...\n",srv_ip);
    struct timeval starttime,endtime;//Used to calculate the RTT
    char testURL[]="www.baidu.com";
    int servfd,clifd,i;
    struct sockaddr_in servaddr, addr;
    int socklen = sizeof(servaddr);
    char buf[BUF_SIZE];
    char *p;

    //1.construct DNS query,query=DNS_HDR+testURL+DNS_QER
    DNS_HDR  *dnshdr = (DNS_HDR *)buf;
    DNS_QER  *dnsqer = (DNS_QER *)(buf + sizeof(DNS_HDR));
    if ((clifd  =  socket(AF_INET,SOCK_DGRAM, 0 ))  <   0 )
    {
        printf( " create socket error!\n " );
        return -1;
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    inet_aton(srv_ip, &servaddr.sin_addr);
    servaddr.sin_port = htons(SRV_PORT);
    memset(buf, 0, BUF_SIZE);
    dnshdr->id = (U16)1;
    dnshdr->tag = htons(0x0100);
    dnshdr->numq = htons(1);
    dnshdr->numa = 0;
    strcpy(buf + sizeof(DNS_HDR) + 1,testURL);
    p = buf + sizeof(DNS_HDR) + 1;
    i = 0;
    while (p < (buf + sizeof(DNS_HDR) + 1 +strlen(testURL)))
    {
        if ( *p == '.')
        {
            *(p - i - 1) =i;
            i = 0;
       }
        else
        {
            i++;
        }
        p++;
   }
    *(p - i - 1) =i;
    dnsqer = (DNS_QER *)(buf + sizeof(DNS_HDR) + 2 +strlen(testURL));
    dnsqer->classes =htons(1);
    dnsqer->type =htons(1);

    //2.send the query request to DNS server
    len = sendto(clifd, buf, sizeof(DNS_HDR) + sizeof(DNS_QER) +
                            strlen(testURL) + 2, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    gettimeofday(&starttime,0);

    //3.receive the reply from DNS server
    len = recvfrom(clifd,buf, BUF_SIZE, 0, (struct sockaddr *)&servaddr, &i);
    gettimeofday(&endtime,0);

    //4.calculate the expected RTT
    double timeuse = 1000000*(endtime.tv_sec - starttime.tv_sec) +
                            endtime.tv_usec - starttime.tv_usec;
    expected_RTT=(int)(timeuse/1000);

    //5.calculate the expected TTL
    if (len >= 0)
    {
        expected_TTL=0;
        p=buf+len-10;
        int i=3;
        while(i>=0)
        {
            int temp=(unsigned int)(*p);
            if(temp<0)
                temp+=256;
            expected_TTL+=temp*pow(16,i*2);
            i--;
            p++;
        }
    }
    close(clifd);

    //6.show the output.
    printf("\n--------Info From Test Request--------\n");
    printf("Test URL: %s \n",testURL);
    if(expected_TTL==-1||expected_RTT==-1)
    {
        printf("Network Unreachable! Program exit.\n");
        return 0;
    }
    printf("Expected RTT:%d, Expected TTL:%d\n",expected_RTT,expected_TTL);
    printf("--------------------------------------\n\n");
    return 0;
}

static void dealSigAlarm(int sigo)//handle the alarm timeout interruption
{
    time_left=0;
    printf("%dth alarm timeout!\n",retry);
    retry++;
    return;//just interrupt the recvfrom()
}

int validateTTL(int ttl)//validate TTL
{
    if(ttl>(expected_TTL*(float)(1.0-ttlRatio))&&ttl<(float)(expected_TTL*(1.0+ttlRatio)))
        return 1;
    else
        return 0;
}
int validateRTT(int rtt)//validate RTT
{
    if(rtt>(expected_RTT*(float)(1.0-rttRatio))&&rtt<(float)(expected_RTT*(1.0+rttRatio)))
        return 1;
    else
        return 0;
}

int DNSForward()
{

    printf("Sending Query %s  to %s...\n\n",queryURL,srv_ip);
    int servfd,clifd,i;
    struct sockaddr_in servaddr, addr;
    struct sigaction alarmact;
    int socklen = sizeof(servaddr);
    char *p;
    int ttl=0,rtt=0;//used to record current reply info
    int len_Ans,rtt_Ans,ttl_Ans;//used to record last unreliable reply info

    //1.contruct DNS query in bufSend
    DNS_HDR  *dnshdr = (DNS_HDR *)bufSend;
    DNS_QER  *dnsqer = (DNS_QER *)(bufSend + sizeof(DNS_HDR));
    if ((clifd  =  socket(AF_INET,SOCK_DGRAM, 0 ))  <   0 )
    {
        printf( "Create socket error!\n " );
        return -1;
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    inet_aton(srv_ip, &servaddr.sin_addr);
    servaddr.sin_port = htons(SRV_PORT);
    /*if (connect(clifd, (struct sockaddr *)&servaddr, socklen) < 0)
    {

         printf( " can't connect to %s!\n ", argv[ 1 ]);
          return -1;
    }*/
    memset(bufSend, 0, BUF_SIZE);
    dnshdr->id = (U16)1;
    dnshdr->tag = htons(0x0100);
    dnshdr->numq = htons(1);
    dnshdr->numa = 0;
    strcpy(bufSend + sizeof(DNS_HDR) + 1,queryURL);
    p = bufSend + sizeof(DNS_HDR) + 1;
    i = 0;
    while (p < (bufSend + sizeof(DNS_HDR) + 1 +strlen(queryURL)))
    {
        if ( *p == '.')
        {
            *(p - i - 1) =i;
            i = 0;
       }
        else
        {
            i++;
        }
        p++;
   }
    *(p - i - 1) =i;
    dnsqer = (DNS_QER *)(bufSend + sizeof(DNS_HDR) + 2 +strlen(queryURL));
    dnsqer->classes =htons(1);
    dnsqer->type =htons(1);

    //2.construct and initialize the alarm system
    bzero(&alarmact,sizeof(alarmact));
    alarmact.sa_handler = dealSigAlarm;
    alarmact.sa_flags = SA_NOMASK;
    sigaction(SIGALRM,&alarmact,NULL);
    struct timeval starttime,endtime;
    i = sizeof(struct sockaddr_in);

    //3.main implementation of Hold-on DNS
    printf("---Info From %s Request---\n",queryURL);
    while(retry<=3)
    {
        //3.1 set alarm and send the query
        if(time_left==0)
        {
        gettimeofday(&starttime,0);
        len = sendto(clifd, bufSend, sizeof(DNS_HDR) + sizeof(DNS_QER) +
                    strlen(queryURL) + 2, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
        alarm(retry*TIMEOUT);
        }
        else
            alarm(time_left);

        //3.2 receive from the DNS server and calculate RTT
        len = recvfrom(clifd,bufRecv, BUF_SIZE, 0, (struct sockaddr *)&servaddr, &i);
        gettimeofday(&endtime,0);
        double timeuse = 1000000*(endtime.tv_sec - starttime.tv_sec) +
                    endtime.tv_usec - starttime.tv_usec;
        rtt=(int)(timeuse/1000);

        //3.2.1 if recvfrom end because timeout, there 's no reliable replies.
        if (len < 0)
        {
                printf("%dth recvfrom got no reliable replies.\n\n",(retry-1));
        }

        //3.2.2 if recvfrom end because receiving a reply
        else
        {
            printf("%dth recvfrom (%d s) got  a reply!",retry,retry*TIMEOUT);
            gotAnyReply=1;
            ttl=0;

            //3.2.2.1 Validate DNSSEC_OK
            /*if (DNSSEC_OK==1)
                print IP and break;*/

            //3.2.2.2 Validate TTL and RTT
            p=bufRecv+len-10;
            int i=3;
            while(i>=0)
            {
                int temp=(int)(*p);
                if(temp<0)
                    temp+=256;
                ttl+=temp*pow(16,i*2);
                i--;
                p++;
            }
            //record info of last reply
            len_Ans=len;
            ttl_Ans=ttl;
            rtt_Ans=rtt;

            printf("    RTT:%d, TTL:%d\n",rtt,ttl);

            //RTT and TTL are both OK, reply is reliable
            if(validateTTL(ttl)==1&&validateRTT(rtt)==1)
            {
                p = bufRecv + len -4;
                printf("\nOne Reliable Reply Received!\n");
                printf("%s ==> %u.%u.%u.%u", queryURL, (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
                printf("    RTT:%d, TTL:%d\n\n",rtt,ttl);
                break;
            }
            //reply is unliable, continue recvfrom
            else
            {
                time_left=alarm(0);
                continue;
            }
        }
    }

    //3.3 if retry=4, means no reliable replies received
    if(retry==4)
    {
        printf("No Reliable Replies Received.\n");
        //3.3.1 got at least one unliable replies
        if(gotAnyReply==1)
        {
            printf("Show the Last Reply:\n");
            p = bufRecv + len_Ans -4;
            printf("%s ==> %u.%u.%u.%u", queryURL, (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
            printf("    RTT:%d, TTL:%d\n\n",rtt_Ans,ttl_Ans);
        }
        //3.3.2 got no replies
        else
            printf("No Suspecious Replies Received.\n\n");
    }
    close(clifd);
    return 0;
}

int main(int argc, char** argv)
{
    strcpy(queryURL,argv[1]);
    Ping();
    getExpectedTTL_RTT();
    DNSForward();
    return 0;
}
