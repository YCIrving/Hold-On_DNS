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
#define TIMEOUT 5

typedef unsigned short U16;
const char srv_ip[] = "8.8.8.8";
int expected_TTL=-1,expected_RTT=-1;
int len=-1,retry=1,time_Left=0;
int gotAnyReply=0,DNSSEC_OK=0;
int ttlRatio=2;
float rttRatio=0.1;
typedef struct _DNS_HDR
{
    U16 id;
    U16 tag;
    U16 numq;
    U16 numa;
    U16 numa1;
    U16 numa2;
}DNS_HDR;

typedef struct _DNS_QER
{
    U16 type;
    U16 classes;
}DNS_QER;

int Ping()
{
    int Ping_RTT=-1,Ping_TTL=-1;
    FILE   *stream;
    FILE   *wstream;
    FILE *file;
    char   buf[1024];
    char str_ping[100];
    memset( buf, ' ', sizeof(buf) );//初始化buf,以免后面写如乱码到文件中

    stream = popen( "/mnt/hgfs/Temp/Unix/ping.sh", "r" ); //将“ls －l”命令的输出 通过管道读取（“r”参数）到FILE* stream
    wstream = fopen( "ping_output.txt", "w+"); //新建一个可写的文件
    fread( buf, sizeof(char), sizeof(buf), stream); //将刚刚FILE* stream的数据流读取到buf中
    fwrite( buf, 1, sizeof(buf), wstream );//将buf中的数据写到FILE    *wstream对应的流中，也是写到文件中

    pclose( stream );
    fclose( wstream );
    file =fopen("ping_output.txt","r");
    int i=0;
    while(1)
    {
        i++;
        if(fgets(str_ping,80,file)==NULL)
        {
            break;
        }
        char *pos;
        if(i==3)
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
        if(strstr(str_ping,"min")!=NULL)
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
    printf("\n------------Info From Ping----------\n");
    printf("Ping RTT: %d ms,Ping TTL: %d\n",Ping_RTT,Ping_TTL);
    printf("--------------------------------------\n\n");
    fclose(file);
	return 0;
}
int getExpectedTTL_RTT()
{
    struct timeval starttime,endtime;
    char testURL[]="www.baidu.com";
    int servfd,clifd,i;
    struct sockaddr_in servaddr, addr;
    int socklen = sizeof(servaddr);
    char buf[BUF_SIZE];
    char *p;
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
    len = sendto(clifd, buf, sizeof(DNS_HDR) + sizeof(DNS_QER) +strlen(testURL) + 2, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    gettimeofday(&starttime,0);
    len = recvfrom(clifd,buf, BUF_SIZE, 0, (struct sockaddr *)&servaddr, &i);
    gettimeofday(&endtime,0);
    double timeuse = 1000000*(endtime.tv_sec - starttime.tv_sec) + endtime.tv_usec - starttime.tv_usec;
    expected_RTT=(int)(timeuse/1000);
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
    printf("\n------------Info From Test Request----------\n");
    printf("Test URL: %s \n",testURL);
    if(expected_TTL==-1||expected_RTT==-1)
    {
        printf("Network Unreachable! Program exit.\n");
        return 0;
    }
    printf("Expected RTT:%d,Expected TTL:%d\n",expected_RTT,expected_TTL);
    printf("--------------------------------------\n\n");
    return 0;
}

static void dealSigAlarm(int sigo)
{

    time_Left=0;
    //len = -1;
    printf("%dth alarm timeout!\n",retry);
    retry++;
    return;//just interrupt the recvfrom()
}
int validateTTL(int ttl)
{
    if(ttl>(expected_TTL/ttlRatio)&&ttl<(expected_TTL*ttlRatio))
        return 1;
    else
        return 0;
}
int validateRTT(int rtt)
{
    if(rtt>(expected_RTT*(float)(1.0-rttRatio))&&rtt<(float)(expected_RTT*(1.0+rttRatio)))
        return 1;
    else
        return 0;
}

int main(int argc, char** argv)
{
    int servfd,clifd,i;
    struct sockaddr_in servaddr, addr;
    struct sigaction alarmact;
    int socklen = sizeof(servaddr);
    char bufSend[BUF_SIZE],bufRecv[BUF_SIZE];
    char *p;
    printf("\nPing %s...\n",srv_ip);
    Ping();
    printf("Send Test Request to %s...\n",srv_ip);
    getExpectedTTL_RTT();

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
    strcpy(bufSend + sizeof(DNS_HDR) + 1,argv[1]);
    p = bufSend + sizeof(DNS_HDR) + 1;
    i = 0;
    while (p < (bufSend + sizeof(DNS_HDR) + 1 +strlen(argv[1])))
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
    dnsqer = (DNS_QER *)(bufSend + sizeof(DNS_HDR) + 2 +strlen(argv[1]));
    dnsqer->classes =htons(1);
    dnsqer->type =htons(1);
    int ttl=0,rtt=0;
    bzero(&alarmact,sizeof(alarmact));
    alarmact.sa_handler = dealSigAlarm;
    alarmact.sa_flags = SA_NOMASK;
    sigaction(SIGALRM,&alarmact,NULL);
    struct timeval starttime,endtime;
    i = sizeof(struct sockaddr_in);
    int len_Ans,rtt_Ans,ttl_Ans;


    while(retry<=3)
    {
        if(time_Left==0)
        {
        gettimeofday(&starttime,0);
        len = sendto(clifd, bufSend, sizeof(DNS_HDR) + sizeof(DNS_QER) +strlen(argv[1]) + 2, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
        alarm(retry*TIMEOUT);
        }
        else
            alarm(time_Left);

        len = recvfrom(clifd,bufRecv, BUF_SIZE, 0, (struct sockaddr *)&servaddr, &i);
        gettimeofday(&endtime,0);
        double timeuse = 1000000*(endtime.tv_sec - starttime.tv_sec) + endtime.tv_usec - starttime.tv_usec;
        rtt=(int)(timeuse/1000);
        //len = recv(clifd, buf, BUF_SIZE, 0);
        if (len < 0)
        {
//            if(errno == EINTR)
//                printf("%dth recvfrom (%d s) timeout.\n",retry,retry*TIMEOUT);
//            else
                //printf("%dth recvfrom (%d s) error.\n",retry,retry*TIMEOUT);
                printf("%dth recvfrom is unable to get a reliable reply.\n\n",(retry-1));
        }
       // else
//        //{
////            if (dnshdr->numa == 0)
////            {
////                printf("%d th ack (%d s) error\n",retry,retry*TIMEOUT);
////            }
            else
            {

                printf("%dth recvfrom (%d s) got  a reply!",retry,retry*TIMEOUT);
                gotAnyReply=1;
                //strcpy(bufAns,bufRecv);
                ttl=0;
                /*Validate DNSSEC_OK
                if OK,print IP and break;*/
//                p = buf + len -4;
//                printf("%s ==> %u.%u.%u.%u\n", argv[1], (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));

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
                len_Ans=len;
                ttl_Ans=ttl;
                rtt_Ans=rtt;

                printf("    TTL:%d, RTT:%d\n",ttl,rtt);
                //printf("TTL:%d, RTT:%d\n",validateTTL(ttl),validateRTT(rtt));
                if(validateTTL(ttl)==1&&validateRTT(rtt)==1)
                {
                    p = bufRecv + len -4;
                    printf("\n\nOne Reliable Reply Received!\n");
                    printf("%s ==> %u.%u.%u.%u", argv[1], (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
                    printf("    TTL:%d, RTT:%d\n\n",ttl,rtt);
                    break;
                }
                else
                {
                    time_Left=alarm(0);
                    continue;
                }
            //}
        }
    }
    if(retry==4)
    {
        printf("No Reliable Replies Received.\n");
        if(gotAnyReply==1)
        {
            printf("Show the Last Reply:\n");
            p = bufRecv + len_Ans -4;
            printf("%s ==> %u.%u.%u.%u", argv[1], (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
            printf("    TTL:%d, RTT:%d\n\n",ttl_Ans,rtt_Ans);
        }
        else
            printf("No Suspecious Replies Received.\n\n");
    }
    //p = buf + len -4;
    //printf("%s ==> %u.%u.%u.%u\n", argv[1], (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
    //printf("\n%d\ns",*(p-1));
    close(clifd);
    return 0;
}
