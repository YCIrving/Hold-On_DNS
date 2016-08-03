#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define PORT 1253
#define BUF_SIZE 1024

int main(int argc, char *argv[])
{
    int sockfd, len;
    char buf[BUF_SIZE];
    char *p;
    struct hostent *he;
    struct sockaddr_in server,peer;
    if (argc !=3)
    {
    printf("Usage: %s <Domain name> <DNSProxy IP Address>\n",argv[0]);
    exit(1);
    }

    if ((he=gethostbyname(argv[2]))==NULL)
    {
    printf("gethostbyname()error\n");
    exit(1);
    }

    if ((sockfd=socket(AF_INET, SOCK_DGRAM,0))==-1)
    {
    printf("socket() error\n");
    exit(1);
    }

    bzero(&server,sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr= *((struct in_addr *)he->h_addr);
    sendto(sockfd, argv[1],strlen(argv[1]),0,(struct sockaddr *)&server,sizeof(server));
    socklen_t  addrlen;
    addrlen=sizeof(server);
    while (1)
    {
        if((len=recvfrom(sockfd,buf,BUF_SIZE,0,(struct sockaddr *)&peer,&addrlen))== -1)
        {
            printf("recvfrom() error\n");
            exit(1);
    }
        if (addrlen != sizeof(server) ||memcmp((const void *)&server, (const void *)&peer,addrlen) != 0)
        {
            printf("Receive message from otherserver.\n");
            continue;
        }
    //buf[num]='\0';
    p=buf + len -4;
    printf("Message From DNSProxy :%s ==> %u.%u.%u.%u\n",argv[1],
           (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
    break;
    }
    close(sockfd);
    return 0;
    }