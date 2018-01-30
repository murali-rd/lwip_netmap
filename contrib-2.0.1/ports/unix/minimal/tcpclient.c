
#define PORT 5001
#define MAXDATASIZE 10000
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <lwip/sockets.h>
#include <strings.h>

int tcp_iperf_test(void);
int tcp_iperf_test(void)
{
  int sockfd,i;
  char buf[MAXDATASIZE];
  struct sockaddr_in server;
  if((sockfd=lwip_socket(AF_INET,SOCK_STREAM,0))==-1){
    printf("socket() error\n");
    exit(1);
  }
  bzero(&server,sizeof(server));
  server.sin_family= AF_INET;
  server.sin_port = htons(PORT);
  server.sin_addr.s_addr = inet_addr("192.168.43.210");
  if(lwip_connect(sockfd,(struct sockaddr *)&server,sizeof(server))==-1){
    printf("connect()error\n");
    perror("connect error :::");
    exit(1);
  }

  for(i=0;i < 100000; i++) {
    if((lwip_send(sockfd,buf,MAXDATASIZE,0)) == -1){
      printf("send error\n");
      exit(1);
    }
  }
  printf("test is done\n");
  lwip_close(sockfd);
  return 0;
}
