#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <strings.h>
#include <arpa/inet.h>
//#include <netinet.h/in.h>
#define PORT 5001
#define MAXDATASIZE 10000

int main(void)
{
  int sockfd,i;
  char buf[MAXDATASIZE];
  struct sockaddr_in server;
  printf("socket creation is started %m\r\n");
  if((sockfd=socket(AF_INET,SOCK_STREAM,0))==-1){
    printf("socket() error\n");
    exit(1);
  }
  printf("socket creation success\r\n");
  bzero(&server,sizeof(server));
  server.sin_family= AF_INET;
  server.sin_port = htons(PORT);
  server.sin_addr.s_addr = inet_addr("192.168.43.210");
  printf("connect is being called\r\n");
  if(connect(sockfd,(struct sockaddr *)&server,sizeof(server))==-1){
    printf("connect()error\n");
    perror("connect error :::");
    exit(1);
  }

  for(i=0;i < 100000; i++) {
    if((send(sockfd,buf,MAXDATASIZE,0)) == -1){
      printf("send error\n");
      exit(1);
    }
  }
  printf("test is done\n");
  close(sockfd);
  return 0;
}
