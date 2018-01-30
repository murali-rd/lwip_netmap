//#include <stdio.h>
//#include <stdlib.h>
//#include <unistd.h>
//#include <string.h>
//#include <sys/types.h>
#include <lwip/sockets.h>
//#include <strings.h>

int lwip_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int lwip_bind(int s, const struct sockaddr *name, socklen_t namelen);
int lwip_shutdown(int s, int how);
int lwip_getpeername (int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockname (int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockopt (int s, int level, int optname, void *optval, socklen_t *optlen);
int lwip_setsockopt (int s, int level, int optname, const void *optval, socklen_t optlen);
int lwip_close(int s);
int lwip_connect(int s, const struct sockaddr *name, socklen_t namelen);
int lwip_listen(int s, int backlog);
int lwip_recv(int s, void *mem, size_t len, int flags);
int lwip_read(int s, void *mem, size_t len);
int lwip_recvfrom(int s, void *mem, size_t len, int flags,
      struct sockaddr *from, socklen_t *fromlen);
int lwip_send(int s, const void *dataptr, size_t size, int flags);
int lwip_sendmsg(int s, const struct msghdr *message, int flags);
int lwip_sendto(int s, const void *dataptr, size_t size, int flags,
    const struct sockaddr *to, socklen_t tolen);
int lwip_socket(int domain, int type, int protocol);
int lwip_write(int s, const void *dataptr, size_t size);
int lwip_writev(int s, const struct iovec *iov, int iovcnt);
int lwip_select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
                struct timeval *timeout);
int lwip_ioctl(int s, long cmd, void *argp);
int lwip_fcntl(int s, int cmd, int val);
#if 1
int accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
  return lwip_accept(s,addr,addrlen);
}

int bind(int s, const struct sockaddr *name, socklen_t namelen)
{
  return lwip_bind(s,name,namelen);
}

int shutdown(int s, int how)
{
  return lwip_shutdown(s,how);
}

int getpeername (int s, struct sockaddr *name, socklen_t *namelen)
{
  return lwip_getpeername(s,name,namelen);
}

int getsockname (int s, struct sockaddr *name, socklen_t *namelen)
{
    return lwip_getsockname (s,name,namelen);
}

int getsockopt (int s, int level, int optname, void *optval, socklen_t *optlen)
{
  return lwip_getsockopt (s,level,optname,optval,optlen);
}

int setsockopt (int s, int level, int optname, const void *optval, socklen_t optlen)
{
  return lwip_setsockopt (s,level,optname,optval,optlen);
}

int close(int s)
{
  return lwip_close(s);
}

int connect(int s, const struct sockaddr *name, socklen_t namelen)
{
  return lwip_connect(s,name,namelen);
}

int listen(int s, int backlog)
{
  return lwip_listen(s,backlog);
}

int recv(int s, void *mem, size_t len, int flags)
{
  return lwip_recv(s,mem,len,flags);
}
#if 0
int read(int s, void *mem, size_t len)
{
  return lwip_read(s,mem,len);
}
#endif

int recvfrom(int s, void *mem, size_t len, int flags,
      struct sockaddr *from, socklen_t *fromlen)
{
  return lwip_recvfrom(s,mem,len,flags,from,fromlen);
}

int send(int s, const void *dataptr, size_t size, int flags)
{
  return lwip_send(s,dataptr,size,flags);
}

int sendmsg(int s, const struct msghdr *message, int flags)
{
  return lwip_sendmsg(s,message,flags);
}

int sendto(int s, const void *dataptr, size_t size, int flags,
    const struct sockaddr *to, socklen_t tolen)
{
  return lwip_sendto(s,dataptr,size,flags,to,tolen);
}
extern int do_lwip_init(void);
int socket(int domain, int type, int protocol)
{
  /*domain = domain;
  type = type;
  protocol = protocol;
  return -1;*/

  static int inited,ret = 0;
  if(inited != 1)
  {
    printf("LWIP used \r\n");
    ret = do_lwip_init();
    if(ret != 0)
    {
      printf("lwip init failed\r\n");
    }
    else
    {
      inited = 1;
    }
  }
  return lwip_socket(domain,type,protocol);
  //return -1;
}
#if 1
int write(int s, const void *dataptr, size_t size)
{
  int ret;
  ret = lwip_write(s,dataptr,size);
  if (ret == -1)
  {
      ret = write(s,dataptr,size);
  }

  return ret;
}

int writev(int s, const struct iovec *iov, int iovcnt)
{
  int ret;
  ret = lwip_writev(s,iov,iovcnt);
  if (ret == -1)
  {
      ret = writev(s,iov,iovcnt);
  }

  return ret;
}
#endif

int select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
                struct timeval *timeout)
{
  return lwip_select(maxfdp1,readset,writeset,exceptset,timeout);
}

/*int ioctl(int s, long cmd, void *argp)
{
  return lwip_ioctl(s,cmd,argp);
}

int fcntl(int s, int cmd, int val)
{
  return lwip_fcntl(s,cmd,val);
}*/

#endif
