#include <netinet/tcp.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <sys/time.h>
#include <sys/select.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <string>
#include <ctype.h>
#include <ctime>
#include <vector>
#include "redislib/hiredis.h"

using namespace std;
#define DEBUG true
#define MAX_CHARS 2000000

#define C_CLOCKS_PER_SEC 1995000000
#define cclock(X)  {unsigned int hi_chris, lo_chris;__asm__ volatile ("rdtsc" : "=d" (hi_chris)); __asm__ volatile ("rdtsc" : "=a" (lo_chris)); X = hi_chris; X=X<<32 | lo_chris;}

redisContext * redis_initiate(char * server, int port)
{
  redisContext * dc;
  /*If we make it back here restart redis connection too*/
  //printf("Made it to initiate %s\n", server);
  int length = strlen(server);
  //printf("length = %d\n", length);
  char * pch = NULL;
  if((pch = strstr(server, "\n")) != NULL)
  {
    //printf("extra line\n");
    pch[0] = 0;
    printf("%s\n", server);
  }
  if(server[0] == 0) return 0;
  struct timeval timeout;
  timeout.tv_sec =  10;
  timeout.tv_usec = 500000;
  dc = redisConnectWithTimeout(server, port, timeout);
  if (dc->err) {
    printf("Connection error: %s\n", dc->errstr);
    redisFree(dc);
    return NULL;
  }
  //printf("Exiting initiate\n");
  return dc;
}

double info_translate(char * infoReply, char * server)
{
  char * uml = strstr(infoReply, "used_memory:");
  char * miduml = strstr(uml, ":");
  char * enduml = strstr(uml, "\r\n");
  char memory[20];
  bzero(memory, 20);
  strncpy(memory, miduml+1, enduml-miduml-1);
  //printf("Info: %s\n", memory);
  double mem_used = atof(memory);
 
  uml = strstr(infoReply, "used_memory_peak:");
  miduml = strstr(uml, ":");
  enduml = strstr(uml, "\r\n");
  char memory_peak[20];
  bzero(memory_peak, 20);
  strncpy(memory_peak, miduml+1, enduml-miduml-1);
  //printf("Memory Peak: %s\n", memory_peak);
  double mem_peak = atof(memory_peak);
 
  printf("%s, %4.4f, %4.4f, %4.4f\n", server, mem_used, mem_peak, (mem_used / mem_peak));
  char * pch = NULL;
  if((pch = strstr(server, "\n")) != NULL) pch[0] = 0;
  FILE * infoFile;
  infoFile = fopen(server, "a");
  if(infoFile != NULL)
  {
    fprintf(infoFile, "%s, %4.4f, %4.4f, %4.4f\n", server, mem_used, mem_peak, (mem_used / mem_peak));
    fclose(infoFile);
  }

  return (mem_used / mem_peak);
}

char * redis_INFO(redisContext *dc)
{
  if(dc == NULL) printf("redisContext is null\n");
  //printf("made it to redis_INFO\n");
  redisReply *replyInfo;
  replyInfo = (redisReply *)redisCommand(dc, "INFO memory");
  int lengthReply = strlen(replyInfo->str);
  if(lengthReply > 0){
    char * myReply;
    myReply = (char *)malloc(sizeof(char) *lengthReply);
    bzero(myReply, lengthReply);
    strncpy(myReply, replyInfo->str, lengthReply);
    freeReplyObject(replyInfo);
    return myReply;
  }

  printf("no info\n");
  freeReplyObject(replyInfo);
  return NULL;
}

char * redis_GET(redisContext *c, char * key)
{
  //printf("entering redis_GET with context\n");
  redisReply * getReply = (redisReply *)redisCommand(c, "GET \"disk:%s\"", key);
  //printf("after redisCommand\n");
  if(getReply->type == REDIS_REPLY_NIL)
  {
    freeReplyObject(getReply);
    return NULL;
  }
  
  int length = strlen(getReply->str);
  if(length <= 0)
  {
    freeReplyObject(getReply);
    return NULL;
  }

  char * pch = NULL;
  pch = strstr(getReply->str, "blank");
  if(pch != NULL && pch[0] == getReply->str[0])
  {
    freeReplyObject(getReply);
    return NULL;
  }

  char * rednit = (char *)malloc(sizeof(char) * length);
  strncpy(rednit, getReply->str + 2, length - 4);  
  freeReplyObject(getReply);
  return rednit;
}

char * redis_GET(char * key)
{
	unsigned long long start, stop;
  unsigned int len = strlen(key) + 1;
  char newkey[len];
  char * newbuf = NULL;
  bzero(newkey, len);
  strcpy(newkey, key);
  //printf("strpcy empty\n");
  char localhost[11];
  bzero(localhost, 11);
  strcpy(localhost, "127.0.0.1");
  int outcome = 0;
	cclock(start);
  char * infoReply = NULL;
  char * getReply = NULL;
  FILE * serversFile;
  char myServers[30];
  bzero(myServers, 30);
  strcpy(myServers, "myServers");
  serversFile = fopen(myServers, "r");
  if(serversFile == NULL)
  {
    redisContext * dc;
    if((dc = redis_initiate(localhost, 1055)) != NULL)
    {
      /* this is the only one working, so send to it */
      infoReply = redis_INFO(dc);
      double size = info_translate(infoReply, localhost);
      //printf("Info: %4.4f\n", size);
      getReply = redis_GET(dc, newkey);
      if(getReply == NULL || strlen(getReply) <= 0)
      {
        newbuf = (char *)malloc(sizeof(char) * 6);
        strcpy(newbuf, "blank");
      }
      else
      {
        int length = strlen(getReply);
        newbuf = (char *)malloc(sizeof(char) * length);
        strncpy(newbuf, getReply, length);
      }
      redisFree(dc);
    }
    else
    {
      newbuf = (char *)malloc(sizeof(char)*6);
      strcpy(newbuf, "blank");
    }
  }
  else
  {
    char inString[100];
    char * line = NULL;
    size_t len = 0;
    int found = 0;
    int port = 1055;
    ssize_t read2;
    bool first = true;
    while((read2 = getline(&line, &len, serversFile)) != -1) {
      bzero(inString, 100);
      strcpy(inString, line);
      char * pch = strstr(inString, ":");
      if(pch != NULL)
      {
        port = atoi(pch+1);
        pch[0] = 0;
      }
      printf("line says server is %s, port is %d.\n", inString, port);

      redisContext * dc;
      dc = redis_initiate(inString, port);
      if(dc == NULL)
      {
        continue;
      }
      else
      {
        infoReply = redis_INFO(dc);
        double size = info_translate(infoReply, inString);
        //printf("Info: %4.4f\n", size);

        if(found == 1){
          redisFree(dc);
          continue;
        }
        
        getReply = redis_GET(dc, newkey);
        if(getReply == NULL || strlen(getReply) <= 0)
        {
          // do nothing
        }
        else
        {
          char * pch = NULL;
          pch = strstr(getReply, "blank");
          if(pch != NULL)
          {
            redisFree(dc);
            continue;
          }
          else
          {
            int length = strlen(getReply);          
            newbuf = (char*)malloc(sizeof(char) * length);
            strncpy(newbuf, getReply, length);
            found = 1;
          }
        }
      }

      redisFree(dc);
    }

    if(found == 0)
    {
      newbuf = (char *)malloc(sizeof(char) * 6);
      strcpy(newbuf, "blank");
    }

    fclose(serversFile);
	}
  //printf("after reply type\n");

  if(getReply != NULL) free(getReply);	
  if(infoReply != NULL) free(infoReply);

	cclock(stop);
	double currtime = (double)( (double)(stop - start) / (double)C_CLOCKS_PER_SEC);
	printf("time to get %s: %4.2f\n", newkey, currtime);
  char * pch = NULL;
  pch = strstr(newbuf, "blank");

  if(pch == NULL) printf("we found the droid we were looking for\n");
  else printf("going to disk\n"); 
	//printf("result of get %s: %s\n", newkey, newbuf);
  return newbuf;
}

main(int argc, char *argv[])
{
	int srvsock;
	int sock;
	struct sockaddr_in srv_addr; // structure for socket name setup
	struct sockaddr_in cli_addr;
  struct sockaddr_in sin_addr;
  struct sockaddr_in bsin_addr;
	struct sockaddr_in head_addr;
	int cliport = atoi(argv[1]);
  int bindport = cliport + 5;
	int srvport = 0;
  /*char srvaddr[100];
  bzero(srvaddr, 100);*/
  if(argc > 2)
  {
      srvport = atoi(argv[2]);
  }

  if(srvport == 0) srvport = 1064;



	int optval = 1;
	int n = 0;
	bool exitBool = false;
  struct timeval tv;
	
	tv.tv_sec = 1;
	tv.tv_usec = 500000;

  /* Connect to client */
  if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
    perror("error opening stream BE socket");
    return -1;
  }	
		
  // construct name of socket to send to
  sin_addr.sin_family = AF_INET;
  sin_addr.sin_addr.s_addr = INADDR_ANY;
  sin_addr.sin_port = htons(cliport);

  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &optval, sizeof optval);

  // bind socket name to socket
  if(bind(sock, (struct sockaddr *)&sin_addr, sizeof(struct sockaddr_in)) < 0) {
		perror("error binding stream socket");
		exit(1);
  }

  if(DEBUG) printf("Bound back end socket port %i\n", cliport);

  // listen for socket connection and set max opened socket connections to 1
  listen(sock, 10);
	printf("Listening for server\n");
	/* We are now listening for a client. */

	int rc = 0;
	struct timeval ZERO;
	ZERO.tv_sec = 0;
	ZERO.tv_usec = 0;
  bool contEx = true;

  while(contEx){
    int clisock;
	  if((clisock = accept(sock, (struct sockaddr *)NULL, (socklen_t *)NULL)) == -1)
	  {
		  perror("error connecting stream client socket");
		  close(clisock);
		  continue;
	  }

	  string value = "";
	  string readyLine = "";
    int si = 0;
	  size_t index = string::npos;
    char tots[1000];
    bzero(tots, 1000);
    int qsize = 0;
    if((qsize = read(clisock, (char*)tots, 1000)) < 0) {
      printf("Read failed");
      close(clisock);
      continue;
    }
    else {
      readyLine += tots;
      //printf("headsock msg %s\n", readyLine.c_str());
      index = readyLine.find("\n");
    }

    si = readyLine.length();

	  printf("Got path %s\n", readyLine.c_str());
	  char * value2;
	  value2 = redis_GET((char *)(readyLine.c_str()));
	  value = value2;

	  if(value.length() > 0) printf("Checked REDIS, answer is %d bytes long\n", value.length());
 
	  printf("before server connect\n");
    bool sentdone = false;
    char * pch = NULL;
    pch = strstr((char*)value.c_str(), "blank");  

	  if(value.length() > 0 && (pch == NULL || pch[0] != value2[0]))
	  {
		  printf("Value from Redis\n");
		  write(clisock, (char*)value.c_str(), value.length());
      //if(value.find("done") != string::npos) sentdone = true;
      value = "";
	  }
	  else
	  {
		  // Connect to server 
		  if((srvsock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			  perror("error opening socket to server");
		  } else {
        printf("socket init\n");
      }
		
		  // bind socket on this end
		  bsin_addr.sin_family = AF_INET;
		  bsin_addr.sin_addr.s_addr = INADDR_ANY;
		  bsin_addr.sin_port = htons(bindport);

      setsockopt(srvsock,SOL_SOCKET,SO_REUSEADDR, &optval, sizeof optval);
      //setsockopt(srvsock,SOL_SOCKET,SO_REUSEPORT, &optval, sizeof optval);

      if(bind(srvsock, (struct sockaddr *)&bsin_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("error binding socket to server");
      }
      printf("bound srvsock to %d\n", bindport);
      // this is the code that handles the ip address
      // construct the name of the socket to send to

      //if(srvaddr[0] != 0)
      //{
      char srvaddr[100];
      bzero(srvaddr, 100);
      FILE * diskFile;
      char diskFileName[30];
      bzero(diskFileName, 30);
      strcpy(diskFileName, "mydisk");
      diskFile = fopen(diskFileName, "r");
      if(diskFile == NULL)
      {
        //crash horribly
        printf("Please provide a target server ipaddress.");
        exit(1);
        //strcpy(srvaddr, "kelley.disk.0");
      }
      else
      {
        char inString[100];
        char * line = NULL;
        size_t len = 0;
        ssize_t read2;
        if((read2 = getline(&line, &len, diskFile)) != -1) {
          bzero(inString, 100);
          strcpy(inString, line);
          char * servfind = NULL;
          if((servfind = strstr(inString, "\n")) != NULL)
          {
            servfind[0] = 0;
            printf("%s\n", inString);
          }
          strcpy(srvaddr, inString);
          int length = strlen(srvaddr);
          if(length <= 0)
          {
            //crash horribly
            printf("Please provide a non-null target server ipaddress.");
            exit(1);
            // strcpy(srvaddr, "kelley.disk.0");
          }
          fclose(diskFile);
        }
      }

      struct hostent *hp;

      hp = gethostbyname(srvaddr);
      if(hp == 0)
      {
	      printf("%s: unknown host\n", srvaddr);
	      exit(1);
      }
      bcopy((void *)hp->h_addr, (void *)&srv_addr.sin_addr, hp->h_length);
      srv_addr.sin_family = AF_INET;
      srv_addr.sin_port = htons(srvport); // put in network byte order
      int optval = 1;
      setsockopt(srvsock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

      //int opt = 1;
      //ioctl(srvsock, FIONBIO, &opt);

      //printf("Connecting to server %d\n", (int *)&srv_addr.sin_addr.s_addr);
      // establish connection with server
      int status;
      if((status = connect(srvsock, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr_in))) < 0)
      {
        printf("Status: %d\n", status);
        perror("error connecting to server\n");
        close(srvsock);
        close(clisock);
        continue;
      }
      else
      { 
        printf("Connected to server\n");
      }
      /* End connect to server */
      struct timeval start;
      gettimeofday(&start, NULL);

      if((status = write(srvsock, tots, qsize+1)) < 0)
      {
        printf("write failed\n");
        close(srvsock);
        close(clisock);
        continue;
      }
      else
      {
        printf("wrote %d bytes to server\n", status);
      }

      bool broken = false;
  
      printf("Done writing %s to server\n", readyLine.c_str());

      printf("Before receive from server\n");
      int strikes = 0;
      broken = false;
      int numEmpty = 0;
      int iter = 0;
      ssize_t bytesRead, bytesWritten;

      struct timeval timeRead;
      timeRead.tv_sec = 0;
      timeRead.tv_usec = 500;
      fd_set fds;
      FD_ZERO(&fds);
      FD_SET(srvsock, &fds);
      int rc;
      
      struct timeval stop;
      gettimeofday(&stop, NULL);

      double lasttime = 0.0;
      int totalbytesr = 0;
      int totalbytesw = 0;

      while((rc = select(sizeof(fds)*8, &fds, NULL, NULL, &timeRead)) > -1)
      {
        //printf("select worked\n");
        if(FD_ISSET(srvsock, &fds))
        {
          gettimeofday(&stop, NULL);
          double currtime = stop.tv_sec - start.tv_sec + (stop.tv_usec /1000000) - (start.tv_usec / 1000000);
          //printf("Iteration %d at time %4.4f\n", iter, currtime);
          lasttime = currtime;
          iter++;
          int stat = 0;
          char toStringTmp[100000];
          bzero(toStringTmp, 100000);
      
          if((bytesRead = recv(srvsock, (char*)toStringTmp, 100000, 0)) < 0) {
            printf("Read failed\n");
            break;
          }
          else
          {
	          if(toStringTmp[0] != 0)
            {
              totalbytesr += (int) bytesRead;
              //printf("we got stuff: %d bytes\n", bytesRead);
	            if((bytesWritten = write(clisock, (char*)toStringTmp, bytesRead)) < 0)
	            {
                printf("Write failed\n");
	              break;
              }
              else
              {
                //printf("Received %d, wrote %d\n", bytesRead, bytesWritten);
                totalbytesw += (int) bytesWritten;
              }
            }
            else
            {
               numEmpty++;
              //printf("No input.");
              if(numEmpty > 30)
	            {
	              printf("More than thirty.");
	              break;
	            }
            }
          }
        }

        struct timeval newtime;
        gettimeofday(&newtime, NULL);
        double auxtime = newtime.tv_sec - stop.tv_sec + (newtime.tv_usec /1000000) - (stop.tv_usec / 1000000);
        if(auxtime > 0.1)
        {
          printf("hit timeout after 0.1 seconds.\n");
          break;
        }

        FD_ZERO(&fds);
        FD_SET(srvsock, &fds);
      }
          
      printf("Query ended after %d iter with %d bytes sent and %d bytes written at %4.4f s.\n", iter, totalbytesr, totalbytesw, lasttime);
    
    }

    free(value2);

    close(srvsock);
    close(clisock);

    printf("listening for new connection\n");

  }
	close(sock);

  printf("Ended naturally with finish\n");
}
