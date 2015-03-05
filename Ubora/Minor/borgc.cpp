#include <omp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include "redislib/hiredis.h"
#include <iostream>
extern "C" {
#include <libipq.h>
}
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <string.h>
#include <cstdint>
#include <cstdlib>

#define BUFSIZE 65536
#define TH_FIN 0x01
#define TH_ACK 0x10
#define MAX_CHARS 536870912

#define C_CLOCKS_PER_SEC 1995000000
#define cclock(X)  {unsigned int hi_chris, lo_chris;__asm__ volatile ("rdtsc" : "=d" (hi_chris)); __asm__ volatile ("rdtsc" : "=a" (lo_chris)); X = hi_chris; X=X<<32 | lo_chris;}

#ifndef TCPOPT_WSCALE
#define	TCPOPT_WSCALE		3	/* window scale factor (rfc1072) */
#endif
#ifndef TCPOPT_SACKOK
#define	TCPOPT_SACKOK		4	/* selective ack ok (rfc1072) */
#endif
#ifndef TCPOPT_SACK
#define	TCPOPT_SACK		5	/* selective ack (rfc1072) */
#endif
#ifndef TCPOLEN_SACK
#define TCPOLEN_SACK            8       /* length of a SACK block */
#endif
#ifndef TCPOPT_ECHO
#define	TCPOPT_ECHO		6	/* echo (rfc1072) */
#endif
#ifndef TCPOPT_ECHOREPLY
#define	TCPOPT_ECHOREPLY	7	/* echo (rfc1072) */
#endif
#ifndef TCPOPT_TIMESTAMP
#define TCPOPT_TIMESTAMP	8	/* timestamps (rfc1323) */
#endif
#ifndef NFPROTO_IPV4
#define NFPROTO_IPV4 2 /* undefined during compile */
#define DEBUG true
#endif

using namespace std;

struct myKV{
	string key;	
	string value;
	int acknum;
	int seqnum;
	bool trans;
};

vector<struct myKV> * allKVs = new vector<struct myKV>();

struct tcp_pseudo
{
  unsigned int src_addr;
  unsigned int dst_addr;
  unsigned char zero;
  unsigned char proto;
  unsigned short length;
} pseudohead;

struct m_group
{
  unsigned short dport;
  unsigned short sport;
  unsigned int src_addr;
  unsigned int dst_addr;
  char data_range[50];
  char mangler[50];
  char parameters[100];
  int mode;
};

long get_tcp_checksum(struct iphdr * myip, struct tcphdr * mytcp) {
    unsigned short total_len = ntohs(myip->tot_len);
    int tcpopt_len = mytcp->doff*4 - 20;
    int tcpdatalen = total_len - (mytcp->doff*4) - (myip->ihl*4);
   
    pseudohead.src_addr = myip->saddr;
    pseudohead.dst_addr = myip->daddr;
    pseudohead.zero = 0;
    pseudohead.proto=IPPROTO_TCP;
    pseudohead.length=htons(sizeof(struct tcphdr) + tcpopt_len + tcpdatalen);
 
    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr) + tcpopt_len + tcpdatalen;
    unsigned short * tcp = new unsigned short[totaltcp_len];
 
    memcpy((unsigned char *)tcp, &pseudohead, sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)mytcp, sizeof(struct tcphdr));
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo)+sizeof(struct tcphdr), (unsigned char*)myip + (myip->ihl*4)+(sizeof(struct tcphdr)), tcpopt_len);
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo)+sizeof(struct tcphdr)+tcpopt_len, (unsigned char *)mytcp+(mytcp->doff*4), tcpdatalen);
 
    register long sum = 0;
 
    while(totaltcp_len > 1)
    {
      sum += * tcp++;
      totaltcp_len -= 2;
    }
 
   if(totaltcp_len > 0)
   {
     sum += * (unsigned char *) tcp;
   }

   while(sum >> 16)
   {
     sum = (sum & 0xffff) + (sum >> 16);
   }

   return ~sum;
}


redisContext * redis_initiate(char * server, int port)
{
    redisContext * dc;
    /*If we make it back here restart redis connection too*/
    if(DEBUG) printf("Made it to initiate %s\n", server);
    int length = strlen(server);
    printf("length = %d\n", length);
    char * pch = NULL;
    if((pch = strstr(server, "\n")) != NULL)
    {
      printf("extra line\n");
      pch[0] = 0;
      printf("extra line: %s\n", server);
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
    if(DEBUG) printf("Exiting initiate\n");
	  return dc;
}

char * redis_INFO(redisContext *dc)
{
  if(dc == NULL) printf("redisContext is null\n");
  if(DEBUG) printf("made it to redis_INFO\n");
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

  if(DEBUG) printf("no Reply\n");
  freeReplyObject(replyInfo);
  return NULL;
}

double info_translate(char * infoReply, char * server)
{
  char * uml = strstr(infoReply, "used_memory:");
  char * miduml = strstr(uml, ":");
  char * enduml = strstr(uml, "\r\n");
  char memory[20];
  bzero(memory, 20);
  strncpy(memory, miduml+1, enduml-miduml-1);
  if(DEBUG) printf("Info: %s\n", memory);
  double mem_used = atof(memory);

  uml = strstr(infoReply, "used_memory_peak:");
  miduml = strstr(uml, ":");
  enduml = strstr(uml, "\r\n");
  char memory_peak[20];
  bzero(memory_peak, 20);
  strncpy(memory_peak, miduml+1, enduml-miduml-1);
  if(DEBUG) printf("Memory Peak: %s\n", memory_peak);
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

int redis_DELETE(redisContext *dc, char * key)
{
  if(dc == NULL){
    printf("redisContext is null\n");
    return 0;
  }

  redisReply * replyDEL;
  replyDEL = (redisReply *)redisCommand(dc, "DEL \"disk:%s\"", key);
  if(replyDEL->type == REDIS_REPLY_NIL)
  {
    freeReplyObject(replyDEL);
    return 0;
  }

  freeReplyObject(replyDEL);
  return 1;
}

int redis_SCARD(char * redis_server, int redis_port)
{
  printf("At SCARD\n");
  redisContext * dc;
  if((dc = redis_initiate(redis_server, redis_port)) != NULL)
  {
    char queries[10];
    bzero(queries, 10);
    strcpy(queries, "queries");
    printf("init in SCARD\n");
    
    redisReply * replyCard;
    replyCard = (redisReply *)redisCommand(dc, "SCARD %s", queries);
    if(replyCard->type == REDIS_REPLY_NIL)
    {
      printf("found REDIS_REPLY_NIL\n");
      freeReplyObject(replyCard);
      redisFree(dc);
      return 0;
    }

    printf("About to interpret string\n");
    int numObjects = (int) replyCard->integer;
    printf("String says: %d\n", numObjects);
    freeReplyObject(replyCard);
    redisFree(dc);
    return numObjects;
  }

  return 0;
}

int redis_SREM(redisContext *dc, char * set, char * key)
{
  if(dc == NULL){
    printf("redisContext is null\n");
    return 0;
  }
  
  redisReply * replyDELfromSET;
  replyDELfromSET = (redisReply *)redisCommand(dc, "SREM %s \"disk:%s\"", set, key);
  if(replyDELfromSET->type == REDIS_REPLY_NIL)
  {
    freeReplyObject(replyDELfromSET);
    return 0;
  }
 
  freeReplyObject(replyDELfromSET);
  return 1;
}

char * redis_SET(redisContext *c, string key, string value, char * setName, int timeout){
  if(DEBUG) printf("entering redis_SET with context\n");
  unsigned int keylen = key.length() + 1;
  unsigned int len = value.length() + 1;
  char newkey[keylen];
  bzero(newkey, keylen);
  char newbuf[len];
  bzero(newbuf, len);
  strcpy(newbuf, value.c_str());
  strcpy(newkey, key.c_str());

  redisReply *replySet;
  replySet = (redisReply *)redisCommand(c,"SET \"disk:%s\" \"\'%s\'\"", newkey, newbuf);
  int replen = strlen(replySet->str);
  if(replen > 0)
  {
    char * newrep;
    newrep = (char *)malloc(sizeof(char) *replen);
    bzero(newrep, replen);
    strcpy(newrep, replySet->str);
    freeReplyObject(replySet);
    printf("newrep: %s\n", newrep);

    redisReply * persistReply;
    if(timeout <= 0)
    {
      persistReply = (redisReply *)redisCommand(c, "EXPIRE \"disk:%s\" %d", newkey, 200);
    }
    else
    {
      persistReply = (redisReply *)redisCommand(c, "EXPIRE \"disk:%s\" %d", newkey, timeout);
    }
    freeReplyObject(persistReply);

    redisReply * addToSet;
    addToSet = (redisReply *)redisCommand(c, "SADD %s \"disk:%s\"", setName, newkey);
    freeReplyObject(addToSet);

    redisReply * expireSet;
    expireSet = (redisReply *)redisCommand(c, "EXPIRE %s %d", setName, timeout);


    return (char *)newrep;
  }
  
  printf("no reply to set\n");
  return NULL;
}

int redis_SET(string key, string value)
{
  if(DEBUG) printf("made it to redis_SET with strings\n");
  unsigned long long start, stop;
  char setNameDisk[10];
  bzero(setNameDisk, 10);
  strcpy(setNameDisk, "disk");
  int setTimeout = 30;
  char localhost[11];
  bzero(localhost, 11);
  strcpy(localhost, "127.0.0.1");
  cclock(start);
  struct timeval timeout;
  timeout.tv_sec = 10;
  timeout.tv_usec = 500000;
  int outcome = -1;
  char * infoReply = NULL;
  char * setReply = NULL;
  FILE * serversFile;
  char myServers[30];
  bzero(myServers, 30);
  strcpy(myServers, "myServers");
  serversFile = fopen(myServers, "r");
  if(serversFile == NULL){
    redisContext * dc;
    
    if((dc = redis_initiate(localhost, 1055)) != NULL)
    {
      /* this is the only one working, so send to it */
      infoReply = redis_INFO(dc);      
      double size = info_translate(infoReply,localhost);
      printf("Info: %4.4f\n", size);
      setReply = redis_SET(dc, key, value, setNameDisk, setTimeout);
      redisFree(dc);
      outcome = 0;
    } else outcome = 1;
  }
  else
  {
    char inString[100];
    char * line = NULL;
    char bestString[100];
    bzero(bestString, 100);
    int bestPort = 0;
    size_t len = 0;
    double mem_size = 5;
    ssize_t read;
    struct m_group tempMG;
    bool first = true;
    while((read = getline(&line, &len, serversFile)) != -1) {
      bzero(inString, 100);
      char * pchi = strstr(line, ":");
      strncpy(inString, line, pchi - line);
      int Rport = atoi(pchi+1);
      redisContext * dc;
      dc = redis_initiate(inString, Rport);
      if(dc == NULL)
      {
        continue;
      }
      else
      {
        infoReply = redis_INFO(dc);
        double size = info_translate(infoReply, inString);
        if(DEBUG) printf("Info: %4.4f\n", size);
        if(size < mem_size)
        {
          mem_size = size;
          bzero(bestString, 100);
          strcpy(bestString, inString);
          bestPort = Rport;
        }
        
        /* parse info and record # keys.  If the most space so far, keep servername. */
        redisFree(dc);
      }
    }

    if(bestString[0] == 0) outcome = 1;
    else
    {
      redisContext *c;
      c = redis_initiate(bestString, bestPort);
      if(c != NULL)
      {
        setReply = redis_SET(c, key, value, setNameDisk, setTimeout);
        outcome = 0;
      }
    }

    fclose(serversFile);
  }

  if(outcome < 0) outcome = 1;

  printf("after sent reply\n");
	cclock(stop);
	double currtime = (double)( (double)(stop - start) / (double)C_CLOCKS_PER_SEC);
	//printf("time to set %s to %s: %4.2f\n", key.c_str(), value.c_str(), currtime);
  if(DEBUG) printf("time to set %s: %4.2f\n", key.c_str(), currtime);
  if(setReply != NULL)
  {
	  if(DEBUG) printf("result of set %s: %s\n", key.c_str(), setReply);
    free(setReply);
  }
  
  if(infoReply != NULL) free(infoReply);

  return outcome;
}

char * redis_GET(redisContext *c, char * key, char * setName, int myTimeout, bool remove)
{
  if(DEBUG) printf("entering redis_GET with context\n");
  redisReply * getReply = (redisReply *)redisCommand(c, "GET \"disk:%s\"", key);
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

  if(remove)
  {
    printf("remove is %d\n", (int) remove);
    int delstat = redis_DELETE(c, key);
    int stat = redis_SREM(c, setName, key);
  }
  else
  {
    redisReply * persistReply;
    if(myTimeout <= 0)
    {
      persistReply = (redisReply *)redisCommand(c, "PERSIST \"disk:%s\"", key);
    }
    else
    {
      persistReply = (redisReply *)redisCommand(c, "EXPIRE \"disk:%s\" %d", key, myTimeout);
    }
    freeReplyObject(persistReply);
  }
  
  char * rednit = (char *)malloc(sizeof(char) * length);
  bzero(rednit, length);
  strncpy(rednit, getReply->str + 2, length - 4);
  freeReplyObject(getReply);
  return rednit;
}

char * redis_GET(char * key)
{
  unsigned long long start, stop;
  unsigned int len = sizeof(key) + 1;
  char newkey[len];
  char * newbuf = NULL;
  bzero(newkey, len);
  strcpy(newkey, key);
  printf("strpcy empty\n");
  char localhost[11];
  bzero(localhost, 11);
  strcpy(localhost, "127.0.0.1");
  char setName[10];
  bzero(setName, 10);
  strcpy(setName, "disk");
  int setTimeout = 3600;
  bool remove = false;
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
      getReply = redis_GET(dc, newkey, setName, setTimeout, remove);
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
    ssize_t read;
    bool first = true;
    while((read = getline(&line, &len, serversFile)) != -1) {
      bzero(inString, 100);
      char * pchi = strstr(line, ":");
      strncpy(inString, line, pchi - line);
      int Rport = atoi(pchi+1);
      redisContext * dc;
      dc = redis_initiate(inString, Rport);
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

        getReply = redis_GET(dc, newkey, setName, setTimeout, remove);
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
  else printf("data not available\n");
  //printf("result of get %s: %s\n", newkey, newbuf);
  return newbuf;
}

int redis_SETQ(string key, string value, char * redis_server, int redis_port)
{
  if(redis_port == 0) return redis_SET(key, value);
  redisContext * dc;
  char * infoReply = NULL;
  char * setReply = NULL;
  char setName[10];
  bzero(setName, 10);
  strcpy(setName, "queries");
  if((dc = redis_initiate(redis_server, redis_port)) != NULL)
  {
    infoReply = redis_INFO(dc);
    double size = info_translate(infoReply, redis_server);
    if(DEBUG) printf("Info: %4.4f\n", size);
    setReply = redis_SET(dc, key, value, setName, 30);
    redisFree(dc);
    free(infoReply);
    free(setReply);
  }

  return 1;
}

char * redis_SRANDOM(char * redis_server, int redis_port)
{
  redisContext * dc;
  char * setMem = NULL;
  char setName[10];
  bzero(setName, 10);
  strcpy(setName, "queries");
  if((dc = redis_initiate(redis_server, redis_port)) != NULL)
  {
    redisReply * replyAll;
    printf("Before requesting SRANDMEMBER %s\n", setName);
    replyAll = (redisReply *)redisCommand(dc, "SRANDMEMBER %s", setName);
    
    printf("After requesting SMEMBERS %s\n", setName);
    
    if(replyAll->type == REDIS_REPLY_NIL)
    {
      freeReplyObject(replyAll);
      return NULL;
    }

    int len = strlen(replyAll->str);
    if(len > 0){
      setMem = (char *)malloc(sizeof(char) *(len+1));
      bzero(setMem, len+1);
      strncpy(setMem, replyAll->str, len);
    }

    freeReplyObject(replyAll);
    redisFree(dc);
  }

  return setMem;
}

char * redis_GETQ(char * key, char * redis_server, int redis_port, bool remove)
{
  if(key == NULL || strlen(key) <= 0) return NULL;
  if(redis_port == 0) return redis_GET(key);
  redisContext * dc;
  char * infoReply = NULL;
  char * setReply = NULL;
  char setName[10];
  bzero(setName, 10);
  strcpy(setName, "queries");
  if((dc = redis_initiate(redis_server, redis_port)) != NULL)
  {
    infoReply = redis_INFO(dc);
    double size = info_translate(infoReply, redis_server);
    printf("GetInfo: %4.4f\n", size);
    setReply = redis_GET(dc, key, setName, 3600, remove);
    redisFree(dc);
    free(infoReply);
  }

  return setReply;
}

struct myKV getKV(int acknum, int seqnum, vector<struct myKV> * allV)
{
  if(DEBUG) printf("Made it to getKV\n");
  if(DEBUG) printf("acknum %d seqnum %d size %d\n", acknum, seqnum, allV->size());
	int c = 0;
	for(unsigned i=0; i < allV->size(); i++)
	{
    if(DEBUG) printf("ack %d seq %d\n", allV->at(i).acknum, allV->at(i).seqnum);
		if(allV->at(i).acknum == acknum)
		{       
			c = 1;
      if(DEBUG) printf("gMatch 1\n");
			if((unsigned int) allV->at(i).seqnum < (unsigned int) seqnum) allV->at(i).seqnum = seqnum;
		}
		else if(allV->at(i).acknum == seqnum)
		{       
			c = 1;
      if(DEBUG) printf("gMatch 2\n");
			if((unsigned int) allV->at(i).seqnum < (unsigned int) acknum) allV->at(i).seqnum = acknum;
		}
		else if(allV->at(i).seqnum == acknum)
		{
			c = 1;
      if(DEBUG) printf("gMatch3\n");
			if((unsigned int) allV->at(i).acknum < (unsigned int) seqnum) allV->at(i).acknum = seqnum;
		}
		else if(allV->at(i).seqnum == seqnum)
		{
			c = 1;
      if(DEBUG) printf("gMatch4\n");
			if((unsigned int) allV->at(i).acknum < (unsigned int) acknum) allV->at(i).acknum = acknum;
		}
    else if(allV->at(i).seqnum+1 == seqnum)
    {
      c = 1;
      if(DEBUG) printf("gMatch 5\n");
      if((unsigned int) allV->at(i).acknum < (unsigned int) acknum) allV->at(i).acknum = acknum;
      allV->at(i).seqnum = seqnum;
    }
    else if(allV->at(i).acknum+1 == acknum)
    {
      c = 1;
      if(DEBUG) printf("gMatch 6\n");
      if((unsigned int) allV->at(i).seqnum < (unsigned int) seqnum) allV->at(i).seqnum = seqnum;
      allV->at(i).acknum = acknum;
    }
    else if(allV->at(i).seqnum+1 == acknum)
    {
      c = 1;
      if(DEBUG) printf("gMatch 7\n");
      if((unsigned int) allV->at(i).acknum < (unsigned int) seqnum) allV->at(i).acknum = seqnum;
      allV->at(i).seqnum = acknum;
    }
    else if(allV->at(i).acknum+1 == seqnum)
    {
      c = 1;
      if(DEBUG) printf("gMatch 8\n");
      if((unsigned int) allV->at(i).seqnum < (unsigned int) acknum) allV->at(i).seqnum = acknum;
      allV->at(i).acknum = seqnum;
    }

		if(c == 1)
		{
			return allV->at(i);
		}
	}

	struct myKV tempKV;
	tempKV.acknum = 0;
	tempKV.seqnum = 0;
	tempKV.trans = 0;
    return tempKV;
}

int updateKV(int acknum, int seqnum, vector<struct myKV> * allV, char * payload)
{
  if(DEBUG) printf("Made it to updateKV; allV->size is %d\n", allV->size());
  if(DEBUG) printf("acknum is %d, seqnum is %d\n", acknum, seqnum);
  //if(DEBUG) printf("data: %s\n", payload);
	int c = 0;
	for(unsigned i=0; i < allV->size(); i++)
	{
    //printf("UpdateKV i is %d, ack is %d, seq is %d, data %s data\n", i,allV->at(i).acknum, allV->at(i).seqnum, allV->at(i).key.c_str());
		if(allV->at(i).acknum == acknum)
		{
      if(DEBUG) printf("match1\n");
			c = 1;
			if((unsigned int) allV->at(i).seqnum < (unsigned int) seqnum) allV->at(i).seqnum = seqnum;
		}
		else if(allV->at(i).acknum == seqnum)
		{
      if(DEBUG) printf("match2\n");
			c = 1;
			if((unsigned int) allV->at(i).seqnum < (unsigned int) acknum) allV->at(i).seqnum = acknum;
		}
		else if(allV->at(i).seqnum == acknum)
		{
      if(DEBUG) printf("match3\n");  //normally this one
			c = 1;
			if((unsigned int) allV->at(i).acknum < (unsigned int) seqnum) 
      {
        if(DEBUG) printf("changing acknum 1\n");
        allV->at(i).acknum = seqnum;
      }
		}
		else if(allV->at(i).seqnum == seqnum)
		{
      if(DEBUG) printf("match4\n");
			c = 1;
			if((unsigned int) allV->at(i).acknum < (unsigned int) acknum) allV->at(i).acknum = acknum;
		}

		if(c == 1)
		{
			allV->at(i).value+=payload;
      if(DEBUG) printf("current size is %d\n", allV->at(i).value.length());
			return i;
		}
	}

	return -1;
}

/* seq or ack match */
int setTrans(int acknum, int seqnum, vector<struct myKV> * allV, bool value)
{
  if(DEBUG) printf("Made it to setTrans\n");
	int c = -1;
	for(unsigned i=0; i < allV->size(); i++)
	{
		if(allV->at(i).acknum == acknum)
		{
			c = 1;
			if((unsigned int)allV->at(i).seqnum < (unsigned int) seqnum) allV->at(i).seqnum = seqnum;
		}
		else if(allV->at(i).acknum == seqnum)
		{
			c = 1;
			if((unsigned int) allV->at(i).seqnum < (unsigned int) acknum) allV->at(i).seqnum = acknum;
		}
		else if(allV->at(i).seqnum == acknum)
		{
			c = 1;
			if((unsigned int) allV->at(i).acknum < (unsigned int) seqnum) allV->at(i).acknum = seqnum;
		}
		else if(allV->at(i).seqnum == seqnum)
		{
			c = 1;
			if((unsigned int) allV->at(i).acknum < (unsigned int) acknum) allV->at(i).acknum = acknum;
		}

		if(c == 1)
		{
			allV->at(i).trans = true;
			return i;
		}
	}
	
	return c;
}

int eraseKV(int acknum, int seqnum, vector<struct myKV> * allV)
{
  if(DEBUG) printf("Made it to eraseKV\n");
	int c = 0;
        for(unsigned i=0; i < allV->size(); i++)
        {
                if(allV->at(i).acknum == acknum || allV->at(i).seqnum == seqnum || allV->at(i).acknum == seqnum || allV->at(i).seqnum == acknum)
                {
			allV->erase(allV->begin() + i);
			return 1;
		}
		c++;
	}

	return 0;
}

/* IP checksum */
unsigned short checksum(unsigned short *buff, int len){
  if(DEBUG) printf("Made it to checksum\n");
	int nleft = len;
  unsigned short * w = buff;
	int sum = 0;
  unsigned short answer = 0;
  //unsigned short word16;
  //unsigned short i;

  /*for(i=0; i<nleft;i=i+2){
    word16 = ((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
    sum = sum + (unsigned int) word16;
  }*/

	while(nleft>1){
		sum += * w++;
    //sum += *w;
    //w++;
		nleft-=2;
	}

	if(nleft == 1){
    *(unsigned char *)(&answer) = *(unsigned char *)w;
    sum += answer;
  }
	/*
	*(unsigned char *)(&answer)=*(unsigned char *)w;
		sum+=answer;
	}*/

	sum = (sum>>16)+(sum & 0xffff);
  sum += (sum>>16);
  answer = ~sum;

	return answer;
}

void changePacket(struct tcphdr * tcp, struct iphdr * iph, uint32_t payload_length, struct iphdr * autoIP_ACK, struct tcphdr * autoTCP_ACK)
{
  if(DEBUG) printf("Made it to changePacket\n");
	autoTCP_ACK->seq = tcp->ack_seq;
	autoTCP_ACK->ack_seq = tcp->seq + (uint32_t) payload_length;
	
	autoTCP_ACK->source = tcp->dest;
	autoTCP_ACK->dest = tcp->source;
	
	autoIP_ACK->saddr = iph->daddr;
	autoIP_ACK->daddr = iph->saddr;
	
	uint8_t tempttl = iph->ttl<<1;
	autoIP_ACK->ttl = tempttl;
	autoIP_ACK->id = iph->id;
	
	// add timestamp info
	const u_char *cp = (const u_char *)tcp + sizeof(*tcp);
	int hlen = tcp->doff*4;
	hlen-=sizeof(struct tcphdr);
	if(hlen > 0)
	{
		while(--hlen >= 0) {
			switch(*cp++) {
				case TCPOPT_EOL:
					break;
				case TCPOPT_NOP:
					break;
				case TCPOPT_TIMESTAMP:
				{
					//fix timestamp
					(void)printf("timestamp %lu %lu", cp[1]<<24 | cp[2] << 16 | cp[3] << 8 | cp[4],
						cp[5] << 24 | cp[6] << 16 | cp[7] << 8 | cp[8]);
					if (*cp != 10)
						cp += 9;
					hlen -= 9;
					break;
				}
				default:
					int i = *cp;
					for(int hen = hlen; hen > 0; hen--)
					{
						i = *cp++ -2;
						(void) printf("%02x", *cp++);
					}
					break;
			}
		}
	}

	uint16_t checktcp = 0;
	autoTCP_ACK->check = checktcp;
	checktcp = get_tcp_checksum(autoIP_ACK, autoTCP_ACK);
	autoTCP_ACK->check = checktcp;
	checktcp = 0;
	autoIP_ACK->check = checktcp;
	checktcp = checksum((unsigned short*)autoIP_ACK, autoIP_ACK->ihl<<2);
	autoIP_ACK->check = checktcp;
}

void mitmCliToM(struct tcphdr * tcp, struct iphdr * iph, uint32_t maddr, uint16_t mport, char * data, int data_len)
{
  if(DEBUG) printf("Made it to mitmCliToM\n");
  if(data_len > 0)
  {
    //for(int i = 0; i < data_len; i++){
    //  unsigned int c = data[i];
      //printf("THIS IS DATA %s THIS IS DATA\n", data);
    //}
    //data[0] = 'J';
  }
	tcp->dest = mport;
  if(DEBUG) printf("tcp->dest %d, mport %d\n", tcp->dest, mport);
  if(DEBUG) printf("reverse dest %d, mport %d\n", htons(tcp->dest), htons(mport));
  struct hostent *hp = gethostbyname("localhost");
  if(hp != 0) {
    //printf("unknown localhost\n");
    bcopy((void *)hp->h_addr, (void *)&iph->daddr, hp->h_length);
  }
  else
  {
    printf("unknown localhost\n");
  }
	//iph->daddr = iph->saddr;
  iph->ttl = iph->ttl+ 3; 
	
	uint16_t checktcp = 0;
	tcp->check = checktcp;
	checktcp = get_tcp_checksum(iph, tcp);
	tcp->check = checktcp;
	uint16_t checkip = 0;
	iph->check = checkip;
	checkip = checksum((unsigned short*)iph, iph->ihl<<2);
	iph->check = checkip;
  printf("Exiting mitmCliToM\n");
}

void mitmMToCli(struct tcphdr * tcp, struct iphdr * iph, uint32_t srvaddr, uint16_t srvport, char * data, int data_len)
{
  if(DEBUG) printf("Made it to mitmMToCli\n");
	tcp->source = srvport;
	iph->saddr = srvaddr;

	uint16_t checktcp = 0;
	tcp->check = checktcp;
	checktcp = get_tcp_checksum(iph, tcp);
	tcp->check = checktcp;
	uint16_t checkip = 0;
	iph->check = checkip;
	checkip = checksum((unsigned short*)iph, iph->ihl<<2);
	iph->check = checkip;
  printf("Exiting mitmMToCli\n");
}

void changeToAck(struct iphdr * iph, int total_length, tcphdr * tcp, char * payload, int payload_length, struct myKV storeKV)
{
  // things to change: tcp-> options timestamp
  tcp->fin = 0;
  tcp->ack = 1;
  tcp->rst = 0;
  tcp->psh = 0;
  tcp->syn = 0;
  tcp->urg = 0;

  if(tcp->seq == storeKV.seqnum)
  {
    tcp->ack_seq = htonl(storeKV.acknum + 1);
  }
  else
  {
    if(tcp->seq == storeKV.acknum)
    {
      tcp->ack_seq = htonl(storeKV.acknum + 1);
    }
  }

  iph->tot_len = ntohs(total_length - payload_length);

  uint16_t checktcp = 0;
  tcp->check = checktcp;
  checktcp = get_tcp_checksum(iph, tcp);
  tcp->check = checktcp;
  uint16_t checkip = 0;
  iph->check = checkip;
  checkip = checksum((unsigned short*)iph, iph->ihl<<2);
  iph->check = checkip;
  printf("Exiting changeToAck\n");
}

static void die(struct ipq_handle *h)
{
    if(DEBUG) printf("Dying! Help!");
    ipq_perror("passer");
    ipq_destroy_handle(h);
    exit(1);
}

void readDirections(vector<struct m_group> * allMGs)
{
  //vector<struct m_group> * allMGs = new vector<struct m_group>();
  FILE * beltA;
  char fileName[20];
  bzero(fileName, 20);
  strcpy(fileName, "borg.cfg");
  beltA = fopen(fileName, "r");
  if(beltA == NULL) exit(1);
  char inString[100];
  char * line = NULL;
  char in2String[100];
  size_t len = 0;
  bool dst, src, port, addr, data, mangle, param, mode;
  ssize_t read;
  struct m_group tempMG;  
  bool first = true;

  while((read = getline(&line, &len, beltA)) != -1) {
    bzero(inString, 100);
    strcpy(inString, line);
    printf("read %s\n", inString);
    char * b = strstr(inString, ":");
    if(b == NULL)
    {
      // start new command
      if(first) first = false;
      else
      {
        printf("before commit\n");
        allMGs->push_back(tempMG);
        printf("after commit\n");
      }

      tempMG.dport = 0;
      tempMG.sport = 0;
      tempMG.dst_addr = 0;
      tempMG.src_addr = 0;
      bzero(tempMG.data_range, 50);
      bzero(tempMG.mangler, 50);
      bzero(tempMG.parameters, 100);
    }
    else
    {
      bzero(in2String, 100);
      dst = false;
      src = false;
      port = false;
      addr = false;
      data = false;
      mangle = false;
      param = false;
      mode = false;
      char * n = strstr(inString, "\n");
      int length = n - b - 2;
      strncpy(in2String, b + 2, length);
      printf("length %d, string %s\n", length, in2String);
      //in2String[sizeof(in2String)-2] = 0;
      if(strstr(inString, "DST") > 0) dst = true;
      if(strstr(inString, "SRC") > 0) src = true;
      if(strstr(inString, "ADDR") > 0) addr = true;
      if(strstr(inString, "PORT") > 0) port = true;
      if(strstr(inString, "DATA") > 0) data = true;
      if(strstr(inString, "MANGLE") > 0) mangle = true;
      if(strstr(inString, "PARAM") > 0) param = true;
      if(strstr(inString, "MODE") > 0) mode = true;
      if(dst && port) tempMG.dport = htons(atoi(in2String));
      if(src && port) tempMG.sport = htons(atoi(in2String));
      if(addr)
      {
        struct hostent *hp = gethostbyname(in2String);
        if(hp != 0) {
          printf("Got hostname\n");
          if(dst) bcopy((void *)hp->h_addr, (void *)&tempMG.dst_addr, hp->h_length);
          if(src) bcopy((void *)hp->h_addr, (void *)&tempMG.src_addr, hp->h_length);
        }
        else
        {
          printf("unknown host: %s\n", in2String);
        }
      }
      if(data) strncpy(tempMG.data_range, in2String, 50);
      if(mangle && !param) strncpy(tempMG.mangler, in2String, 50);
      if(mangle && param) strncpy(tempMG.parameters, in2String, 100);
      if(mode) tempMG.mode = atoi(in2String);
    }
  }

  allMGs->push_back(tempMG);

  fclose(beltA);

  unsigned i = 0;
  for(i = 0; i < allMGs->size(); i++)
  {
    printf("%d %d %d %d %s %s %s\n", allMGs->at(i).dport, allMGs->at(i).sport, allMGs->at(i).dst_addr, allMGs->at(i).src_addr, allMGs->at(i).data_range, allMGs->at(i).mangler, allMGs->at(i).parameters);
  }
}

int collectDataSrv(struct ipq_handle *h, ipq_packet_msg_t * m, struct iphdr * iph, struct tcphdr * tcp, char * payload, int total_length, int payload_length, char * parameters)
{
  char * pchpara = NULL;
  char redis_server[100];
  bzero(redis_server, 100);
  int redis_port = 0;
  int delay = 1;

  pchpara = strstr(parameters, ",");
  if(pchpara != NULL)
  {
    strncpy(redis_server, parameters, pchpara - parameters);
    //printf("redis_server is %s\n", redis_server);
    redis_port = atoi(pchpara+1);
    char * npchpara = strstr(pchpara+1, ",");
    if(npchpara != NULL)
    {
      delay = atoi(npchpara+1);
    }
    else
    {
      delay = 1;
    }
  }
  else
  {
    strcpy(redis_server, "localhost");
    redis_port = 0;
    delay = 1;
  }

  int srv_port = 1064;
  uint32_t srvaddr;
  uint16_t srvport = htons(srv_port);
  int status;

  if(!(tcp->fin || payload_length > 0))
  {
    // If the packet is not a closing packet or it doesn't have data, we don't care.
    if(DEBUG) printf("1We didn't care about this one.\n");
    status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL);
    return 1;
  }
  else if(tcp->fin)
  {
    // If the packet was sent from the server, we have finished receiving
    // data for this connection and need to send it to Redis.
    // So we get the data from our data structure and commit this data to Redis.
    printf("Fin was sent from server.  Payload length %d. Committing data.\n", payload_length);
    struct myKV tempKV = getKV(ntohl(tcp->seq), ntohl(tcp->ack_seq), allKVs);
    printf("1\n");
    //if(tempKV.acknum != 0 && tempKV.seqnum != 0)
    //{
      printf("this exists %d %d\n", tempKV.key.length(), tempKV.value.length());
      if(tempKV.key.length() > 0 && tempKV.value.length() > 0)
      {
        printf("2\n");
        //commit saved key, value to Redis
        status = redis_SETQ(tempKV.key, tempKV.value, redis_server, redis_port);
        
        printf("4 committed key %s\n", tempKV.key.c_str());
        printf("key %s, value %s", tempKV.key.c_str(), tempKV.value.c_str());


      }

      eraseKV(ntohl(tcp->seq), ntohl(tcp->ack_seq), allKVs);
    //}

    // But then we allow the packet to go through.
    status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, m->data_len, m->payload);
    return 1;
  }
  else if(payload_length > 0)
  {
    //printf("More data from server\n");
    // We assume that the data is from the server.  In this case, we want to add data
    // to the value of a pre-existing entry in the data store.
    char prepPayload[payload_length+1];
    bzero(prepPayload, payload_length+1);
    strncpy(prepPayload, payload, payload_length);
    int pos = updateKV(ntohl(tcp->ack_seq),ntohl( tcp->seq), allKVs, prepPayload);
    if(pos == -1)
    {
      if(DEBUG) printf("No Such Entry\n");
      // If there is no such entry, we will accept the packet
      status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL);
      return 1;
    }
    else
    {
      if(DEBUG) printf("Found entry\n");
      if(delay == 0)
      {
        status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL);
        return 1;
      }

      struct myKV storeKV = getKV(ntohl(tcp->seq),ntohl( tcp->ack_seq), allKVs);
      // If we found an entry and added new data, then we need to send it on to the client if 
      // the connection is still open.
      if(!storeKV.trans)
      {
        //printf("Accepting data packet\n");
        status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL);
        return 1;
      }
      else
      {
        // And if the client is trying to close the socket, drop the packet.
        printf("Dropping data packet so it does not go to client\n");
        //changePacket(tcp,iph, payload_length, autoIP_ACK, autoTCP_ACK);
        //status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, autoACK->data_len, autoACK->payloa        d);
        status = ipq_set_verdict(h, m->packet_id, NF_DROP, 0, NULL);
        return 2;
      }
    }
  }

  return 0;
}

int collectDataCli(struct ipq_handle * h, ipq_packet_msg_t * m, struct iphdr * iph, struct tcphdr * tcp, char * payload, int total_length, int payload_length, char * parameters){
  char * pchpara = NULL;
  char redis_server[100];
  bzero(redis_server, 100);
  int redis_port = 0;
  int delay = 1;

  pchpara = strstr(parameters, ",");
  if(pchpara != NULL)
  {
    strncpy(redis_server, parameters, pchpara - parameters);
    //printf("redis_server is %s\n", redis_server);
    redis_port = atoi(pchpara+1);
    char * npchpara = strstr(pchpara+1, ",");
    if(npchpara != NULL)
    {
      delay = atoi(npchpara+1);
    }
    else
    {
      delay = 1;
    }
  }
  else
  {
    strcpy(redis_server, "localhost");
    redis_port = 0;
    delay = 1;
  } 

  int srv_port = 1064;
  //vector<struct myKV> * allKVs = new vector<struct myKV>();
  uint16_t srvport = htons(srv_port);
  bool exitBool = false;
  ipq_packet_msg_t *autoACK = new ipq_packet_msg_t();
  struct iphdr *autoIP_ACK;
  struct tcphdr *autoTCP_ACK;
  redisContext * c;
  int status;
  // Then we are listening for data packets and logging their data;
  // We are also listening for fin packets so that we can stop ones from the client
  // and commit the data so far received if from the server, then accept.
  //if(DEBUG) printf("Mode 1, holding all cli fins and collecting data\n");
  
  if(!(tcp->fin || payload_length > 0))
  {
    // If the packet is not a closing packet or it doesn't have data, we don't care.
    if(DEBUG) printf("1We didn't care about this one.\n");
    status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL);
    return 1;
  }
  else if(tcp->fin)
  {
    if(DEBUG) printf("This was a fin packet!");
    // If delay is set, we want to stop it from being sent.
    // We are keeping track of all data packets from the client and the responses
    // to that specific packet from the server.  This function marks the structure
    // in which we keep that data that a fin packet has been seen from the client 
    // for this message.
    int outcome = -1;

    if(delay == 1)
    {
      outcome = setTrans(ntohl(tcp->seq), ntohl(tcp->ack_seq), allKVs, true);
    }

    if(outcome == -1)
    {
      // this connection does not exist.
      if(DEBUG) printf("Fin from client accepted\n");
      status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL);
      return 2;
    }
    else
    {
      // And then we modify the packet to ack the latest packet
      printf("Fin from client modified to ack\n");
      struct myKV storeKV = getKV(ntohl(tcp->seq), ntohl(tcp->ack_seq), allKVs);
      changeToAck(iph, total_length, tcp, payload, payload_length, storeKV);
      status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, m->data_len, m->payload);
      return 1;
    }
  }
  else if( payload_length > 0)
  {
    printf("Data to record\n");
    // If the data comes from the client, we need to start a new entry in our data store.
    char newqu[payload_length+1];
    bzero(newqu, payload_length+1);
    strncpy(newqu, payload, payload_length);
    printf("New query from client: %s\n", newqu);
    struct myKV storeKV = getKV(ntohl(tcp->seq), ntohl(tcp->ack_seq), allKVs);
    if(storeKV.acknum != 0 && storeKV.seqnum != 0)
    {
      printf("found prior entry\n");
      if(storeKV.key.length() > 0 && storeKV.value.length() > 0)
      {
        printf("and it had data\n");
      	//commit any previous saved key,value pair to Redis
      	int stat = redis_SETQ(storeKV.key, storeKV.value, redis_server, redis_port);
      	printf("key2 %s %s\n", storeKV.key.c_str(), storeKV.value.c_str());


      }

      printf("did it work? keylength %d valuelength %d\n", storeKV.key.length(), storeKV.value.length());
      //printf("key2 %s value2 %s", storeKV.key.c_str(), storeKV.value.c_str());
      int confirm = eraseKV(ntohl(tcp->seq), ntohl(tcp->ack_seq), allKVs);
    }
  
    struct myKV tempKV;
    tempKV.acknum = ntohl(tcp->ack_seq);
    tempKV.seqnum = ntohl(tcp->seq);
    tempKV.value = "";
    char prepPayload[payload_length+1];
    bzero(prepPayload, payload_length+1);
    strncpy(prepPayload, payload, payload_length);
    tempKV.key.assign(prepPayload);
    printf("payload %s saved\n", tempKV.key.c_str());
    allKVs->push_back(tempKV);
    printf("allKVs.size is %d\n", allKVs->size());
    status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL);
    return 1;
  }

  return 0;
}

int getRR(char * fileName, unsigned long long curr_request, double percentage, char * redis_server, int redis_port, bool forced)
{
  if(DEBUG) printf("Got to getRR\n");
	unsigned long long last_request = 0;
	double number_of_requests = 0.0;
	double average_time_between_requests = 0.0;
	bool last = false, number = false, avg = false;
	int outcome = 0;

	FILE * allInfo;
	allInfo = fopen(fileName, "r");
	if(allInfo != NULL)
	{
	  char inString[100];
	  char * line = NULL;
	  size_t len = 0;
	  ssize_t read;

	  while((read = getline(&line, &len, allInfo)) != -1) {
	    bzero(inString, 100);
	    strcpy(inString, line);
	    if(DEBUG) printf("read %s\n", inString);
	    char * b = strstr(inString, ":");
	    char * pEnd;
	    if(!last && inString[0] == 'l')
	    {
	      last_request = strtoull(b+1, &pEnd, 10);
	      last = true;
	    }
	    else {
	      if(!number && inString[0] == 'n')
	      {
		      number_of_requests = atof(b+1);
		      number = true;
	      }
	      else {
	        if(!avg && inString[0] == 'a')
		      {
		        average_time_between_requests = atof(b+1);
		        avg = true;
		      }
	      }
	    }
	  }

	  fclose(allInfo);
	}

	double time_between = 0.0;
	double new_average = 0.0;
	
	if(!last)
	{
	  last_request = curr_request;
	  last = true;
	}
	
	if(!number)
	{
	  number_of_requests = 2;
	  number = true;
	}

	time_between = (double) ( (double)(curr_request - last_request) / (double)C_CLOCKS_PER_SEC);
	last_request = curr_request;

	if(time_between >= 0.0)
	{
	  if(avg)
	  {
	    new_average = (average_time_between_requests * number_of_requests) + time_between;
	    new_average = new_average / (number_of_requests + 1);
	    number_of_requests += 1;
	  }
	  else
	  {
	    new_average = time_between;
	    number_of_requests = 2;
	  }

	  avg = true;

	  double average_request_rate = 1.0 / new_average;
	  double current_request_rate = 1.0 / time_between;

	  double r = ((double) rand() / (double) RAND_MAX);
	  
    outcome = 0; // continue monitoring
    if(percentage > 0.0)
    {
      if(r < percentage)
      {
	      if(average_request_rate > current_request_rate || forced)
	      {
		      // we have time to record or replay
		      outcome = 1;
        }
	    }
	    else
	    {
        if(average_request_rate > current_request_rate || forced)
        {
          // sample REDIS to see if a key exists and write the data to a temporary file
          char * freekey = NULL;
          char * freeans = NULL;
          int s = 0;
          do{
            s = redis_SCARD(redis_server, redis_port);
            printf("S cardinality is %d\n", s);
            if(s > 0)
            {
              if(freekey != NULL) free(freekey);
              freekey = redis_SRANDOM(redis_server, redis_port);
              if(freekey != NULL){
                char * pch = NULL;
                char * ned = &freekey[strlen(freekey)];
                pch = strstr(freekey, ":");
                int len = (int) (ned - pch);
                char rkey[len+1];
                bzero(rkey, len+1);
                strncpy(rkey, pch+1, len-2);
                freeans = redis_GETQ(rkey, redis_server, redis_port, true);
                printf("in while loop %s %s %d\n", freekey, rkey, strlen(freeans));
              }
            }
          } while(freeans == NULL && s > 1 && freekey != NULL);

          if(freeans != NULL && freekey != NULL)
          {
            FILE * temp;
            temp = fopen("keys", "a");
            if(temp != NULL)
            {
              char * ptem = strstr(freekey, ":");
              char inStr[strlen(ptem)];
              bzero(inStr, strlen(ptem));
              strncpy(inStr, ptem+1, strlen(ptem) -2);
              fprintf(temp, "REQUIEM%sREQUIEM\n", inStr);
              fclose(temp);
            }

            FILE * req;
            temp = fopen("values", "a");
            if(temp != NULL)
            {
              fprintf(temp, "REQUIEM%sREQUIEM\n", freeans);
              fclose(temp);
            }

            if(freekey != NULL) free(freekey);
            if(freeans != NULL) free(freeans);
            printf("setting mode to 0\n");            
            outcome = 2;
          }
        }
	    }
    }
	}

  if(avg) printf("%4.4f\n", new_average);

	if(last || avg || number)
	{
	  allInfo = fopen(fileName, "w");
    if(allInfo != NULL)
    {
	    if(last) fprintf(allInfo, "l:%llu\n", last_request);
	    if(number) fprintf(allInfo, "n:%4.4f\n", number_of_requests);
	    if(avg) fprintf(allInfo, "a:%4.4f\n", new_average);
	    fclose(allInfo);
	  }
	}

	return outcome;
}

int monitorCli(struct ipq_handle * h, ipq_packet_msg_t * m, struct iphdr * iph, struct tcphdr * tcp, char * payload, int total_length, int payload_length, char * parameters){
  if(DEBUG) printf("Got to monitorCli\n");
  char * pchpara = NULL;
  char redis_server[100];
  bzero(redis_server, 100);
  int redis_port = 0;
  char fileName[100];
  bzero(fileName, 100);
  double percentage = 0.0;
  unsigned long long timeSoFar;
  bool lastarg = false;
  bool forced = true;

  if(payload_length > 0)
  {
    if(DEBUG) printf("we have payload %s", payload);
    cclock(timeSoFar);

    pchpara = strstr(parameters, ",");
    if(pchpara != NULL)
    {
      percentage = atof(parameters);
      char * pchn = NULL;
      pchn = strstr(pchpara, " ");
      pchpara += 1;
      if(pchpara == pchn)
      {
        pchpara = pchn + 1;
      }

      char * nextchar = NULL;
      nextchar = strstr(pchpara, ",");
      if(nextchar == NULL)
      {
        int len = strlen(parameters);
        nextchar = (char *)&parameters[len];
        lastarg = true;
      }

      strncpy(fileName, pchpara, nextchar - pchpara);
      printf("fileName is %s\n", fileName);

      if(!lastarg)
      {
        char * thirdchar = NULL;
        thirdchar = strstr(nextchar+1, ",");
        pchn = NULL;
        pchn = strstr(nextchar, " ");
        nextchar += 1;
        if(nextchar == pchn)
        {
          printf("found\n");
          nextchar = pchn+1;
        }

        if(thirdchar == NULL)
        {
          int len = strlen(parameters);
          thirdchar = (char *)&parameters[len];
          lastarg = true;
        }

        strncpy(redis_server, nextchar, thirdchar - nextchar);
        printf("redis_server is %s\n", redis_server);

        if(!lastarg)
        {
          thirdchar += 1;
          redis_port = atoi(thirdchar);

          nextchar = NULL;
          nextchar = strstr(thirdchar, ",");
          if(nextchar != NULL)
          {
            int tempInt = atoi(nextchar+1);
            if(tempInt == 0)
            {
              forced = false;
            }
          }
        }
      }
      else
      {
        printf("lastarg");
      }
    }
    else
    {
      strcpy(fileName, "default_out");
      percentage = 0.0;
      bzero(redis_server, 10);
      redis_port = 0;
      forced = true;
    }

    int outcome = getRR(fileName, timeSoFar, percentage, redis_server, redis_port, forced);

    if(outcome == 1)
    {
      // we can record
    }
    else
    {
      if(outcome == 2)
      {
        // we can re-execute
        //printf("finished executing system call\n");
      }
    }
  }

  int status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL);
  return 1;
}

int regurgitate(struct ipq_handle *h, ipq_packet_msg_t * m, struct iphdr * iph,struct tcphdr * tcp, char * payload, int total_length, int payload_length){
  int local_port = 1061;
  int srv_port = 1064;
  int local_bound_port = 1066;
  vector<struct myKV> * allKVs = new vector<struct myKV>();
  uint32_t cliaddr;
  uint32_t srvaddr;
  uint32_t maddr;
  uint16_t cliport;
  uint16_t srvport = htons(srv_port);
  uint16_t mport = htons(local_port);
  uint16_t bndport = htons(local_bound_port);
  if(DEBUG) printf("Mode 2 ready to go\n");
  int status;

  if(mport == tcp->source) //&& (iph->daddr == iph->saddr))
  {
    // This is from the mitm and it is destined locally.
    if(DEBUG) printf("srv to cli from mitmM, ipc: %d, tcpc: %d\n", iph->check, tcp->check);
    mitmMToCli(tcp, iph, srvaddr, srvport, payload, payload_length);
    if(DEBUG) printf("Saddr: %d; sprt %d\n", iph->saddr, htons(tcp->source));
    if(DEBUG) printf("IPc: %d; TCPc: %d\n", iph->check, tcp->check);
  }
  else if(srvport == tcp->dest  && tcp->source != bndport)
  {
    // if the packet is being sent cli to srv port, it goes to mitm.
    if(DEBUG) printf("cli to mitm, ipc: %d, tcpc: %d\n", iph->check, tcp->check);
    mitmCliToM(tcp, iph, maddr, mport, payload, payload_length);
    if(DEBUG) printf("Daddr: %d; Dprt %d\n", iph->daddr, htons(tcp->dest));
    if(DEBUG) printf("IPc: %d; TCPc: %d\n", iph->check, tcp->check);
  }
 
  if(DEBUG) printf("Sending accept\n");
  status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, m->data_len, m->payload);
  printf("Status: %d, data_len: %d, payload: %s\n", status, m->data_len, m->payload);
  return 1;
}

int matches(char * myString, char * regexString)
{
  if(sizeof(regexString) <= 1) return 1;
  return 1;
}

int main(int argc, char **argv)
{
  if(DEBUG) printf("Made it to main");
  //vector<struct myKV> * allKVs = new vector<struct myKV>();
  char modefile[10];
  strcpy(modefile, "mode.cfg");
  int mode;
  bool exitBool = false;
  int status;
  unsigned char buf[BUFSIZE];
  srand(time(NULL));

  // need to read in the rules
  vector<struct m_group> * myRules = new vector<struct m_group>(); 
  readDirections(myRules);

  if(DEBUG) printf("Made it to thread 1\n");
  struct ipq_handle *h;
	h = ipq_create_handle(0, NFPROTO_IPV4);
	if (!h)
		die(h);
	status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
	if (status < 0)
	  die(h);

  int timesFedUp = 0;
			
  if(DEBUG) printf("Setup complete\n");
	do{
		status = ipq_read(h, buf, BUFSIZE, 0);
		if (status < 0)
		{
      printf("Died at top of loop\n");
      timesFedUp++;
      if(timesFedUp > 10) die(h);
     	continue;
		}
    timesFedUp = 0;
	
		switch (ipq_message_type(buf)) {
			case NLMSG_ERROR:
			{
        if(DEBUG) printf("case 1\n");
				fprintf(stderr, "Received error message %d\n",
				ipq_get_msgerr(buf));
				break;
			}
			case IPQM_PACKET: 
			{
        // get mode
        FILE * mfile;
        mfile = fopen(modefile, "r");
        if(mfile == NULL) mode = 0;
        else
        {
          fscanf(mfile, "%d", &mode);
          fclose(mfile);
        }

        if(mode < 0) mode = 0;

        if(DEBUG) printf("case 2, mode %d\n", mode);
				// We received a packet and should decide what to do with it.
				// So first we get the actual IP packet message:
				ipq_packet_msg_t *m = ipq_get_packet(buf);
				struct iphdr *iph = ((struct iphdr *)m->payload);
				
				// Then we get a pointer to the actual TCP packet:
				struct tcphdr *tcp = ((struct tcphdr *) (m->payload + (iph->ihl<<2)));
				
				// And finally, we want a pointer to the data payload itself:
        int total_length = ntohs(iph->tot_len);
        int header_length = (iph->ihl<<2) + (tcp->doff<<2);
  			char * payload = ((char*) (m->payload + header_length));
					
				//It also doesn't hurt to have the length of the payload, since this is variable.
				//u_char flags = tcp->th_flags;
				int payload_length = ntohs(iph->tot_len) - (iph->ihl<<2) - (tcp->doff<<2);

        if(DEBUG) printf("Allocating buffer\n");
        /*if(payload_length > 0)
        {
          printf("We have payload\n");
          for(int i = 0; i < payload_length; i++)
          {
            char c = payload[i];
            printf("%c", c);
          }
          printf("\n");
        }*/

        //if(payload_length > 0) printf("payload length %d\n", payload_length);
        /*char seqbuff[4];
        memcpy(seqbuff, (char *)&(tcp->seq), 4);
        for(int i=0; i< 4; i++) printf("%d ", seqbuff[i]);
        printf("\n");

        memcpy(seqbuff, (char *)&(tcp->ack_seq), 4);
        for(int i=0; i<4; i++) printf("%d ", seqbuff[i]);
        printf("\n");
        */

        if(DEBUG) printf("seq %u ack %u\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));

        // We are checking our checksum function for accuracy here.
        /*unsigned short ccheck = tcp->check;
        tcp->check = 0;
        unsigned short cnew = get_tcp_checksum(iph, tcp);
        printf("old checksum: %d, new checksum %d\n", ccheck, cnew);
        tcp->check = ccheck; 

        unsigned short icheck = iph->check;
        printf("prior icheck: %d\n", icheck);
        iph->check = 0;
        unsigned short inew = checksum((unsigned short *)iph, iph->ihl * 4);
        printf("Old IP checksum: %d, new IP checksum %d\n", icheck, inew);
        printf("in hex: %d %d %d %d\n", (inew>>12), (inew>>8) & 0x000f, (inew>>4)&0x000f, (inew)&0x000f);
        if(inew == icheck)
        {
          printf("iph is working fine\n");
        }
        else
        {
          printf("Problem found\n");
        } 

        iph->check = icheck;
        */

        //if(DEBUG) printf("Source addr: %d; Dest addr %d\n", iph->saddr, iph->daddr);
        if(DEBUG) printf("Source port: %d; Dest port %d\n", htons(tcp->source), htons(tcp->dest));
        //if(DEBUG && payload_length > 0) printf("Data: %s\n", payload);
        unsigned i = 0;

        if(DEBUG) printf("myRules->size() %d\n", myRules->size());
        int status = 0;


        for(i = 0; i < myRules->size(); i++)
        {
          if(DEBUG) printf("Checking rule %d\n", i);
          struct m_group mR = myRules->at(i);
      /*    if(mode == mR.mode) printf("mode match");
          if((mR.dport != 0 && mR.dport == tcp->dest)||mR.dport==0) printf("dport match");
          if((mR.sport != 0 && mR.sport == tcp->source)||mR.sport ==0){
             printf("sport match");
          }
          else
          {
            printf("sport %d tcpsource %d\n", mR.sport, tcp->source);
          }

          if((mR.src_addr != 0 && mR.src_addr == iph->saddr)||mR.src_addr == 0)
          {
            printf("saddr match");
          }
          else
          {
            printf("saddr %d, iph->saddr %d\n", mR.src_addr, iph->saddr);
          }

          if((mR.dst_addr != 0 && mR.dst_addr == iph->daddr)||mR.dst_addr == 0) printf("daddr match");
          if(matches(payload, mR.data_range)) printf("payload match"); */
          
          if((mode == mR.mode) && 
             ((mR.dport != 0 && mR.dport == tcp->dest)|| mR.dport==0)&&
             ((mR.sport != 0 && mR.sport == tcp->source)|| mR.sport ==0) &&
             ((mR.src_addr != 0 && mR.src_addr == iph->saddr)||mR.src_addr == 0) &&
             ((mR.dst_addr != 0 && mR.dst_addr == iph->daddr)||mR.dst_addr == 0) &&
             (matches(payload, mR.data_range)))
          {
            //printf("match occured\n");
            //perform function specifed in mangle with mangle parameters
            if(strstr(mR.mangler, "collectDataSrv"))
            {
               if(DEBUG) printf("collectDataSrv\n");
               status = collectDataSrv(h, m, iph, tcp, payload, total_length, payload_length, mR.parameters);
            }

            if(strstr(mR.mangler, "collectDataCli"))
            {
              if(DEBUG) printf("collectDataCli\n");
              status = collectDataCli(h, m, iph, tcp, payload, total_length, payload_length, mR.parameters);
            }

            if(strstr(mR.mangler, "monitorCli"))
            {
              if(DEBUG) printf("monitorCli");
              status = monitorCli(h, m, iph, tcp, payload, total_length, payload_length, mR.parameters);
            }

            if(status == 0) status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL);
            break;
          }
        }

        if(status == 0){
           status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL);
           if(DEBUG) printf("not covered by circumstances\n");
        }
        break;
  		}
			default:
        if(DEBUG) printf("Unknown message type\n");
	  		fprintf(stderr, "Unknown message type!\n");
				break;
		}
	} while (!exitBool);
	ipq_destroy_handle(h);

  return 0;
}
