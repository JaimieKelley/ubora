#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include "redislib/hiredis.h"
#include <iostream>
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
#include <regex>
#include <signal.h>

#define BUFSIZE 65536
#define MAX_CHARS 536870912
#define MAX_NODES 64

#define C_CLOCKS_PER_SEC 1995000000
#define cclock(X)  {unsigned int hi_chris, lo_chris;__asm__ volatile ("rdtsc" : "=d" (hi_chris)); __asm__ volatile ("rdtsc" : "=a" (lo_chris)); X = hi_chris; X=X<<32 | lo_chris;}

using namespace std;

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

struct metrics
{
  double sampleRate;
  double timeout;
  double timeSinceReplay;
};

struct node{
  int sock;
  char address[100];
  int port;
};

struct storage{
  char address[100];
  int port;
};

class Ubora {
  //global variables
  int Usockets[];
  struct storage ** Ustorage;
  vector<int> allQ;
  struct storage * UCat[];
  struct storage * UBlt[];
  struct storage * UMem[];
  struct storage * UAux[];
  int NodePorts[];
  struct node ** Unodes;
  int numNodes;
  bool regex;
  unsigned long long pitime;
  double sample;
  int policy;
  double timeout;
public:
  /* set up Ubora with list of known nodes, number of nodes, and ports to contact ubora on other nodes, sample rate, and timeout	*/
  void setupUbora(char **, int, int, int, double, double);
  /* set up Tiers: client access tier, business logic, memory, auxiliary, numbers for each */
  void setupTiers(char **, char **, char **, char **, int, int, int, int);
  /* set up Storage nodes to use with Ubora.  List of int nodes already running on int[] ports. */
  void setupStore(char **, int, int[]);
  /* set up Storage nodes on same tier. Regex and single port to look for, and number of nodes to search for */
  void setupStore(char *, int, int);
  /* can be either a regex or a list of int nodes or a set of ports. Broadcast list is for propagation. Returns an id that can be used to replay */
  void recordSetup(char **, int, int[], int);
  /* takes no arguments,and returns a hash to replay from. */
  int record();
  /* uses record id to replay */
  int replay(int, char **, int, char *);
  /* using executable, premature, and mature answers, get answer quality */
  void waitForTimeout();
  void closeUbora();
  redisContext * redis_initiate(char *, int);
  int redis_SCARD(redisContext *, char *);
  char * redis_SRANDOM(redisContext *, char *);
  bool redis_EXISTS(redisContext *, char *);
  void redis_SREM_K(redisContext *, char *, char *);

  int getRR(char *, int);
private:
  char * generateAddress(char *);
};

redisContext * Ubora::redis_initiate(char * server, int port) {
  redisContext * dc;
  /*If we make it back here restart redis connection too*/
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
  printf("server %s port %d\n", server, port);
  dc = redisConnectWithTimeout(server, port, timeout);
  if (dc->err) {
    printf("Connection error: %s\n", dc->errstr);
    redisFree(dc);
    return NULL;
  }
  return dc;
}

int Ubora::redis_SCARD(redisContext * dc, char * setName){
  if(dc == NULL)
    {
      printf("null dc\n");
      return -1;
    }

  redisReply * replyCard;
  replyCard = (redisReply *)redisCommand(dc, "SCARD queries");
  if(replyCard->type = REDIS_REPLY_NIL)
    {
      printf("Found REDIS_REPLY_NIL in SCARD\n");
      freeReplyObject(replyCard);
      return -1;
    }

  printf("About to interpret int\n");
  int numObjects = (int) replyCard->integer;
  printf("SCARD %s %d\n", setName, numObjects);
  freeReplyObject(replyCard);
  return numObjects;
}

char * Ubora::redis_SRANDOM(redisContext * dc, char * setName){
  char * setMem = NULL;
  if(dc == NULL) return setMem;

  redisReply * replyAll;
  replyAll = (redisReply *)redisCommand(dc, "SRANDMEMBER %s", setName);

  if(replyAll->type == REDIS_REPLY_NIL)
    {
      freeReplyObject(replyAll);
      return NULL;
    }

  int len = strlen(replyAll->str);
  if(len > 0){
    setMem = (char *)malloc(sizeof(char) * (len+1));
    bzero(setMem, len+1);
    strncpy(setMem, replyAll->str, len);
  }

  freeReplyObject(replyAll);

  return setMem;
}

bool Ubora::redis_EXISTS(redisContext * dc, char * queryNum){
  if(dc == NULL) return false;

  redisReply * replyQ;
  replyQ = (redisReply *)redisCommand(dc, "EXISTS %s:query", queryNum);
  if(replyQ->type == REDIS_REPLY_NIL)
    {
      freeReplyObject(replyQ);
      return false;
    }

  if(replyQ->integer == 0)
    {
      freeReplyObject(replyQ);
      return false;
    }
  freeReplyObject(replyQ);

  redisReply * replyA;
  replyA = (redisReply *)redisCommand(dc, "EXISTS %s:panswer", queryNum);
  if(replyA->type == REDIS_REPLY_NIL)
    {
      freeReplyObject(replyA);
      return false;
    }

  if(replyA->integer == 0)
    {
      freeReplyObject(replyA);
      return false;
    }
  freeReplyObject(replyA);

  return true;
}

void Ubora::redis_SREM_K(redisContext * dc, char * setName, char * key){
  if(dc != NULL)
    {
      redisReply * replyS;
      replyS = (redisReply *)redisCommand(dc, "SREM %s %s", setName, key);
      freeReplyObject(replyS);
    }
}

void Ubora::waitForTimeout(){
  unsigned long long start, stop;
  double currtime = 0.0;
  cclock(start);
  do{
    int timehelp = 1; //timeout * 100;
    sleep(timehelp);
    cclock(stop);
    currtime = (double)(stop - start) / (double)C_CLOCKS_PER_SEC;
  }while(currtime < timeout);
  printf("done waiting\n");
}

/* set up Ubora with list of nodes, and ports associated with nodes, 
   sample rate, replay policy, and timeout */
void Ubora::setupUbora(char ** NodeList, int numNL, int port, int myPolicy, double sample_rate, double time_out)
{
  printf("Made it to setupUbora\n");
  numNodes = numNL;
  cclock(pitime);

  Unodes = new struct node*[numNL];
  for(int i = 0; i < numNL; i++)
    {
      Unodes[i] = (struct node*)malloc(sizeof(struct node));
    }

  sample = sample_rate;
  timeout = time_out;
  policy = myPolicy;
	
  char message[100];
  bzero(message, 100);
  sprintf(message, "timeout:%2.4f:1", timeout);
	
  int count = -1;
  int tcount = 0;
  char * address = NULL;

  for(int n = 0; n < numNL; n++)
    {
      printf("made it to for loop %d %d\n", n, numNL);
      count++;
      bzero(Unodes[n]->address, 100);
      strcpy(Unodes[n]->address, NodeList[n]);
      Unodes[n]->port = port;
      Unodes[n]->sock = socket(AF_INET, SOCK_STREAM, 0);

      if(Unodes[n]->sock > 0)
	{
	  printf("tempsock greater than 0");
	  int optval = 1;
	  //setsockopt(Unodes[n]->sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(int));
	  struct hostent *hp;
	  hp = gethostbyname(Unodes[n]->address);
	  if(hp == 0) {
	    printf("%s: unknown host\n", Unodes[n]->address);
	    continue;
	  }
	  printf("got host %s\n", Unodes[n]->address);
	  struct sockaddr_in cin_addr;
	  bcopy((void *)hp->h_addr, (void *)&cin_addr.sin_addr, hp->h_length);
	  cin_addr.sin_family = AF_INET;
	  cin_addr.sin_port = htons(Unodes[n]->port);
			
	  if(connect(Unodes[n]->sock, (struct sockaddr *)&cin_addr, sizeof(struct sockaddr_in)) < 0)
	    {
	      printf("problem with connect on port %d\n", Unodes[n]->port);
	    }
	  printf("connected to %d %s\n", Unodes[n]->port, Unodes[n]->address);
			
	  printf("saved address %s\n", Unodes[n]->address);
	  if(write(Unodes[n]->sock, message, 100) < 0)
	    {
	      printf("write problem\n");
	    }
	  printf("wrote message %s\n", message);
	  tcount++;
	}
    }
}

/* set up Tiers: client access tier, business logic, memory, auxiliary */
void Ubora::setupTiers(char ** Cat, char ** Blt, char ** Mem, char ** Aux, int c, int b, int m, int a){
  int count = -1;
  int tcount = 0;
  char * address = NULL;
  for(int cn = 0; cn < c; cn++);
  {
    count++;
    address = Cat[count];
    if(address != NULL)
      {
	struct storage temp;
	strncpy(temp.address, address, 100);
	*UCat[tcount] = temp;
	tcount++;
      }
  }

  count = -1;
  tcount = 0;
  address = NULL;
	

  for(int bn = 0; bn < b; bn++)
    {
      count++;
      address = Blt[count];
      if(address != NULL)
	{
	  struct storage temp;
	  strncpy(temp.address, address, 100);
	  *UBlt[tcount] = temp;
	  tcount++;
	}
    }
	
  count = -1;
  tcount = 0;
  address = NULL;

  for(int mn = 0; mn < m; mn++)
    {
      count++;
      address = Mem[count];
      if(address != NULL)
	{
	  struct storage temp;
	  strncpy(temp.address, address, 100);
	  *UMem[tcount] = temp;
	  tcount++;
	}
    }
	
  count = -1;
  tcount = 0;
  address = NULL;

  for(int an = 0; an < a; a++);
  {
    count++;
    address = Aux[count];
    if(address != NULL)
      {
	struct storage temp;
	strncpy(temp.address, address, 100);
	*UAux[tcount] = temp;
	tcount++;
      }
  }
}

/* set up Storage nodes to use with Ubora.  List of nodes already running on int[] ports. */
void Ubora::setupStore(char **NodesList, int numNL, int PortsList[]){
  char message[100];
  bzero(message, 100);
  char file[100];
  bzero(file, 100);
  strcpy(file, "storage:");
  int characters = 0;
  int msgchar = 0;
  int count = -1;
  int tcount = 0;
  int icount = 0;
  char * address = NULL;

  printf("Made it to setupStore\n");

  if(numNL > 0)
    {
      Ustorage = new struct storage*[numNL];

      for(int n = 0; n < numNL; n++)
	{
	  Ustorage[n] = (struct storage*)malloc(sizeof(struct storage));
	  bzero(Ustorage[n]->address, 100);
	}
    }

  FILE * storeFile;
  storeFile = fopen("myServers", "w");
	
  for(int n = 0; n < numNL; n++)
    {
      printf("in for %d %d\n", n, numNL);
      count++;
      characters = strlen(file);
      strcpy(Ustorage[n]->address, NodesList[n]);
      Ustorage[n]->port = PortsList[n]; 
      bzero(message, 100);
      if(Ustorage[n]->address[0] != 0)
	{
	  sprintf(message, "%s:%d\n", Ustorage[n]->address, Ustorage[n]->port);
	  printf("%s\n", message);
	  if(storeFile != NULL) fprintf(storeFile, "%s", message);

	  printf("stored tempS.address, %s, port, %d\n", Ustorage[n]->address, Ustorage[n]->port);
	}
      msgchar = strlen(message);
      if(characters+msgchar < 100 && msgchar > 0)
	{
	  strcat(file, message);
	  printf("file: %s\n", file);
	}
      else
	{
	  printf("Did not fit\n");
	  for(int i = 0; i < numNodes; i++)
	    {
	      write(Unodes[i]->sock, file, 100);
	    }
			
	  bzero(file, 100);
	  strcpy(file, "append:");
	  strcat(file, message);
	}
    }

  if(storeFile != NULL) fclose(storeFile);

  for(int i = 0; i < numNodes; i++)
    {
      if(write(Unodes[i]->sock, file, 100) < 0)
	{
	  printf("write error\n");
	}
      else
	{
	  printf("%d %d %s\n", Unodes[i]->sock, i, file);
	}
    }
}

/* can be either a regex or a list of nodes or a set of ports. */
void Ubora::recordSetup(char ** NodeList, int numNL, int PortsList[],int catport){
  char message[100];
  bzero(message, 100);
  char file[100];
  bzero(file, 100);
  int rhash = rand() % 3000;
  strcpy(file, "bolo:");
  int characters = 0;
  int msgchar = 0;
  int count = -1;
  int tcount = 0;
  int icount = 0;
  char * address = NULL;
	
  for(int n = 0; n < numNL; n++)
    {
      characters = strlen(file);
      bzero(message, 100);
      printf("NL %s PL %d\n", NodeList[n], PortsList[n]);
      if(NodeList[n][0] != 0 || PortsList[n] != 0)
	{
	  sprintf(message, "%s:%d\n", NodeList[n], PortsList[n]);
	  printf("message %s\n", message);
	}
      msgchar = strlen(message);
      printf("filelen %d msgchar %d\n", characters, msgchar);
      if(characters+msgchar < 100 && msgchar > 0)
	{
	  printf("appending %s to %s\n", message, file);
	  strcat(file, message);
	}
      else
	{
	  if(msgchar > 0 && message[0] != 0)
	    {
	      for(int i = 0; i < numNodes; i++)
		{
		  printf("writing 1 %s\n", file);
		  write(Unodes[i]->sock, file, 100);
		}
			
	      bzero(file, 100);
	      strcpy(file, "bolo:");
	      strcat(file, message);
	    }
	}
    }

  int flen = strlen(file);
  if(flen > 6)
    {
      for(int i = 0; i < numNodes; i++)
	{
	  printf("writing 2 %s\n", file);
	  write(Unodes[i]->sock, file, 100);
	}
    }

  FILE * modeFile;
  modeFile = fopen("mode.cfg", "w");
  if(modeFile != NULL)
    {
      fprintf(modeFile, "%d", 2);
      fflush(modeFile);
      int modeFile_fd = fileno(modeFile);
      fsync(modeFile_fd);

      fclose(modeFile);
    }
  char thisLine[512];
  sprintf(thisLine, "iptables -D INPUT -p tcp --dport %d -j QUEUE", catport);
  int s1 = system(thisLine);
  sprintf(thisLine, "iptables -D OUTPUT -p tcp --sport %d -j QUEUE", catport);
  int s2 = system(thisLine);
  sprintf(thisLine, "iptables -A INPUT -p tcp --dport %d -j QUEUE", catport);
  int s3 = system(thisLine);
  sprintf(thisLine, "iptables -A OUTPUT -p tcp --sport %d -j QUEUE", catport);
  int s4 = system(thisLine);
  printf("iptables set\n");

  FILE * borgRules;
  while((borgRules = fopen("borg.cfg", "w")) == NULL)
    {
      printf("borg.cfg could not be opened.\n");
    }

  //mode 2
  fprintf(borgRules, "Monitor Group\n  DST PORT: %d\n  SRC PORT: \n  DST ADDR: \n  SRC ADDR: \n  DATA RANGE: \n  MANGLER: monitorCli\n  MANGLE PARAMETERS: so-far-seen\n  MODE: 2\n", catport);
  //mode 1
  fprintf(borgRules, "Monitor Group\n  DST PORT: %d\n  SRC PORT: \n  DST ADDR: \n  SRC ADDR: \n  DATA RANGE: \n  MANGLER: collectDataCli\n  MANGLE PARAMETERS: localhost, 1055\n  MODE: 1\n", catport);
  fprintf(borgRules, "Monitor Group\n  DST PORT: \n  SRC PORT: %d\n  DST ADDR: \n  SRC ADDR: \n  DATA RANGE: \n  MANGLER: collectDataSrv\n  MANGLE PARAMETERS: localhost, 1055\n  MODE: 1\n", catport);
  //mode 0
  fprintf(borgRules, "Monitor Group\n  DST PORT: %d\n  SRC PORT: \n  DST ADDR: \n  SRC ADDR: \n  DATA RANGE: \n  MANGLER: collectDataCli\n  MANGLE PARAMETERS: localhost, 1055\n  MODE: 0\n", catport);
  fprintf(borgRules, "Monitor Group\n  DST PORT: \n  SRC PORT: %d\n  DST ADDR: \n  SRC ADDR: \n  DATA RANGE: \n  MANGLER: collectDataSrv\n  MANGLE PARAMETERS: localhost, 1055\n  MODE: 0\n", catport);
  fprintf(borgRules, "Monitor Group\n  DST PORT: %d\n  SRC PORT: \n  DST ADDR: \n  SRC ADDR: \n  DATA RANGE: \n  MANGLER: collectDataCli\n  MANGLE PARAMETERS: localhost, 1055\n  MODE: 3\n", catport);
  fprintf(borgRules, "Monitor Group\n  DST PORT: \n  SRC PORT: %d\n  DST ADDR: \n  SRC ADDR: \n  DATA RANGE: \n  MANGLER: collectDataSrv\n  MANGLE PARAMETERS: localhost, 1055\n  MODE: 3\n", catport);
  fflush(borgRules);
  int borgRules_fd = fileno(borgRules);
  fsync(borgRules_fd);
  fclose(borgRules);

  int p = system("pkill borg");
  int b2 = system("screen -S borg -p0 -X stuff $'./borgPro\n'");
}

/* can be either a regex or a list of nodes or a set of ports. */
int Ubora::record(){
  char message[100];
  bzero(message, 100);
  char file[100];
  bzero(file, 100);
  int rhash = rand() % 3000;
  sprintf(file, "record:%d", rhash);
  printf ("Die here 1 %d\n", rhash);
  fflush(stdout);
  allQ.push_back(rhash);
  printf ("Die here 2 %d\n", allQ.size());
  fflush(stdout);
  int characters = 0;
  int msgchar = 0;
  int count = -1;
  int tcount = 0;
  int icount = 0;
  char * address = NULL;
  
  for(int i = 0; i < numNodes; i++)
    {
      write(Unodes[i]->sock, file, 100);
    }
  printf ("Die here 3\n");
  fflush(stdout);
  unsigned long long timeSlip;
  cclock(timeSlip);
	
  //send timeSlip to redis
  redisContext * dc;
  char * rAddr = Ustorage[0]->address;
  int rPort = Ustorage[0]->port;
  printf("storage addr %s port %d for rhash %d\n", Ustorage[0]->address, Ustorage[0]->port,rhash);
  struct timeval rtimeout;
  rtimeout.tv_sec = 10;
  rtimeout.tv_usec = 500000;
  dc = redisConnectWithTimeout(rAddr, rPort, rtimeout);
  if(dc->err){
    printf("Connection error %s\n", dc->errstr);
    redisFree(dc);
  }
  else
    {
      redisReply * replyT;
      replyT = (redisReply *)redisCommand(dc, "SET %d:timeSlip %ul", rhash, timeSlip);
      if(replyT->type == REDIS_REPLY_NIL)
	{
	  freeReplyObject(replyT);
	  redisFree(dc);
	  printf("redis nil\n");
	  return -1;
	}
      freeReplyObject(replyT);
      redisFree(dc);
    }

  FILE * hashfile;
  hashfile = fopen("hashfile", "w");
  if(hashfile != NULL)
    {
      fprintf(hashfile, "%d", rhash);
      fflush(hashfile);
      int hashfile_fd = fileno(hashfile);
      fsync(hashfile_fd);

      fclose(hashfile);
    }

  FILE * modefile;
  modefile = fopen("mode.cfg", "w");
  if(modefile != NULL)
    {
      fprintf(modefile, "%d", 1);
      fflush(modefile);
      int modefile_fd = fileno(modefile);
      fsync(modefile_fd);

      fclose(modefile);
    }

  printf("waiting for timeout\n");
  waitForTimeout();
	
  FILE * modeFile2;
  modeFile2 = fopen("mode.cfg", "w");
  if(modeFile2 != NULL)
    {
      fprintf(modeFile2, "%d", 2);
      fflush(modeFile2);
      int modeFile2_fd = fileno(modeFile2);
      fsync(modeFile2_fd);

      fclose(modeFile2);
    }

  return rhash;
}

/* uses record id to replay */
int Ubora::replay(int rhash, char * catnodes[], int port, char * command){
  unsigned long long ustart = 0;
  char * myQuery;
  char * myResult;

  //Send replay
  char message[100];
  bzero(message, 100);
  sprintf(message, "replay:%d\n", rhash);
  int characters = 0;
  int msgchar = 0;
  int count = -1;
  int tcount = 0;
  int icount = 0;
 
  for(int i = 0; i < numNodes; i++)
    {
      printf("sending message %s\n", message);
      write(Unodes[i]->sock, message, 100);
    }
 
  //Retrieve timeFromRedis
  redisContext * dc;
  char * rAddr = Ustorage[0]->address;
  int rPort = Ustorage[0]->port;
  printf("replay storage addr %s port %d for rhash %d\n", Ustorage[0]->address, Ustorage[0]->port,rhash);
  struct timeval rtimeout;
  rtimeout.tv_sec = 10;
  rtimeout.tv_usec = 500000;
  dc = redisConnectWithTimeout(rAddr, rPort, rtimeout);
  if(dc->err){
    printf("replay end -1\n");
    printf("Connection error %s\n", dc->errstr);
    redisFree(dc);
    return (0);
  }
  else
    {
      redisReply * replyT;
      replyT = (redisReply *)redisCommand(dc, "GET %d:timeSlip", rhash);
      if(replyT->type == REDIS_REPLY_NIL)
	{
	  printf("replay end 0\n");
	  freeReplyObject(replyT);
	  redisFree(dc);
	  return (0);
	}

      if(replyT->type == REDIS_REPLY_INTEGER)
	{
	  ustart = (unsigned long long) replyT->integer;
	}
      else
	{
	  ustart = strtoul(replyT->str, NULL, 0);
	}

      freeReplyObject(replyT);

      printf("ustart %ull\n", ustart);

      // Retrieve query from redis and write to file
      redisReply * replyQ;
      int redisRetries=0;
      do {
	replyQ = (redisReply *)redisCommand(dc, "GET %d:query", rhash);
	redisRetries++;
      }while ( ((replyQ == NULL) || (replyQ->type == REDIS_REPLY_NIL)) && (redisRetries < 10) );

      if (redisRetries >= 10){
	printf("replay end 1\n");
	usleep(100);
	freeReplyObject(replyQ);
	redisFree(dc);
	return (0);
      }



      redisReply * replyRM;
      replyRM = (redisReply *)redisCommand(dc, "SREM queries %d", rhash);
      if(replyRM != NULL) freeReplyObject(replyRM);
      printf("exiting replay access redis\n");
      if(dc != NULL) redisFree(dc);
      printf("redisFree\n");
    }

  printf("after redis access\n");

  FILE * modeFile;
  modeFile = fopen("mode.cfg", "w");
  if(modeFile != NULL)
    {
      fprintf(modeFile, "%d", 0);
      fflush(modeFile);
      int modeFile_fd = fileno(modeFile);
      fsync(modeFile_fd);

      fclose(modeFile);
    }


  char replayCmd[200];
  bzero(replayCmd, 200);
  sprintf(replayCmd, "UboraReplayEngine -cp jedis-1.5.0.jar:. lightningClient %s %d %s %d %d", catnodes[0], port,Ustorage[0]->address, Ustorage[0]->port,rhash);
	
  char aqCmd[1000];
  bzero(aqCmd, 1000);
  sprintf(aqCmd, "%s %d:panswer %d:manswer", command, rhash, rhash);
  printf("Starting replay and aq:\n%s\n%s\n", replayCmd, aqCmd);

  if(!fork())
    {
      // Start replay
      int s2 = system(replayCmd);
      // Get answer quality
      system(aqCmd);
      exit(-1);
    }


  unsigned long long timeStop;
  cclock(timeStop);
	
  /*
    FILE * modeFile3;
    modeFile3 = fopen("mode.cfg", "w");
    if(modeFile3 != NULL)
    {
    fprintf(modeFile3, "%d", 2);
    fflush(modeFile3);
    int modeFile3_fd = fileno(modeFile3);
    fsync(modeFile3_fd);
    fclose(modeFile3);
    }
  */
  while(1)
    {
      FILE * modeFile2;
      modeFile2 = fopen("mode.cfg", "r");
      if(modeFile2 != NULL)
	{
	  int c = 0;
	  fscanf(modeFile2, "%d", &c);
	  fclose(modeFile2);
	  if(c == 2) break;
	  usleep(100);
	}
      else
	{
	  printf("broken file\n");
	  break;
	}
    }
  //waitForTimeout();

  return (1);
}

char * Ubora::generateAddress(char * regex){
  char * start = regex;
  char * pch = strstr(start, "\\.");
  char * newAddr = (char *) malloc(100* sizeof(char));
  //char newAddr[100];
  bzero(newAddr, 100);
  while(pch != NULL)
    {
      char subS[100];
      bzero(subS, 100);
      strncpy(subS, start, pch - start);
      char * tempS = strpbrk(subS, "\\t\\n\\v\\f\\r\\d\\D\\s\\S\\w\\W*+?()");
      if(tempS == NULL)
	{
	  if(newAddr[0] == 0)
	    {
	      strcpy(newAddr, subS);
	    }
	  else
	    {
	      sprintf(newAddr, "%s.%s", newAddr, subS);
	    }
	}
      else
	{
	  int rM = rand() % 256;
	  if(newAddr[0] == 0)
	    {
	      sprintf(newAddr, "%d", rM);
	    }
	  else
	    {
	      sprintf(newAddr, "%s.%d", newAddr, rM);
	    }
	}
		
      start = pch;
      pch = strstr(start, "\\.");
    }
	
  printf("New Address: %s\n", newAddr);
  return newAddr;
}

/* set up Storage nodes on same tier. Regex and single port to look for */
void Ubora::setupStore(char * address, int port, int num){
  int count = num * 4;
  int numSt = 0;
  char file[100];
  bzero(file, 100);
  strcpy(file, "storage:");
  int characters = 0;
  int msgchar = 0;
	
  // General protocol: 1. generate an address from the regex
  // 2. Try to connect to the port.  If it doesn't fail, close and add to the list.  Only try expected * 4 number of possibilities.
  for(int i = 0; i < count; i++)
    {
      // generate address from regex
      char newAddress[100];
      bzero(newAddress, 100);
      strcpy(newAddress, generateAddress(address));
		
      struct node temp;
      strncpy(temp.address, newAddress, 100);
      temp.port = port;
      temp.sock = socket(AF_INET, SOCK_STREAM, 0);
      if(temp.sock > 0)
	{
	  int optval = 1;
	  setsockopt(temp.sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(int));
	  struct hostent *hp;
	  hp = gethostbyname(temp.address);
	  if(hp == 0) {
	    printf("%s: unknown host\n", temp.address);
	    continue;
	  }
	  struct sockaddr_in cin_addr;
	  bcopy((void *)hp->h_addr, (void *)&cin_addr.sin_addr, hp->h_length);
	  cin_addr.sin_family = AF_INET;
	  cin_addr.sin_port = htons(temp.port);
			
	  connect(temp.sock, (struct sockaddr *)&cin_addr, sizeof(struct sockaddr_in));
	  printf("connected to %s\n", temp.address);

	  close(temp.sock);

	  numSt++;
			
	  char message[100];
	  bzero(message, 100);
	  characters = strlen(file);
	  sprintf(message, "%s:%d\n", newAddress, port);
	  struct storage tempS;
	  bzero(tempS.address, 100);
	  strcpy(tempS.address, newAddress);
	  tempS.port = port;
	  *Ustorage[count] = tempS;
	  msgchar = strlen(message);
	  if(characters+msgchar < 100 && msgchar > 0)
	    {
	      strcat(file, message);
	    }
	  else
	    {
	      for(int i = 0; i < numNodes; i++)
		{
		  write(Unodes[i]->sock, file, 100);
		}
			
	      bzero(file, 100);
	      strcpy(file, "append:");
	      strcat(file, message);
	    }
			
	  if(numSt >= num) break;
	}
    }
	
  characters = strlen(file);
  if(characters > 7)
    {
      for(int i = 0; i < numNodes; i++)
	{
	  write(Unodes[i]->sock, file, 100);
	}
    }
}



void Ubora::closeUbora()
{
  char file[100];
  bzero(file, 100);
  strcpy(file, "close:");

  for(int i = 0; i < numNodes; i++)
    {
      write(Unodes[i]->sock, file, 100);
      close(Unodes[i]->sock);
    }
}

int Ubora::getRR(char * fileName, int max_in_flight)
{
  //printf("Got to getRR\n");
  unsigned long long last_request = 0;
  unsigned long long curr_request = 0;
  double number_of_requests = 0.0;
  double average_time_between_requests = 0.0;
  bool last = false, prev = false, avg = false;
  int outcome = 0;
  bool readyToReplay = false;
  char * freekey = NULL;
  char * freeans = NULL;
  char setName[10];
  bzero(setName, 10);
  strcpy(setName, "queries");

  if(sample > 0.0)
    {
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
	    //printf("read %s\n", inString);
	    char * b = strstr(inString, ":");
	    char * pEnd;
	    if(inString[0] == 'p')
	      {
		last_request = strtoull(b+1, &pEnd, 10);
		prev = true;
	      }
	    else {
	      if(inString[0] == 'l')
		{
		  curr_request = strtoull(b+1, &pEnd, 10);
		  last = true;
		}
	      else{
		if(inString[0] == 'a')
		  {
		    average_time_between_requests = atof(b+1);
		    avg = true;
		  }
	      }
	    }
	  }

	  fclose(allInfo);
	}

      if(!last || !prev || last_request == curr_request)
	{
	  //printf("not enough data\n");
	  return -2;
	}

      if(last_request == pitime)
	{
	  //printf("not a new packet\n");
	  usleep(100);
	  return -2;
	}

      pitime = last_request;

      double r = ((double) rand() / (double) RAND_MAX);

      //printf("addr, %s, port %d\n", Ustorage[0]->address, Ustorage[0]->port);
      //redisContext * dc = redis_initiate(Ustorage[0]->address, Ustorage[0]->port);
      int s;

      s = allQ.size();

      /*if(dc == NULL) s = 0;
	else
	{
	s = redis_SCARD(dc, setName);
	}*/

      printf("S %d R %2.4f P %2.4f\n", s, r, sample);

      if(r < sample)
	{
	  if(s < max_in_flight)
	    {
	      //redisFree(dc);
	      return -1;
	    }
	  else
	    {
	      //redisFree(dc);
	      printf("too many queries outstanding\n");
	      return -2;
	    }
	}
      else
	{
	  if(s <= 0)
	    {
	      //redisFree(dc);
	      printf("no queries to replay\n");
	      return -2;
	    }

	  if(policy == 0)
	    {
	      double time_between = 0.0;
	      double new_average = 0.0;
  
	      if(!avg)
		{
		  //redisFree(dc);
		  printf("no average\n");
		  return -2;
		}
	      else
		{
		  time_between = (double) ( (double)(curr_request - last_request) / (double)C_CLOCKS_PER_SEC);
 
		  if(time_between <= 0.0 || time_between >= avg)
		    {
		      //redisFree(dc);
		      printf("greater than average\n");
		      return -2;
		    }
		}
	    }

	  int mine = allQ.back();
	  allQ.pop_back();
	  printf("returning %d\n", mine);
	  return mine;


	  // sample REDIS to see if a key exists and write the data to a temporary file
	  /*freekey = NULL;
	    freeans = NULL;
	    readyToReplay = false;

	    for(int i = 0; i < s; i++)
	    {
	    if(freekey != NULL) free(freekey);
	    freekey = redis_SRANDOM(dc, setName);
	    if(freekey != NULL){
	    if(redis_EXISTS(dc, freekey))
	    {
            readyToReplay = true;
            printf("in loop %s exists\n", freekey);
            break;
	    }
	    }
	    } 

	    redisFree(dc);
	    int fkey = -2;

	    if(freekey != NULL)
	    {
	    fkey = atoi(freekey);
	    free(freekey);
	    }
  
	    if(!readyToReplay) return -2;
	    else return fkey;*/
	}
    }
}

int main(int ARGC, char * ARGV[])
{
  int allMyNodesLength=0;
  int allMyTargetsLength=0;
  int allMyStorageLength=0;
  char * allMyNodes[MAX_NODES];
  char * allMyStorage[MAX_NODES];
  char * aux[MAX_NODES];
  char * cat[1];
  double samplingRate = 0.2;
  int uboraPort = 1063;
  double timeout = 10;
  int storagePort=1055;
  int catport = 12912;
  int auxport[1];
  int policy = 1;
  auxport[0] = 1064;
  char executable[50];
  bzero(executable, 50);
  signal(SIGCHLD, SIG_IGN);
  


  /*  To make Ubora easier to use, I moved a lot of parameters out of the code
      into a config file.

      - cstewart, Sun May 11, 2014
  */
  FILE * uboraFile;
  uboraFile = fopen("ubora.conf", "r");
  if (uboraFile == NULL)  {
    printf("Could not fine ubora.conf.  Did you run this in the local directory?\n");
    exit(-1);
  }
  char line[350];
  char parameter[30];
  char value[30];
  while (feof(uboraFile) == false) {
    
    //printf("Line: %s",line);
    if (fgets(line, 350, uboraFile) ){
      sscanf(line, "%30[^:]:%30[^\n]", parameter, value);
    }
    else {
      parameter[0] = '#';
      parameter[1] = '\0';
    }
     
    int cs_trim = 0;
    while ((value[cs_trim] == ' ')  && (cs_trim < 30))
      cs_trim++;

    if (cs_trim > 0) {
      int cs_walk = 0;
      for (cs_walk = cs_trim; cs_walk < 30; cs_walk++) {
	value[cs_walk - cs_trim] = value[cs_walk];
      }
    }
 
    if (line[0] == '#') {
      parameter[0] = '#';
      parameter[1] = '\0';
    }
    for(int pi = 0; parameter[pi]; pi++){
      parameter[pi] = tolower(parameter[pi]);
    }
    //printf("Parameter %s  Value %s\n",parameter,value);

    if (strcmp(parameter,"fullnode") == 0) {
      printf("Adding record node: %s\n", value);
      allMyNodes[allMyNodesLength] = (char *)malloc(30 * sizeof(char));
      strcpy(allMyNodes[allMyNodesLength], value);
      allMyNodesLength++;

      printf("Adding storage node: %s\n", value);
      allMyStorage[allMyStorageLength] = (char *)malloc(30 * sizeof(char));
      strcpy(allMyStorage[allMyStorageLength], value);
      allMyStorageLength++;
    }
    else if (strcmp(parameter,"targetport") == 0) {
      printf("Adding target port: %s\n", value);
      auxport[0] = atoi(value);
    }
    else if (strcmp(parameter,"recordnode") == 0) {
      printf("Adding record node: %s\n", value);
      allMyNodes[allMyNodesLength] = (char *)malloc(30 * sizeof(char));
      strcpy(allMyNodes[allMyNodesLength], value);
      allMyNodesLength++;
    }
    else if (strcmp(parameter,"targetnode") == 0) {
      printf("Adding target node: %s\n", value);
      aux[allMyTargetsLength] = (char*)malloc(30 * sizeof(char));
      strcpy(aux[allMyTargetsLength], value);
      allMyTargetsLength++;
    }
    else if (strcmp(parameter,"frontend") == 0) {
      printf("Adding front end: %s\n", value);
      cat[0] = (char*)malloc(30 * sizeof(char));
      bzero(cat[0], 30);
      strcpy(cat[0], value);
    }
    else if (strcmp(parameter,"queryport") == 0) {
      printf("Setting query port to %s\n", value);
      catport = atoi(value);
    }
    else if (strcmp(parameter,"deploymode") == 0) {
      printf("Setting deploy mode to %s\n", value);
      policy = atoi(value);
    }
    else if (strcmp(parameter,"qualityfunc") == 0) {
      strcpy(executable, value);
    }
    else if (strcmp(parameter,"storageport") == 0) {
      printf("Setting storage port to %s\n", value);
      storagePort = atoi(value);
    }
    else if (strcmp(parameter,"samplerate") == 0) {
      printf("Setting sampling to %s\n", value);
      samplingRate = atof(value);
      if(samplingRate < 0) samplingRate = 0.4;
    }
    else if (strcmp(parameter,"timeout") == 0) {
      printf("Setting timeout to %s\n", value);
      timeout = atoi(value);
      if(timeout <= 0) timeout = 10;
    }
    else if ((parameter[0] == '#') || (parameter[0] == '\n') || (parameter[0] == '\0') ) {
    }
    else {
      printf("Unknown config parameter %s, exiting\n", parameter);
      exit(-1);
    }

  }

  /*  The following code makes the above YAML processing compatible with Kelley's original implementation
   */
  int numNodes = allMyNodesLength;
  int storageNodes = allMyStorageLength;


  int ports[storageNodes];
  for(int i = 0; i < storageNodes; i++)
    ports[i] = storagePort;








  


  printf("about to start Ubora\n");

  Ubora myUbora;

  printf("myUbora\n");
  myUbora.setupUbora(allMyNodes, numNodes, uboraPort, policy, samplingRate, timeout);
  printf("setupUbora\n");
  sleep(2);
  myUbora.setupStore(allMyStorage, storageNodes, ports);
  printf("setupStore\n");
  sleep(2);
  myUbora.recordSetup(aux, 1, auxport, catport);
  printf("recordSetup\n");
  sleep(3);

  char AggFileName[30];
  bzero(AggFileName, 30);
  strcpy(AggFileName, "so-far-seen");

  int max_in_flight = 10;

  /*int xt = myUbora.getRR(AggFileName, max_in_flight);
    printf("xt %d\n", xt);
  
    int hash = myUbora.record();
    //allQ.pushback(hash);
    printf("record\n");
    sleep(10);

    xt = myUbora.getRR(AggFileName, max_in_flight);
    printf("xt %d\n", xt);

    struct metrics myMet = myUbora.replay(hash);
    printf("replay\n");
    sleep(10);

    xt = myUbora.getRR(AggFileName, max_in_flight);
    printf("xt %d\n", xt);
  */
  

  int mode = 2;
  int xt;

  while(1)
    {
      //printf("in while loop\n");
      //fflush(stdout);
      FILE * modeFile;
      if((modeFile = fopen("mode.cfg", "r")) != NULL)
	{
	  fscanf(modeFile, "%d", &mode);
	  fclose(modeFile);
	}

      if(mode == 2)
	{
	  xt = myUbora.getRR((char*)AggFileName, max_in_flight);

	  if(xt > -2)
	    {
	      printf("xt %d\n", xt);

	      if(xt == -1)
		{
		  int hash = myUbora.record();
		}
	      else
		{
		  if (myUbora.replay(xt, cat, catport, executable) ) {
		    printf("Succesfully started replay and answer qual\n");
		  }
		}
	    }
	}
    }

  myUbora.closeUbora();
}
