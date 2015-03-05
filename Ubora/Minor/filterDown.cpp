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
  char src_addr[100];
  char dst_addr[100];
  char data_range[50];
  char mangler[50];
  char parameters[100];
  int mode;
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
    vector<struct m_group> allRules;
		struct node ** Unodes;
		int numNodes;
		int policy;
		double timeout;
	public:
		/* set up Ubora with list of known nodes, number of nodes, and ports to contact ubora on other nodes, sample rate, and timeout	*/
		void setupUbora(char **, int, int, int, double, char *);
    /* setup iptables rules for record */
    void recordSetup(char *);
    /* start propagating */
    void propagate(char *);
    /* start record */
    void record();
    /* start replay */
    void replay();
    /* start normal */
    void normal();
    /* close Ubora connections */
		void closeUbora();
    /* wait for timeout */
    void waitForTimeout();
    /* find any iptables transformations of targeted port */
    int IPlookup(int);
};

int Ubora::IPlookup(int port)
{
  char command[100];
  bzero(command, 100);
  sprintf(command, "iptables -L -t nat -n | grep \"dpt:%d\" | grep -v \"spt:!1066\" \n", port);
  FILE * ipipe = popen(command, "r");

  if(!ipipe)
  {
    return port;
  }

  char buffer[1000];
  bzero(buffer, 1000);
  char * lpipeline = fgets(buffer, sizeof(buffer), ipipe);
  pclose(ipipe);
  printf("output: %s\n", buffer);
  int newport = port; 

  char * pch = strstr(buffer, "to:");
  if(pch != NULL){
    pch = strstr(pch+3, ":"); 
    if(pch != NULL) newport = atoi(pch+1);
  }

  printf("newport %d\n", newport);

  return newport;
}

void Ubora::waitForTimeout(){
	unsigned long long start, stop;
  double currtime = 0.0;
  int timehelp = 1;
	cclock(start);
  do
  {
		sleep(timehelp);
		cclock(stop);
		currtime = (double)(stop - start) / (double)C_CLOCKS_PER_SEC;
	}while(currtime < timeout);
  printf("Waited %4.4f seconds of %4.4f requested.\n", currtime, timeout);
}

/* set up Ubora with list of nodes, and ports associated with nodes, 
sample rate, replay policy, and timeout */
void Ubora::setupUbora(char ** NodeList, int numNL, int port, int policy_time, double time_out, char * message)
{
  printf("Made it to setupUbora with message %s\n", message);
  if(numNL > 0)
  {
    Unodes = new struct node*[numNL];
    for(int i = 0; i < numNL; i++)
    {
      Unodes[i] = (struct node*)malloc(sizeof(struct node));
    }
  }
  else
  {
    Unodes = new struct node*[1];
  }
  printf("freed Unodes\n");
	policy = policy_time;
	timeout = time_out;
  numNodes = numNL;
	
	if(numNL > 0)
  {
    int totNum = 0;
	  for(int n = 0; n < numNL; n++)
	  {
      printf("made it to for loop %d %d\n", n, numNL);
      bzero(Unodes[totNum]->address, 100);
      strcpy(Unodes[totNum]->address, NodeList[n]);
      Unodes[totNum]->port = port;
		  Unodes[totNum]->sock = socket(AF_INET, SOCK_STREAM, 0);
		  if(Unodes[totNum]->sock > 0)
		  {
        printf("tempsock greater than 0");
			  int optval = 1;
			  setsockopt(Unodes[totNum]->sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(int));
			  struct hostent *hp;
			  hp = gethostbyname(Unodes[totNum]->address);
			  if(hp == 0) {
			  	printf("%s: unknown host\n", Unodes[totNum]->address);
			  	continue;
			  }
        printf("got host %s\n", Unodes[totNum]->address);
			  struct sockaddr_in cin_addr;
			  bcopy((void *)hp->h_addr, (void *)&cin_addr.sin_addr, hp->h_length);
			  cin_addr.sin_family = AF_INET;
			  cin_addr.sin_port = htons(Unodes[totNum]->port);
			
			  if(connect(Unodes[totNum]->sock, (struct sockaddr *)&cin_addr, sizeof(struct sockaddr_in)) < 0){
          printf("problem with connection on port %d\n", Unodes[totNum]->port);
          continue;
        }
			  printf("connected to %d %s\n", Unodes[totNum]->port, Unodes[totNum]->address);
			
			  printf("saved address %s\n", Unodes[totNum]->address);
			  if(write(Unodes[totNum]->sock, message, 100) < 0)
        {
          printf("write problem\n");
          continue;
        }
        printf("wrote message %s\n", message);
        totNum++;
		  }
	  }
    numNodes = totNum;
  }
}

/* can be a list of nodes or a set of ports. */
void Ubora::recordSetup(char * rulesList){
  char * pch = strstr(rulesList, "bolo");
  char address[100];
  bzero(address, 100);
  int port = 0;

  printf("got to record setup\n");

  if(pch != NULL)
  {
    pch = strstr(pch, ":");
    while(pch != NULL)
    {
      char * pch2 = strstr(pch+1, ":");
      bzero(address, 100);
      port = 0;
      if(pch2 != NULL && pch2 != pch+1)
      {
        strncpy(address, pch+1, pch2 - pch-1);
        printf("address %s\n", address);
      }

      if(pch2 != NULL)
      {
        pch = NULL;
        pch = strstr(pch2+1, "\n");
        if(pch != NULL && pch != pch2+1)
        {
          port = atoi(pch2+1);
          pch2 = NULL;
        }
      }
      else
      {
        pch = NULL;
      }

      if(address[0] != 0 || port != 0)
      {
        printf("we found address %s and port %d\n", address, port);
        //add rule for line in bolo
        struct m_group tempdstRule;
        bzero(tempdstRule.src_addr, 100);
        bzero(tempdstRule.dst_addr, 100);
        bzero(tempdstRule.data_range, 50);
        bzero(tempdstRule.mangler, 50);
        bzero(tempdstRule.parameters, 100);
        tempdstRule.mode = 1;
        tempdstRule.dport = port;
        strcpy(tempdstRule.dst_addr, address);
        tempdstRule.sport = 0;
        strcpy(tempdstRule.mangler, "collectDataCli");
        strcpy(tempdstRule.parameters, "");
        
        allRules.push_back(tempdstRule);

        struct m_group tempsrcRule;
        bzero(tempsrcRule.src_addr, 100);
        bzero(tempsrcRule.dst_addr, 100);
        bzero(tempsrcRule.data_range, 50);
        bzero(tempsrcRule.mangler, 50);
        bzero(tempsrcRule.parameters, 100);
        tempsrcRule.mode = 1;
        tempsrcRule.dport = 0;
        tempsrcRule.sport = port;
        strcpy(tempsrcRule.src_addr, address);
        strcpy(tempsrcRule.mangler, "collectDataSrv");
        strcpy(tempsrcRule.parameters, "tcp, iph, data");

        allRules.push_back(tempsrcRule);
      }
    }
  }

  FILE * borgRules;
  if((borgRules = fopen("borg.cfg", "w")) == NULL)
  {
    printf("borg.cfg could not be opened.\n");
    exit(1);
  }

  // launch iptables rules
  for(std::vector<struct m_group>::size_type i = 0; i != allRules.size(); i++) {
    char syscmd[200];
    bzero(syscmd, 200);
    sprintf(syscmd, "iptables -A ");
    if(allRules[i].sport != 0 || allRules[i].src_addr[0] != 0)
      strcat(syscmd, "INPUT ");
    else if(allRules[i].dport != 0 || allRules[i].dst_addr[0] != 0)
      strcat(syscmd, "OUTPUT ");

    strcat(syscmd, "-p tcp ");

    if(allRules[i].sport != 0)
      sprintf(syscmd, "%s--sport %d ", syscmd, IPlookup(allRules[i].sport));

    if(allRules[i].dport != 0)
      sprintf(syscmd, "%s--dport %d ", syscmd, IPlookup(allRules[i].dport));

   /* if(allRules[i].src_addr[0] != 0)
      sprintf(syscmd, "%s-s %s ", syscmd, allRules[i].src_addr);

    if(allRules[i].dst_addr[0] != 0)
      sprintf(syscmd, "%s-d %s ", syscmd, allRules[i].dst_addr);
*/
    strcat(syscmd, "-j QUEUE");

    printf("%s\n", syscmd);
    int s = system(syscmd);
    //count++;
    fprintf(borgRules, "Monitor Group\n  DST PORT: ");
    if(allRules[i].dport != 0) fprintf(borgRules, "%d", IPlookup(allRules[i].dport));
    fprintf(borgRules, "\n  SRC PORT: ");
    if(allRules[i].sport != 0) fprintf(borgRules, "%d", IPlookup(allRules[i].sport));
    //fprintf(borgRules, "\n  DST ADDR: %s\n  SRC ADDR: %s\n  DATA RANGE: \n  MANGLER: %s\n  MANGLE PARAMETERS: %s\n  MODE: %d\n", allRules[i].dst_addr, allRules[i].src_addr, allRules[i].mangler, allRules[i].parameters, 1); 
    fprintf(borgRules, "\n  DST ADDR: \n  SRC ADDR: \n  DATA RANGE: \n  MANGLER: %s\n  MANGLE PARAMETERS: %s\n  MODE: %d\n", allRules[i].mangler, allRules[i].parameters, 1);
  }

  fclose(borgRules);
}

void Ubora::record(){
  printf("start record\n");
  int b = system("pkill borg");
  int b3 = system("screen -S borg -p0 -X stuff $'./borgPro\n'");

  printf("screen borg\n");
  for(std::vector<struct m_group>::size_type i = 0; i != allRules.size(); i++)
  {
    char syscmd[200];
    bzero(syscmd, 200);
    strcpy(syscmd, "iptables -t nat -D OUTPUT -p tcp ");

    if(allRules[i].dport != 0 || allRules[i].dst_addr[0] != 0)
    {
      if(allRules[i].dport != 0)
        sprintf(syscmd, "%s--dport %d ", syscmd, allRules[i].dport);

      if(allRules[i].dst_addr[0] != 0)
        sprintf(syscmd, "%s-d %s ", syscmd, allRules[i].dst_addr);

      strcat(syscmd, "! --sport 1066 -j REDIRECT --to-port 1061");

      printf("syscmd %s\n", syscmd);
      int r = system(syscmd);
    }
  }

  printf("write file to mode %d\n", 1);
 
  FILE * modeFile;
  modeFile = fopen("mode.cfg", "w");
  if(modeFile != NULL)
  {
    fprintf(modeFile, "%d", 1);
    fclose(modeFile);
  }

  printf("iptables rules:\n");
  for(std::vector<struct m_group>::size_type i = 0; i != allRules.size(); i++)
  {
    char syscmd[200];
    bzero(syscmd, 200);
    sprintf(syscmd, "iptables -A ");
    if(allRules[i].sport != 0 || allRules[i].src_addr[0] != 0)
      strcat(syscmd, "INPUT ");
    else if(allRules[i].dport != 0 || allRules[i].dst_addr[0] != 0)
      strcat(syscmd, "OUTPUT ");

    strcat(syscmd, "-p tcp ");

    if(allRules[i].sport != 0)
      sprintf(syscmd, "%s--sport %d ", syscmd, IPlookup(allRules[i].sport));

    if(allRules[i].dport != 0)
      sprintf(syscmd, "%s--dport %d ", syscmd, IPlookup(allRules[i].dport));

    /*if(allRules[i].src_addr[0] != 0)
      sprintf(syscmd, "%s-s %s ", syscmd, allRules[i].src_addr);
 
    if(allRules[i].dst_addr[0] != 0)
      sprintf(syscmd, "%s-d %s ", syscmd, allRules[i].dst_addr);
*/
    strcat(syscmd, "-j QUEUE");

    printf("Syscmd: %s\n", syscmd);
    int s = system(syscmd);
  }

  printf("policy %d waiting for timeout\n", policy);

  //if(policy == 1)
  //{
    //waitForTimeout();
    //normal();
  //}
}

/* uses record id to replay */
void Ubora::replay(){
  char path[50];
  bzero(path, 50);
  strcpy(path, "screen -S mitm -p0 -X stuff $'./MITM 1061 ");
  for(std::vector<struct m_group>::size_type i = 0; i != allRules.size(); i++) {
    if(allRules[i].dport != 0)
    {
      sprintf(path, "%s %d", path, allRules[i].dport);
    }
  }

  strcat(path, "\n'");

  int r = system("pkill MITM");
  int m2 = system(path);

  FILE * modeFile;
  modeFile = fopen("mode.cfg", "w");
  if(modeFile != NULL)
  {
    fprintf(modeFile, "%d", 0);
    fclose(modeFile);
  }
  
  for(std::vector<struct m_group>::size_type i = 0; i != allRules.size(); i++)
  {
    char syscmd[200];
    bzero(syscmd, 200);
    strcpy(syscmd, "iptables -t nat -I OUTPUT 1 -p tcp ");
  
    if(allRules[i].dport != 0 || allRules[i].dst_addr[0] != 0)
    {
      if(allRules[i].dport != 0)
        sprintf(syscmd, "%s--dport %d ", syscmd, allRules[i].dport);
  
      if(allRules[i].dst_addr[0] != 0)
        sprintf(syscmd, "%s-d %s ", syscmd, allRules[i].dst_addr);
    
      strcat(syscmd, "! --sport 1066 -j REDIRECT --to-port 1061");

      printf("Syscmd %s\n", syscmd);
      int r = system(syscmd);
    }
  }

  // as of this version of Ubora, we need to turn off iptables rules and turn on our own.
  for(std::vector<struct m_group>::size_type i = 0; i != allRules.size(); i++)
  {
    char syscmd[200];
    bzero(syscmd, 200);
    sprintf(syscmd, "iptables -D ");
    if(allRules[i].sport != 0 || allRules[i].src_addr[0] != 0)
      strcat(syscmd, "INPUT ");
    else if(allRules[i].dport != 0 || allRules[i].dst_addr[0] != 0)
      strcat(syscmd, "OUTPUT ");
 
    strcat(syscmd, "-p tcp ");

    if(allRules[i].sport != 0)
      sprintf(syscmd, "%s--sport %d ", syscmd, IPlookup(allRules[i].sport));

    if(allRules[i].dport != 0)
      sprintf(syscmd, "%s--dport %d ", syscmd, IPlookup(allRules[i].dport));

    /*if(allRules[i].src_addr[0] != 0)
      sprintf(syscmd, "%s-s %s ", syscmd, allRules[i].src_addr);

    if(allRules[i].dst_addr[0] != 0)
      sprintf(syscmd, "%s-d %s ", syscmd, allRules[i].dst_addr);
    */
    strcat(syscmd, "-j QUEUE");

    printf("Syscmd %s\n", syscmd);
    int s = system(syscmd);
  }

  int b = system("pkill borg");

  //if(policy == 1)
  //{
  //  waitForTimeout();
  //  normal();
  //}
}

void Ubora::normal()
{
  for(std::vector<struct m_group>::size_type i = 0; i != allRules.size(); i++)
  {
    char syscmd[200];
    bzero(syscmd, 200);
    sprintf(syscmd, "iptables -D ");
    if(allRules[i].sport != 0 || allRules[i].src_addr[0] != 0)
      strcat(syscmd, "INPUT ");
    else if(allRules[i].dport != 0 || allRules[i].dst_addr[0] != 0)
      strcat(syscmd, "OUTPUT ");
    
    strcat(syscmd, "-p tcp ");

    if(allRules[i].sport != 0)
      sprintf(syscmd, "%s--sport %d ", syscmd, IPlookup(allRules[i].sport));

    if(allRules[i].dport != 0)
      sprintf(syscmd, "%s--dport %d ", syscmd, IPlookup(allRules[i].dport));

    /*if(allRules[i].src_addr[0] != 0)
      sprintf(syscmd, "%s-s %s ", syscmd, allRules[i].src_addr);

    if(allRules[i].dst_addr[0] != 0)
      sprintf(syscmd, "%s-d %s ", syscmd, allRules[i].dst_addr);
 */
    strcat(syscmd, "-j QUEUE");
 
    int s = system(syscmd);
  }

  for(std::vector<struct m_group>::size_type i = 0; i != allRules.size(); i++)
  {
    char syscmd[200];
    bzero(syscmd, 200);
    strcpy(syscmd, "iptables -t nat -D OUTPUT -p tcp ");
    
    if(allRules[i].dport != 0 || allRules[i].dst_addr[0] != 0)
    {
      if(allRules[i].dport != 0)
        sprintf(syscmd, "%s--dport %d ", syscmd, allRules[i].dport);
  
      if(allRules[i].dst_addr[0] != 0)
        sprintf(syscmd, "%s-d %s ", syscmd, allRules[i].dst_addr);
  
      strcat(syscmd, "! --sport 1066 -j REDIRECT --to-port 1061");
  
      printf("syscmd %s\n", syscmd);
      int r = system(syscmd);
    }
  }

  FILE * modeFile;
  modeFile = fopen("mode.cfg", "w");
  if(modeFile != NULL)
  {
    fprintf(modeFile, "%d", 2);
    fclose(modeFile);
  }

  int p = system("pkill borg");  
}

void Ubora::propagate(char * file)
{
  for(int i = 0; i < numNodes; i++)
  {
    write(Unodes[i]->sock, file, 100);
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

  for(int i = 0; i < numNodes; i++)
  {
    free(Unodes[i]);
  }
}

int main(int ARGC, char * ARGV[])
{
  char * allMyNodes[MAX_NODES];
  int allMyNodesLength = 0;
  int uboraPort = 1063;

  /*  To make Ubora easier to use, I moved a lot of parameters out of the code into a config file.
      - cstewart, Mon May 12, 2014
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
    }
    else if (strcmp(parameter,"recordnode") == 0) {
      printf("Adding record node: %s\n", value);
      allMyNodes[allMyNodesLength] = (char *)malloc(30 * sizeof(char));
      strcpy(allMyNodes[allMyNodesLength], value);
      allMyNodesLength++;
    }

  }

  if (allMyNodesLength == 0) {
    printf("No Nodes Specified\n");
    exit(-1);
  }

  int numNodes = allMyNodesLength;

  printf("got allMyNodes\n");



  //int underPort = 1054;

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in serv_addr;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(uboraPort);

  int optval = 1;

  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &optval, sizeof optval);


  if (bind(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)   {
    perror("ERROR on binding");
    exit(1);
  }

  if (listen(sock, 10) < 0 ){
      perror("ERROR on listening");
      exit(1);
    }


  printf("listening on port %d\n", uboraPort); 

  unsigned long long recordtime, replaytime;
  double timeout = 0.0;
  int autotimeout = 0;
  Ubora myUbora;

  bool needToClose = false;

  //int underPort = 1048;

  while(!needToClose)
  {
    int connfd = accept(sock, (struct sockaddr*)NULL, NULL);

    char recvBuff[100];

    do{
      bzero(recvBuff, 100);
      read(connfd, recvBuff, 100);
      if(recvBuff[0] != 0) printf("message %s\n", recvBuff);
      int leng = strlen(recvBuff);
      char * notS = strstr(recvBuff, "timeout");

      if(numNodes > 0)
      {
        if(leng > 0 && notS == NULL)
        {
          myUbora.propagate(recvBuff);
        }
      }

      char * col = strstr(recvBuff, ":");

      if(leng > 0)
      {
        char * rep = strstr(recvBuff, "record");
        if(rep != NULL)
        {
          int rhash = atoi(col+1);

          FILE * hashFile;
          if((hashFile = fopen("hashfile", "w")) != NULL)
          {
            fprintf(hashFile, "%d", rhash);
            fclose(hashFile);
          }

          myUbora.record();

          myUbora.waitForTimeout();
          myUbora.normal();
        }
        else
        {
          rep = strstr(recvBuff, "replay");
          if(rep != NULL)
          {
            int rhash = atoi(col+1);

            FILE * hashFile;
            if((hashFile = fopen("hashfile", "w")) != NULL)
            {
              fprintf(hashFile, "%d", rhash);
              fclose(hashFile);
            }

            myUbora.replay();
            myUbora.waitForTimeout();
            myUbora.normal();
          }
          else
          {
            rep = strstr(recvBuff, "normal");
            if(rep != NULL)
            {
              myUbora.normal();
            }
            else
            {
              char * pch = strstr(recvBuff, "bolo");
              if(pch != NULL)
              {
                //add rule for line in bolo
                myUbora.recordSetup(recvBuff);
              }
              else
              {
                pch = strstr(recvBuff, "timeout");
                if(pch != NULL)
                {
                  timeout = atof(col+1);
                  pch = strstr(col+1, ":");
                  autotimeout = atoi(pch+1);
                  myUbora.setupUbora(allMyNodes, numNodes, uboraPort, autotimeout, timeout, recvBuff);
                }
                else
                {
                  pch = strstr(recvBuff, "storage");
                  if(pch != NULL)
                  {
                    char storage[100];
                    bzero(storage, 100);
                    strcpy(storage, col+1);
                    FILE * storeFile;
                    if((storeFile = fopen("myServers", "w")) != NULL)
                    {
                      fprintf(storeFile, "%s", storage);
                      fclose(storeFile);
                    }
                  }
                  else
                  {
                    pch = strstr(recvBuff, "append");
                    if(pch != NULL)
                    {
                      char storage[100];
                      bzero(storage, 100);
                      strcpy(storage, col+1);
                      FILE * storeFile;
                      if((storeFile = fopen("myServers", "a")) != NULL)
                      {
                        fprintf(storeFile, "%s", storage);
                        fclose(storeFile);
                      }
                    }
                    else
                    {
                      pch = strstr(recvBuff, "close");
                      if(pch != NULL)
                      {
                        needToClose = true;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
      else
      {
       // printf("Something went wrong with message %s\n", recvBuff);
      }

    } while(!needToClose);

    close(connfd);
  }

  myUbora.closeUbora();
}
