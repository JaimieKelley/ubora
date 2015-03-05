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

#define BUFSIZE 2048
#define MAX_CHARS 536870912

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
		int Usockets[];
    vector<struct m_group> allRules;
		int NodePorts[];
		struct node * Unodes[];
		int numNodes;
		int policy;
		double timeout;
	public:
		/* set up Ubora with list of known nodes, number of nodes, and ports to contact ubora on other nodes, sample rate, and timeout	*/
		void setupUbora(char **, int, int, int, double);
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
};

void Ubora::waitForTimeout(){
	unsigned long long start, stop;
  double currtime = 0.0;
	cclock(start);
	do{
		int timehelp = timeout * 100;
		usleep(timeout /10);
		cclock(stop);
		currtime = (double)(stop - start) / (double)C_CLOCKS_PER_SEC;
	}while(currtime < timeout);
}

/* set up Ubora with list of nodes, and ports associated with nodes, 
sample rate, replay policy, and timeout */
void Ubora::setupUbora(char ** NodeList, int numNL, int port, int policy_time, double time_out)
{
  printf("Made it to setupUbora\n");
  printf("freed Unodes\n");
	policy = policy_time;
	timeout = time_out;
  numNodes = numNL;
	
	char message[100];
	bzero(message, 100);
	sprintf(message, "timeout:%2.4", timeout);
	
	int count = -1;
	int tcount = 0;
  char * address = NULL;

	for(int n = 0; n < numNL; n++)
	{
    printf("made it to for loop %d %d\n", n, numNL);
		count++;
		char * address = NodeList[count];
		struct node temp;
		strncpy(temp.address, address, 100);
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
			
			Unodes[tcount] = &temp;
			printf("saved address %s\n", Unodes[count]->address);
			write(Unodes[tcount]->sock, message, 100);
      printf("wrote message %s\n", message);
			tcount++;
		}
	}
	
	numNodes = tcount;
}

/* can be a list of nodes or a set of ports. */
void Ubora::recordSetup(char * rulesList){
  char * pch = strstr(rulesList, "bolo");
  char address[100];
  bzero(address, 100);
  int port = 0;

  if(pch != NULL)
  {
    pch = strstr(pch, ":");
    while(pch != NULL)
    {
      char * pch2 = strstr(pch+1, ":");
      bzero(address, 100);
      if(pch2 != NULL && pch2 != pch+1)
      {
        strncpy(address, pch+1, pch2 - pch-1);
        printf("address %s\n", address);
      }

      if(pch2 != NULL)
      {
        pch = strstr(pch2+1, ":");
        if(pch != NULL && pch != pch2+1)
        {
          port = atoi(pch2+1);
        }
      }

      if(address[0] != 0 || port != 0)
      {
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


      FILE * borgRules;
      if((borgRules = fopen("borg.cfg", "a")) == NULL)
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
          sprintf(syscmd, "%s--sport %d ", syscmd, allRules[i].sport);

        if(allRules[i].dport != 0)
          sprintf(syscmd, "%s--dport %d ", syscmd, allRules[i].dport);

        if(allRules[i].src_addr[0] != 0)
          sprintf(syscmd, "%s-s %s ", syscmd, allRules[i].src_addr);

        if(allRules[i].dst_addr[0] != 0)
          sprintf(syscmd, "%s-d %s ", syscmd, allRules[i].dst_addr);

        strcat(syscmd, "-j QUEUE");

        int s = system(syscmd);

        fprintf(borgRules, "Monitor Group\n  DST PORT: %d\n  SRC PORT: %d\n  DST ADDR: %s\n  SRC ADDR: %s\n  DATA RANGE: \n  MANGLER: %s\n  MANGLE PARAMETERS: %s\n MODE: %d\n", allRules[i].dport, allRules[i].sport, allRules[i].dst_addr, allRules[i].src_addr, allRules[i].mangler, allRules[i].parameters); 
      }

      fclose(borgRules);
    }
  }
}

void Ubora::record(){
  for(std::vector<struct m_group>::size_type i = 0; i != allRules.size(); i++)
  {
    char syscmd[200];
    bzero(syscmd, 200);
    strcpy(syscmd, "iptables -t nat -D OUTPUT -p tcp ");

    if(allRules[i].dport != 0 || allRules[i].dst_addr[0] != 0)
    {
      if(allRules[i].dport != 0)
        sprintf(syscmd, "%s--dport %d ", syscmd, allRules[i].dport);

      if(allRules[i].dst_addr != 0)
        sprintf(syscmd, "%s-d %s ", syscmd, allRules[i].dst_addr);

      strcat(syscmd, "! --sport 1066 -j REDIRECT --to-port 1061");

      int r = system(syscmd);
    }
  }
 
  int m = system("screen -S borg -p0 -X stuff $'./borgPro\n'");

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
      sprintf(syscmd, "%s--sport %d ", syscmd, allRules[i].sport);

    if(allRules[i].dport != 0)
      sprintf(syscmd, "%s--dport %d ", syscmd, allRules[i].dport);

    if(allRules[i].src_addr[0] != 0)
      sprintf(syscmd, "%s-s %s ", syscmd, allRules[i].src_addr);
 
    if(allRules[i].dst_addr[0] != 0)
      sprintf(syscmd, "%s-d %s ", syscmd, allRules[i].dst_addr);

    strcat(syscmd, "-j QUEUE");

    int s = system(syscmd);
  }

  if(policy == 1)
  {
    waitForTimeout();
    normal();
  }
}

/* uses record id to replay */
void Ubora::replay(){
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
      sprintf(syscmd, "%s--sport %d ", syscmd, allRules[i].sport);

    if(allRules[i].dport != 0)
      sprintf(syscmd, "%s--dport %d ", syscmd, allRules[i].dport);

    if(allRules[i].src_addr[0] != 0)
      sprintf(syscmd, "%s-s %s ", syscmd, allRules[i].src_addr);

    if(allRules[i].dst_addr[0] != 0)
      sprintf(syscmd, "%s-d %s ", syscmd, allRules[i].dst_addr);

    strcat(syscmd, "-j QUEUE");

    int s = system(syscmd);
  }

  int m = system("screen -S mitm -p0 -X stuff $'./MITM\n'");

  for(std::vector<struct m_group>::size_type i = 0; i != allRules.size(); i++)
  {
    char syscmd[200];
    bzero(syscmd, 200);
    strcpy(syscmd, "iptables -t nat -I OUTPUT 1 -p tcp "); 
    
    if(allRules[i].dport != 0 || allRules[i].dst_addr[0] != 0)
    {
      if(allRules[i].dport != 0)
        sprintf(syscmd, "%s--dport %d ", syscmd, allRules[i].dport);

      if(allRules[i].dst_addr != 0)
        sprintf(syscmd, "%s-d %s ", syscmd, allRules[i].dst_addr);

      strcat(syscmd, "! --sport 1066 -j REDIRECT --to-port 1061");

      int r = system(syscmd);
    }
  }

  if(policy == 1)
  {
    waitForTimeout();
    normal();
  }
}

void Ubora::normal()
{
  FILE * modefile;
  if((modefile = fopen("mode.cfg", "w")) != NULL)
  {
    fprintf(modefile, "2");
    fclose(modefile);
  }

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
      sprintf(syscmd, "%s--sport %d ", syscmd, allRules[i].sport);

    if(allRules[i].dport != 0)
      sprintf(syscmd, "%s--dport %d ", syscmd, allRules[i].dport);

    if(allRules[i].src_addr[0] != 0)
      sprintf(syscmd, "%s-s %s ", syscmd, allRules[i].src_addr);

    if(allRules[i].dst_addr[0] != 0)
      sprintf(syscmd, "%s-d %s ", syscmd, allRules[i].dst_addr);
 
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
  
      if(allRules[i].dst_addr != 0)
        sprintf(syscmd, "%s-d %s ", syscmd, allRules[i].dst_addr);
  
      strcat(syscmd, "! --sport 1066 -j REDIRECT --to-port 1061");
  
      int r = system(syscmd);
    }
  }  
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
}

int main(int ARGC, char * ARGV[])
{
  char * allMyNodes[4];
  for(int i = 0; i < 4; i++)
  {
    allMyNodes[i] = (char *)malloc(30 * sizeof(char));
  }
  strcpy(allMyNodes[0], "kelley.r245.0");
  strcpy(allMyNodes[1], "kelley.r245.1");
  strcpy(allMyNodes[2], "kelley.r245.2");
  strcpy(allMyNodes[3], "kelley.r245.3");
  int numNodes = 4;

  printf("got allMyNodes\n");

  int uboraPort = 12911;

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in serv_addr;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(uboraPort);

  bind(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

  listen(sock, 10);

  unsigned long long recordtime, replaytime;
  double timeout = 0.0;
  int autotimeout = 0;
  Ubora myUbora;

  while(1)
  {
    int connfd = accept(sock, (struct sockaddr*)NULL, NULL);

    char recvBuff[100];

    do{
      bzero(recvBuff, 100);
      read(connfd, recvBuff, 100);
      int leng = strlen(recvBuff);
      char * notS = strstr(recvBuff, "timeout");

      if(leng > 0 && notS == NULL)
      {
        myUbora.propagate(recvBuff);
      }

      char * col = strstr(recvBuff, ":");

      if(leng > 0)
      {
        char * rep = strstr(recvBuff, "record");
        if(rep != NULL)
        {
          FILE * modeFile2;
          if((modeFile2 = fopen("mode.cfg", "w")) != NULL)
          {
            fprintf(modeFile2, "%d", 2);
            fclose(modeFile2);
          }

          int rhash = atoi(col+1);

          FILE * hashFile;
          if((hashFile = fopen("hashfile", "w")) != NULL)
          {
            fprintf(hashFile, "%d", rhash);
            fclose(hashFile);
          }

          myUbora.record();

          FILE * modeFile;
          if((modeFile = fopen("mode.cfg", "w")) != NULL)
          {
            fprintf(modeFile, "%d", 1);
            fclose(modeFile);
          }
        }
        else
        {
          rep = strstr(recvBuff, "replay");
          if(rep != NULL)
          {
            FILE * modeFile;
            if((modeFile = fopen("mode.cfg", "w")) != NULL)
            {
              fprintf(modeFile, "%d", 2);
              fclose(modeFile);
            }

            int rhash = atoi(col+1);

            FILE * hashFile;
            if((hashFile = fopen("hashfile", "w")) != NULL)
            {
              fprintf(hashFile, "%d", rhash);
              fclose(hashFile);
            }

            myUbora.replay();

            FILE * modeFile2;
            if((modeFile2 = fopen("mode.cfg", "w")) != NULL)
            {
              fprintf(modeFile2, "%d", 0);
              fclose(modeFile2);
            }
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
                  myUbora.setupUbora(allMyNodes, numNodes, uboraPort, autotimeout, timeout);
                }
                else
                {
                  pch = strstr(recvBuff, "file");
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
                  }
                }
              }
            }
          }
        }
      }
      else
      {
        printf("Something went wrong with message %s\n", recvBuff);
      }

    } while(recvBuff[0] != 0);

    close(connfd);
  }

  myUbora.closeUbora();
}
