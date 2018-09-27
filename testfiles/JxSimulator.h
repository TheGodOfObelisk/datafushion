#pragma once

#define SLEEP_TIME 3000

#import "C:\Program Files (x86)\Common Files\System\ado\msado15.dll" no_namespace rename("EOF", "adoEOF")rename("BOF", "adoBOF")


char g_sgmtUUID[20][64] = {0};
char g_siteUUID[20][64] = {0};
char g_hostUUID[250][64] = {0};
char g_routerUUID[10][64] = {0};
char g_entityUUID[20][64] = {0};
char g_taskUUID[200][64] = {0};
char g_injectionUUID[64] = {0};

int g_ip3[20] = {0};
int g_ip4[20][10] = {0};

char g_protocol[10][10] = {"TELNET", "SNMP", "ICMP", "ARP", "HTTP", "FTP", "POP3", "SMTP", "RTP", "SIP"};


BOOL InitDataBase(_ConnectionPtr& pConn);						//Initialize DB
BOOL InjectInitAgent(_ConnectionPtr pConn);					//Inject first agents
BOOL InitSniff(_ConnectionPtr pConn);							//Execute first detection
BOOL InitDecision(_ConnectionPtr pConn);						//Execute first decision
BOOL Sniff_2(_ConnectionPtr pConn);		
BOOL Decision_2(_ConnectionPtr pConn);		
BOOL Sniff_3(_ConnectionPtr pConn);		
BOOL Decision_3(_ConnectionPtr pConn);	

void GetUUID(char* uuidBuf);																																		//get UUID
BOOL UpdateTask(_ConnectionPtr pConn, char* type, char* period, char* process, char* uuid);											//update task
BOOL AddSegment(_ConnectionPtr pConn, int Seq, int ip3);																								//Ìí¼ÓÍø¶Î