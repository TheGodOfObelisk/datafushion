//2018-03-16：态势展示模拟器，x64编译成功
//2018-03-23：部署新Agent
//2018-03-26：SITE/SEGMENT/SITE_SEGMENT_REL成对出现
//2018-03-29：五轮，3-3-4-5-5，共20个子网


#include <stdio.h>
#include "JxSimulator.h"


int main()
{
	CoInitialize(NULL);
	_ConnectionPtr pConn(__uuidof(Connection));
	_CommandPtr pCmd(__uuidof(Command));
	_RecordsetPtr pRst(__uuidof(Recordset));
	
	//Initialize Database
	if( !InitDataBase(pConn) )
	{
		printf("Fail to initialize database!\n");
		return -1;
	}
	printf("Database has been initialized!\n");


	//Insert First Agent
	if( !InjectInitAgent(pConn) )
	{
		printf("Fail to insert first agents!\n");
		return -1;
	}
	printf("First agents have been inserted!\n");


	//Execute First Sniff Task
	if( !InitSniff(pConn) )
	{
		printf("ExeInitDetect failed!\n");
		return -1;
	}
	printf("ExeInitDetect OK!\n");
	

	//Execute First Decision
	if( !InitDecision(pConn) )
	{
		printf("ExeInitDecision failed!\n");
		return -1;
	}
	printf("ExeInitDecision OK!\n");

	//Execute Second Sniff
	if( !Sniff_2(pConn) )
	{
		printf("Sniff_2 failed!\n");
		return -1;
	}
	printf("Sniff_2 OK!\n");


	//Execute Second Decision
	if( !Decision_2(pConn) )
	{
		printf("Decision_2 failed!\n");
		return -1;
	}
	printf("Sniff_2 OK!\n");

	//Execute Sniff_3
	if( !Sniff_3(pConn) )
	{
		printf("Sniff_3 failed!\n");
		return -1;
	}
	printf("Sniff_3 OK!\n");

	//Execute Second Decision
	if( !Decision_3(pConn) )
	{
		printf("Decision_3 failed!\n");
		return -1;
	}
	printf("Decision_3 OK!\n");

	return 0;
}


//Initialize database
BOOL InitDataBase(_ConnectionPtr& pConn)
{
	HRESULT hr;
	char sqlBuf[1024] = {0};
	char uuidBuf[64] = {0};

	//Connect to database
	try
	{
		pConn->ConnectionString = "Provider=OraOLEDB.Oracle.1;User ID=nsds;Password=123";
		HRESULT hr = pConn->Open("", "", "", adConnectUnspecified);
		if( FAILED(hr) )
		{
			return FALSE;
		}
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}

	//IP3
	for(int i=0; i<20; i++)
		g_ip3[i] = 1+i*12;

	//IP4
	for(int i=0; i<20; i++)
		for(int j=0; j<10; j++)
			g_ip4[i][j] = i+23*j+2;

	return TRUE;
}


//Inject Initial Agents
BOOL InjectInitAgent(_ConnectionPtr pConn)
{
	HRESULT hr;
	char sqlBuf[1024] = {0};
	char uuidBuf[64] = {0};

	//Insert initial hosts
	try
	{ 
		//host:3-0
		GetUUID(uuidBuf);
		memcpy_s(&g_hostUUID[3*10][0], sizeof(g_hostUUID[3*10]), uuidBuf, sizeof(uuidBuf));
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into HOST(ID, UPDATED, OS, NET, IP, PORT, BUSINESSTYPE, MAC, PROCESS, ATTACKED, KEY, ENTRY) Values('%s', '1', 'Win7', '192.168.%d.0', '192.168.%d.%d', '80', 'Unknown', '00-01-03-04-05-06', 'iexplorer.exe', '0', '0', '1')", uuidBuf, g_ip3[3], g_ip3[3], g_ip4[3][0]);
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to insert HOST!\n");
			return FALSE;
		}

		//host:6-0
		GetUUID(uuidBuf);
		memcpy_s(&g_hostUUID[6*10][0], sizeof(g_hostUUID[6*10]), uuidBuf, sizeof(uuidBuf));
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into HOST(ID, UPDATED, OS, NET, IP, PORT, BUSINESSTYPE, MAC, PROCESS, ATTACKED, KEY, ENTRY) Values('%s', '1', 'Win7', '192.168.%d.0', '192.168.%d.%d', '80', 'Unknown', '00-01-03-04-05-06', 'iexplorer.exe', '0', '0', '1')", uuidBuf, g_ip3[6], g_ip3[6], g_ip4[6][0]);
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to insert HOST!\n");
			return FALSE;
		}

		//host:9-0
		GetUUID(uuidBuf);
		memcpy_s(&g_hostUUID[9*10][0], sizeof(g_hostUUID[9*10]), uuidBuf, sizeof(uuidBuf));
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into HOST(ID, UPDATED, OS, NET, IP, PORT, BUSINESSTYPE, MAC, PROCESS, ATTACKED, KEY, ENTRY) Values('%s', '1', 'Win7', '192.168.%d.0', '192.168.%d.%d', '80', 'Unknown', '00-01-03-04-05-06', 'iexplorer.exe', '0', '0', '1')", uuidBuf, g_ip3[9], g_ip3[9], g_ip4[9][0]);
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to insert HOST!\n");
			return FALSE;
		}
		
		printf("Hosts appear!\n");
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}
	Sleep(5000);


	//Insert sat injection
	try
	{ 
		GetUUID(uuidBuf);
		memcpy_s(g_injectionUUID, sizeof(g_injectionUUID), uuidBuf, sizeof(uuidBuf));
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into INJECTION(ID, UPDATED, TARGET_ID, PERIOD) Values('%s', '1', '%s', 'start')", uuidBuf, g_hostUUID[3*10]);			
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("插入INJECTION失败！\n");
			return FALSE;
		}
		printf("SAT注入中……\n");
		Sleep(10000);
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}


	//Insert initial agents
	try
	{
		for(int i=0; i<3; i++)
		{
			//add new segments
			if( !AddSegment(pConn, (i+1)*3, g_ip3[(i+1)*3]) )
			{
				printf("Fail to add new segments!\n");
				return FALSE;
			}
			Sleep(3000);

			//SEGMENT_HOST_REL needed
			GetUUID(uuidBuf);
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SEGMENT_HOST_REL(ID, UPDATED, SEGMENT_ID, HOST_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_sgmtUUID[(i+1)*3], g_hostUUID[(i+1)*30]);			
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert SEGMENT_HOST_REL!\n");
				return FALSE;
			}

			//ENTITY
			GetUUID(uuidBuf);
			memcpy_s(&g_entityUUID[(i+1)*3][0], sizeof(g_entityUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into ENTITY(ID, UPDATED, ONLINE_TIME, HOST_ID, NUM, STATUS) Values('%s', '1', TO_TIMESTAMP('2018/03/15 20:18:00', 'YYYY/MM/DD HH24:MI:SS'), '%s', %d, 'online')", uuidBuf, g_hostUUID[(i+1)*30], i+1);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert ENTITY!\n");
				return FALSE;
			}
			Sleep(3000);
		}
		printf("Agents appear!\n");

		//update INJECTION to stop SAT
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Update INJECTION Set UPDATED='1', PERIOD='done' Where ID='%s' ", g_injectionUUID);	
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("更新INJECTION失败！\n");
			return FALSE;
		}
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}


	//to make agent net
	try
	{
		for(int i=0; i<3; i++)
		{
			//TASK
			GetUUID(uuidBuf);
			memcpy_s(&g_taskUUID[i][0], sizeof(g_taskUUID[i]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into TASK(ID, UPDATED, EXECUTOR_ID, TYPE, PERIOD, PROCESS) Values('%s', '1', '%s', '嗅探分析', 'start', '正在构建自组织网络')", uuidBuf, g_entityUUID[(i+1)*3]);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert TASK!\n");
				return FALSE;
			}
		}
		printf("Task appear!\n");
		Sleep(10000);
		//工具关系表
		//ENTITY_ENTITY_REL
		GetUUID(uuidBuf);
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into ENTITY_ENTITY_REL(ID, UPDATED, PARENT_ID, CHILD_ID) Values('%s', '1', '%s', '%s')", uuidBuf, g_entityUUID[3], g_entityUUID[6]);		
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to insert ENTITY_ENTITY_REL!\n");
			return FALSE;
		}
		Sleep(5000);

		GetUUID(uuidBuf);
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into ENTITY_ENTITY_REL(ID, UPDATED, PARENT_ID, CHILD_ID) Values('%s', '1', '%s', '%s')", uuidBuf, g_entityUUID[3], g_entityUUID[9]);		
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to insert ENTITY_ENTITY_REL!\n");
			return FALSE;
		}
		Sleep(5000);

		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "嗅探分析", "done", "正在构建自组织网络", g_taskUUID[i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(3000);
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}

	return TRUE;
}


//Execute first detection, to appear 3 subnets
BOOL InitSniff(_ConnectionPtr pConn)
{
	HRESULT hr;
	char sqlBuf[1024] = {0};
	char uuidBuf[64] = {0};
	int hostSeq = 0;	//Host_ID sequence


	//Insert new detected nodes
	try
	{
		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "嗅探分析", "start", "正在探测存活主机", g_taskUUID[i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(8000);

		//Insert hosts
		for(int i=0; i<3; i++)
		{
			for(int j=1; j<10; j++)
			{
				GetUUID(uuidBuf);
				memcpy_s(&g_hostUUID[(i+1)*30+j][0], sizeof(g_hostUUID[0]), uuidBuf, sizeof(uuidBuf));
				sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into HOST(ID, UPDATED, OS, NET, IP, PORT, BUSINESSTYPE, MAC, PROCESS, ATTACKED, KEY, ENTRY) Values('%s', '1', 'Win7', '192.168.%d.0', '192.168.%d.%d', '80', 'Unknown', '00-01-03-04-05-06', 'iexplorer.exe', '0', '0', '0')", uuidBuf, g_ip3[3+i*3], g_ip3[3+i*3], g_ip4[3+i*3][j]);
				hr = pConn->Execute(sqlBuf, NULL, adCmdText);
				if( FAILED(hr) )
				{
					printf("Fail to insert HOST!\n");
					return FALSE;
				}
				Sleep(500);
			}
		}

		//Insert hosts
		for(int i=0; i<3; i++)
		{
			for(int j=0; j<5; j++)
			{
				GetUUID(uuidBuf);
				memcpy_s(&g_hostUUID[40+i*30+j][0], sizeof(g_hostUUID[0]), uuidBuf, sizeof(uuidBuf));
				sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into HOST(ID, UPDATED, OS, NET, IP, PORT, BUSINESSTYPE, MAC, PROCESS, ATTACKED, KEY, ENTRY) Values('%s', '1', 'Win7', '192.168.%d.0', '192.168.%d.%d', '80', 'Unknown', '00-01-03-04-05-06', 'iexplorer.exe', '0', '0', '0')", uuidBuf, g_ip3[4+i*3], g_ip3[4+i*3], g_ip4[4+i*3][j]);
				hr = pConn->Execute(sqlBuf, NULL, adCmdText);
				if( FAILED(hr) )
				{
					printf("Fail to insert HOST!\n");
					return FALSE;
				}
				Sleep(500);
			}
		}

		//Insert routers
		for(int i=0; i<3; i++)
		{
			GetUUID(uuidBuf);
			memcpy_s(&g_routerUUID[i*3+3][0], sizeof(g_routerUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into ROUTER(ID, UPDATED, OS, IP, NET, MAC, ATTACKED, KEY ) Values('%s', '1', 'Cisco iOS', '192.168.%d.1', '192.168.%d.0', 'aa-bb-cc-dd-ee-ff', '0', '0')", uuidBuf, g_ip3[i*3+3], g_ip3[i*3+3]);			
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert ROUTER!\n");
				return FALSE;
			}
			Sleep(500);
		}

		//add segment_router_rel
		for(int i=0; i<3; i++)
		{
			//SEGMENT_ROUTER_REL
			GetUUID(uuidBuf);
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SEGMENT_ROUTER_REL(ID, UPDATED, SEGMENT_ID, ROUTER_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_sgmtUUID[3+i*3], g_routerUUID[3+i*3]);			
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert SEGMENT_ROUTER_REL!\n");
				return FALSE;
			}
			Sleep(500);
		}

		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "嗅探分析", "done", "正在探测存活主机", g_taskUUID[i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(5000);
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}


	//try to get router table
	try
	{
		//TASK instruction
		for(int i=0; i<3; i++)
		{
			GetUUID(uuidBuf);
			memcpy_s(&g_taskUUID[i+3][0], sizeof(g_taskUUID[i+3]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into TASK(ID, UPDATED, EXECUTOR_ID, TYPE, PERIOD, PROCESS, TARGET_ID) Values('%s', '1', '%s', '指令传输', 'start', '正在尝试获取路由表', '%s')", uuidBuf, g_entityUUID[(i+1)*3], g_routerUUID[(i+1)*3]);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert TASK!\n");
				return FALSE;
			}
		}
		Sleep(15000);
		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "指令传输", "done", "正在尝试获取路由表", g_taskUUID[i+3]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(3000);

		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "嗅探分析", "start", "路由表获取失败", g_taskUUID[i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(5000);

		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "嗅探分析", "done", "路由表获取失败", g_taskUUID[i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(5000);
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}


	//Detection result sharing
	try
	{
		//Insert task
		GetUUID(uuidBuf);
		memcpy_s(&g_taskUUID[6][0], sizeof(g_taskUUID[0]), uuidBuf, sizeof(uuidBuf));
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into TASK(ID, UPDATED, EXECUTOR_ID, TYPE, PERIOD, PROCESS, TARGET_ID) Values('%s', '1', '%s', '文件传输', 'start', '正在回传探测结果', '%s')", uuidBuf, g_entityUUID[6], g_hostUUID[30]);		
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to insert TASK!\n");
			return FALSE;
		}
		//Insert task
		GetUUID(uuidBuf);
		memcpy_s(&g_taskUUID[7][0], sizeof(g_taskUUID[0]), uuidBuf, sizeof(uuidBuf));
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into TASK(ID, UPDATED, EXECUTOR_ID, TYPE, PERIOD, PROCESS, TARGET_ID) Values('%s', '1', '%s', '文件传输', 'start', '正在回传探测结果', '%s')", uuidBuf, g_entityUUID[9], g_hostUUID[30]);		
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to insert TASK!\n");
			return FALSE;
		}
		//update task
		if(!UpdateTask(pConn, "嗅探分析", "start", "正在收集探测结果", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(15000);

		//Update task
		if(!UpdateTask(pConn, "文件传输", "done", "正在回传探测结果", g_taskUUID[6]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		//Update task
		if(!UpdateTask(pConn, "文件传输", "done", "正在回传探测结果", g_taskUUID[7]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		//update task
		if(!UpdateTask(pConn, "嗅探分析", "done", "正在收集探测结果", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(5000);
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}

	return TRUE;
}


//First Decison
BOOL InitDecision(_ConnectionPtr pConn)
{
	HRESULT hr;
	char sqlBuf[1024] = {0};
	char uuidBuf[64] = {0};


	//Insert segment、segment_rel
	try
	{
		//Update task
		if(!UpdateTask(pConn, "嗅探分析", "start", "正在还原网络拓扑", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(10000);

		//add new segments
		for(int i=0; i<3; i++)
		{
			if( !AddSegment(pConn, 4+i*3, g_ip3[4+i*3]) )
			{
				printf("Fail to add new segments!\n");
				return FALSE;
			}
		}

		//add segment_host_rel
		for(int i=0; i<3; i++)
		{
			for(int j=1; j<10; j++)
			{
				GetUUID(uuidBuf);
				sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SEGMENT_HOST_REL(ID, UPDATED, SEGMENT_ID, HOST_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_sgmtUUID[3+i*3], g_hostUUID[30+i*30+j]);			
				hr = pConn->Execute(sqlBuf, NULL, adCmdText);
				if( FAILED(hr) )
				{
					printf("Fail to insert SEGMENT_HOST_REL!\n");
					return FALSE;
				}
				Sleep(500);
			}
		}

		//add segment_host_rel
		for(int i=0; i<3; i++)
		{
			for(int j=0; j<5; j++)
			{
				GetUUID(uuidBuf);
				sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SEGMENT_HOST_REL(ID, UPDATED, SEGMENT_ID, HOST_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_sgmtUUID[4+i*3], g_hostUUID[40+i*30+j]);			
				hr = pConn->Execute(sqlBuf, NULL, adCmdText);
				if( FAILED(hr) )
				{
					printf("Fail to insert SEGMENT_HOST_REL!\n");
					return FALSE;
				}
				Sleep(500);
			}
		}

		//Update task
		if(!UpdateTask(pConn, "嗅探分析", "done", "正在还原网络拓扑", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(3000);
	}//try
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}


	//Set new agents
	try
	{
		//Update task
		if(!UpdateTask(pConn, "嗅探分析", "start", "正在决策选取新的Agent", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(10000);

		//Update task
		if(!UpdateTask(pConn, "嗅探分析", "done", "正在决策选取新的Agent", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(3000);

		//Insert task
		for(int i=0; i<3; i++)
		{
			GetUUID(uuidBuf);
			memcpy_s(&g_taskUUID[9+i][0], sizeof(g_taskUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into TASK(ID, UPDATED, EXECUTOR_ID, TYPE, PERIOD, PROCESS, TARGET_ID) Values('%s', '1', '%s', '渗透扩散', 'start', '正在部署新的Agent', '%s')", uuidBuf, g_entityUUID[i*3+3], g_hostUUID[30*i+40]);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert TASK!\n");
				return FALSE;
			}
		}
		Sleep(15000);
		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "渗透扩散", "done", "正在部署新的Agent", g_taskUUID[9+i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(3000);

		//Agents get online
		for(int i=0; i<3; i++)
		{
			GetUUID(uuidBuf);
			memcpy_s(&g_entityUUID[i*3+4][0], sizeof(g_entityUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into ENTITY(ID, UPDATED, ONLINE_TIME, HOST_ID, NUM, STATUS) Values('%s', '1', TO_TIMESTAMP('2018/03/15 20:18:00', 'YYYY/MM/DD HH24:MI:SS'), '%s', %d, 'online')", uuidBuf, g_hostUUID[30*i+40], i+4);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert ENTITY!\n");
				return FALSE;
			}
			Sleep(1000);

			GetUUID(uuidBuf);
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into ENTITY_ENTITY_REL(ID, UPDATED, PARENT_ID, CHILD_ID) Values('%s', '1', '%s', '%s')", uuidBuf, g_entityUUID[i*3+3], g_entityUUID[i*3+4]);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert ENTITY_ENTITY_REL!\n");
				return FALSE;
			}
		}
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}


	return TRUE;
}


//The second detection, to appear 3 subnets
BOOL Sniff_2(_ConnectionPtr pConn)
{
	HRESULT hr;
	char sqlBuf[1024] = {0};
	char uuidBuf[64] = {0};

	try
	{
		//Insert task
		for(int i=0; i<3; i++)
		{
			GetUUID(uuidBuf);
			memcpy_s(&g_taskUUID[12+i][0], sizeof(g_taskUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into TASK(ID, UPDATED, EXECUTOR_ID, TYPE, PERIOD, PROCESS) Values('%s', '1', '%s', '嗅探分析', 'start', '正在探测存活主机')", uuidBuf, g_entityUUID[i*3+4]);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert TASK!\n");
				return FALSE;
			}
		}
		Sleep(8000);

		//Insert hosts
		for(int i=0; i<3; i++)
		{
			for(int j=5; j<10; j++)
			{
				GetUUID(uuidBuf);
				memcpy_s(&g_hostUUID[i*30+40+j][0], sizeof(g_hostUUID[0]), uuidBuf, sizeof(uuidBuf));
				sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into HOST(ID, UPDATED, OS, NET, IP, PORT, BUSINESSTYPE, MAC, PROCESS, ATTACKED, KEY, ENTRY) Values('%s', '1', 'Win7', '192.168.%d.0', '192.168.%d.%d', '80', 'Unknown', '00-01-03-04-05-06', 'iexplorer.exe', '0', '0', '0')", uuidBuf, g_ip3[4+i*3], g_ip3[4+i*3], g_ip4[4+i*3][j]);
				hr = pConn->Execute(sqlBuf, NULL, adCmdText);
				if( FAILED(hr) )
				{
					printf("Fail to insert HOST!\n");
					return FALSE;
				}
				Sleep(500);
			}
		}

		//Insert hosts
		for(int i=0; i<3; i++)
		{
			for(int j=0; j<5; j++)
			{
				GetUUID(uuidBuf);
				memcpy_s(&g_hostUUID[i*30+50+j][0], sizeof(g_hostUUID[0]), uuidBuf, sizeof(uuidBuf));
				sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into HOST(ID, UPDATED, OS, NET, IP, PORT, BUSINESSTYPE, MAC, PROCESS, ATTACKED, KEY, ENTRY) Values('%s', '1', 'Win7', '192.168.%d.0', '192.168.%d.%d', '80', 'Unknown', '00-01-03-04-05-06', 'iexplorer.exe', '0', '0', '0')", uuidBuf, g_ip3[5+i*3], g_ip3[5+i*3], g_ip4[5+i*3][j]);
				hr = pConn->Execute(sqlBuf, NULL, adCmdText);
				if( FAILED(hr) )
				{
					printf("Fail to insert HOST!\n");
					return FALSE;
				}
				Sleep(500);
			}
		}

		//Insert routers
		for(int i=0; i<3; i++)
		{
			GetUUID(uuidBuf);
			memcpy_s(&g_routerUUID[i*3+4][0], sizeof(g_routerUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into ROUTER(ID, UPDATED, OS, IP, NET, MAC, ATTACKED, KEY ) Values('%s', '1', 'Cisco iOS', '192.168.%d.1', '192.168.%d.0', 'aa-bb-cc-dd-ee-ff', '0', '0')", uuidBuf, g_ip3[i*3+4], g_ip3[i*3+4]);			
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert ROUTER!\n");
				return FALSE;
			}
			Sleep(500);
		}

		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "嗅探分析", "done", "正在探测存活主机", g_taskUUID[12+i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(5000);

	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}


	//try to get router table
	try
	{
		//add segment_router_rel
		for(int i=0; i<3; i++)
		{
			//SEGMENT_ROUTER_REL
			GetUUID(uuidBuf);
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SEGMENT_ROUTER_REL(ID, UPDATED, SEGMENT_ID, ROUTER_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_sgmtUUID[4+i*3], g_routerUUID[4+i*3]);			
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert SEGMENT_ROUTER_REL!\n");
				return FALSE;
			}
			Sleep(500);
		}

		//TASK instruction
		for(int i=0; i<3; i++)
		{
			GetUUID(uuidBuf);
			memcpy_s(&g_taskUUID[15+i][0], sizeof(g_taskUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into TASK(ID, UPDATED, EXECUTOR_ID, TYPE, PERIOD, PROCESS, TARGET_ID) Values('%s', '1', '%s', '指令传输', 'start', '正在尝试获取路由表', '%s')", uuidBuf, g_entityUUID[3*i+4], g_routerUUID[3*i+4]);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert TASK!\n");
				return FALSE;
			}
		}
		Sleep(10000);
		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "指令传输", "done", "正在尝试获取路由表", g_taskUUID[i+15]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(3000);

		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "嗅探分析", "start", "路由表获取失败", g_taskUUID[i+12]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(5000);

		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "嗅探分析", "done", "路由表获取失败", g_taskUUID[i+12]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(5000);
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}


	//Detection result sharing
	try
	{
		for(int i=0; i<3; i++)
		{
			//Insert task
			GetUUID(uuidBuf);
			memcpy_s(&g_taskUUID[18+i][0], sizeof(g_taskUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into TASK(ID, UPDATED, EXECUTOR_ID, TYPE, PERIOD, PROCESS, TARGET_ID) Values('%s', '1', '%s', '文件传输', 'start', '正在回传探测结果', '%s')", uuidBuf, g_entityUUID[4+i*3], g_hostUUID[30+30*i]);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert TASK!\n");
				return FALSE;
			}
		}
		for(int i=0; i<2; i++)
		{
			//update task
			if(!UpdateTask(pConn, "文件传输", "start", "正在回传探测结果", g_taskUUID[6+i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		//update task
		if(!UpdateTask(pConn, "嗅探分析", "start", "正在收集探测结果", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(15000);

		//task done
		for(int i=0; i<3; i++)
		{
			//update task
			if(!UpdateTask(pConn, "文件传输", "done", "正在回传探测结果", g_taskUUID[18+i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}

			//update task
			if(!UpdateTask(pConn, "文件传输", "done", "正在回传探测结果", g_taskUUID[6+i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		//update task
		if(!UpdateTask(pConn, "嗅探分析", "done", "正在收集探测结果", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(3000);
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}

	return TRUE;
}



//The second detection
BOOL Decision_2(_ConnectionPtr pConn)
{
	HRESULT hr;
	char sqlBuf[1024] = {0};
	char uuidBuf[64] = {0};


	//Insert segment、segment_rel
	try
	{
		//Update task
		if(!UpdateTask(pConn, "嗅探分析", "start", "正在还原网络拓扑", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(10000);

		//add new segments
		for(int i=0; i<3; i++)
		{
			if( !AddSegment(pConn, 5+i*3, g_ip3[5+i*3]) )
			{
				printf("Fail to add new segments!\n");
				return FALSE;
			}
		}

		//add segment_host_rel
		for(int i=0; i<3; i++)
		{
			for(int j=5; j<10; j++)
			{
				GetUUID(uuidBuf);
				sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SEGMENT_HOST_REL(ID, UPDATED, SEGMENT_ID, HOST_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_sgmtUUID[4+i*3], g_hostUUID[40+i*30+j]);			
				hr = pConn->Execute(sqlBuf, NULL, adCmdText);
				if( FAILED(hr) )
				{
					printf("Fail to insert SEGMENT_HOST_REL!\n");
					return FALSE;
				}
				Sleep(500);
			}
		}

		//add segment_host_rel
		for(int i=0; i<3; i++)
		{
			for(int j=0; j<5; j++)
			{
				GetUUID(uuidBuf);
				sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SEGMENT_HOST_REL(ID, UPDATED, SEGMENT_ID, HOST_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_sgmtUUID[5+i*3], g_hostUUID[50+i*30+j]);			
				hr = pConn->Execute(sqlBuf, NULL, adCmdText);
				if( FAILED(hr) )
				{
					printf("Fail to insert SEGMENT_HOST_REL!\n");
					return FALSE;
				}
				Sleep(500);
			}
		}

		//Update task
		if(!UpdateTask(pConn, "嗅探分析", "done", "正在还原网络拓扑", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(3000);
	}//try
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}


	//Set new agents
	try
	{
		//Update task
		if(!UpdateTask(pConn, "嗅探分析", "start", "正在决策选取新的Agent", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(10000);

		//Update task
		if(!UpdateTask(pConn, "嗅探分析", "done", "正在决策选取新的Agent", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(3000);

		//Insert task
		for(int i=0; i<3; i++)
		{
			GetUUID(uuidBuf);
			memcpy_s(&g_taskUUID[21+i][0], sizeof(g_taskUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into TASK(ID, UPDATED, EXECUTOR_ID, TYPE, PERIOD, PROCESS, TARGET_ID) Values('%s', '1', '%s', '渗透扩散', 'start', '正在部署新的Agent', '%s')", uuidBuf, g_entityUUID[i*3+4], g_hostUUID[30*i+50]);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert TASK!\n");
				return FALSE;
			}
		}
		Sleep(10000);
		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "渗透扩散", "done", "正在部署新的Agent", g_taskUUID[21+i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(3000);

		//Agents get online
		for(int i=0; i<3; i++)
		{
			GetUUID(uuidBuf);
			memcpy_s(&g_entityUUID[i*3+5][0], sizeof(g_entityUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into ENTITY(ID, UPDATED, ONLINE_TIME, HOST_ID, NUM, STATUS) Values('%s', '1', TO_TIMESTAMP('2018/03/15 20:18:00', 'YYYY/MM/DD HH24:MI:SS'), '%s', %d, 'online')", uuidBuf, g_hostUUID[30*i+50], i+7);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert ENTITY!\n");
				return FALSE;
			}
			Sleep(1000);

			GetUUID(uuidBuf);
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into ENTITY_ENTITY_REL(ID, UPDATED, PARENT_ID, CHILD_ID) Values('%s', '1', '%s', '%s')", uuidBuf, g_entityUUID[i*3+4], g_entityUUID[i*3+5]);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert ENTITY_ENTITY_REL!\n");
				return FALSE;
			}
		}
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}

	return TRUE;
}


//to appear 5 segments
BOOL Sniff_3(_ConnectionPtr pConn)
{
	HRESULT hr;
	char sqlBuf[1024] = {0};
	char uuidBuf[64] = {0};

	try
	{
		//Insert task
		for(int i=0; i<3; i++)
		{
			GetUUID(uuidBuf);
			memcpy_s(&g_taskUUID[24+i][0], sizeof(g_taskUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into TASK(ID, UPDATED, EXECUTOR_ID, TYPE, PERIOD, PROCESS) Values('%s', '1', '%s', '嗅探分析', 'start', '正在探测存活主机')", uuidBuf, g_entityUUID[i*3+5]);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert TASK!\n");
				return FALSE;
			}
		}
		Sleep(8000);

		//Insert the rest hosts
		for(int i=0; i<3; i++)
		{
			for(int j=5; j<10; j++)
			{
				GetUUID(uuidBuf);
				memcpy_s(&g_hostUUID[i*30+50+j][0], sizeof(g_hostUUID[0]), uuidBuf, sizeof(uuidBuf));
				sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into HOST(ID, UPDATED, OS, NET, IP, PORT, BUSINESSTYPE, MAC, PROCESS, ATTACKED, KEY, ENTRY) Values('%s', '1', 'Win7', '192.168.%d.0', '192.168.%d.%d', '80', 'Unknown', '00-01-03-04-05-06', 'iexplorer.exe', '0', '0', '0')", uuidBuf, g_ip3[5+i*3], g_ip3[5+i*3], g_ip4[5+i*3][j]);
				hr = pConn->Execute(sqlBuf, NULL, adCmdText);
				if( FAILED(hr) )
				{
					printf("Fail to insert HOST!\n");
					return FALSE;
				}
				Sleep(500);
			}
		}

		//Insert routers
		for(int i=0; i<3; i++)
		{
			GetUUID(uuidBuf);
			memcpy_s(&g_routerUUID[i*3+5][0], sizeof(g_routerUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into ROUTER(ID, UPDATED, OS, IP, NET, MAC, ATTACKED, KEY ) Values('%s', '1', 'Cisco iOS', '192.168.%d.1', '192.168.%d.0', 'aa-bb-cc-dd-ee-ff', '0', '0')", uuidBuf, g_ip3[i*3+5], g_ip3[i*3+5]);			
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert ROUTER!\n");
				return FALSE;
			}
			Sleep(500);
		}

		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "嗅探分析", "done", "正在探测存活主机", g_taskUUID[24+i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(5000);

	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}


	//try to get router table
	try
	{
		//add segment_router_rel
		for(int i=0; i<3; i++)
		{
			//SEGMENT_ROUTER_REL
			GetUUID(uuidBuf);
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SEGMENT_ROUTER_REL(ID, UPDATED, SEGMENT_ID, ROUTER_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_sgmtUUID[i*3+5], g_routerUUID[i*3+5]);			
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert SEGMENT_ROUTER_REL!\n");
				return FALSE;
			}
			Sleep(500);
		}

		//TASK instruction
		for(int i=0; i<3; i++)
		{
			GetUUID(uuidBuf);
			memcpy_s(&g_taskUUID[27+i][0], sizeof(g_taskUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into TASK(ID, UPDATED, EXECUTOR_ID, TYPE, PERIOD, PROCESS, TARGET_ID) Values('%s', '1', '%s', '指令传输', 'start', '正在尝试获取路由表', '%s')", uuidBuf, g_entityUUID[i*3+5], g_routerUUID[i*3+5]);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert TASK!\n");
				return FALSE;
			}
		}
		Sleep(10000);

		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "指令传输", "done", "正在尝试获取路由表", g_taskUUID[i+27]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "嗅探分析", "start", "路由表获取成功", g_taskUUID[i+24]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(5000);

		//Update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "嗅探分析", "done", "路由表获取成功", g_taskUUID[i+24]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		Sleep(5000);
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}


	//Detection result sharing
	try
	{
		for(int i=0; i<3; i++)
		{
			//Insert task
			GetUUID(uuidBuf);
			memcpy_s(&g_taskUUID[30+i][0], sizeof(g_taskUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into TASK(ID, UPDATED, EXECUTOR_ID, TYPE, PERIOD, PROCESS, TARGET_ID) Values('%s', '1', '%s', '文件传输', 'start', '正在回传探测结果', '%s')", uuidBuf, g_entityUUID[5+i*3], g_hostUUID[40+30*i]);		
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert TASK!\n");
				return FALSE;
			}
		}
		//update task
		for(int i=0; i<3; i++)
		{
			if(!UpdateTask(pConn, "文件传输", "start", "正在回传探测结果", g_taskUUID[18+i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		//update task
		for(int i=0; i<2; i++)
		{
			if(!UpdateTask(pConn, "文件传输", "start", "正在回传探测结果", g_taskUUID[6+i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		//update task
		if(!UpdateTask(pConn, "嗅探分析", "start", "正在收集探测结果", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(20000);

		//task done
		for(int i=0; i<3; i++)
		{
			//update task
			if(!UpdateTask(pConn, "文件传输", "done", "正在回传探测结果", g_taskUUID[30+i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}

			//update task
			if(!UpdateTask(pConn, "文件传输", "done", "正在回传探测结果", g_taskUUID[18+i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		//update task
		for(int i=0; i<2; i++)
		{
			if(!UpdateTask(pConn, "文件传输", "done", "正在回传探测结果", g_taskUUID[6+i]))
			{
				printf("Fail to update task!\n");
				return FALSE;
			}
		}
		//update task
		if(!UpdateTask(pConn, "嗅探分析", "done", "正在收集探测结果", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(3000);
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}

	return TRUE;
}


BOOL Decision_3(_ConnectionPtr pConn)
{
	HRESULT hr;
	char sqlBuf[1024] = {0};
	char uuidBuf[64] = {0};


	//Insert segment、segment_rel
	try
	{
		//Update task
		if(!UpdateTask(pConn, "嗅探分析", "start", "正在还原网络拓扑", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(10000);

		//add segment_host_rel
		for(int i=0; i<3; i++)
		{
			for(int j=5; j<10; j++)
			{
				GetUUID(uuidBuf);
				sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SEGMENT_HOST_REL(ID, UPDATED, SEGMENT_ID, HOST_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_sgmtUUID[5+i*3], g_hostUUID[50+i*30+j]);			
				hr = pConn->Execute(sqlBuf, NULL, adCmdText);
				if( FAILED(hr) )
				{
					printf("Fail to insert SEGMENT_HOST_REL!\n");
					return FALSE;
				}
				Sleep(500);
			}
		}
	}//try
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}


	//Update router
	try
	{
		//Delete all current routers
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Delete from ROUTER");		
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to delete ROUTER!\n");
			return FALSE;
		}

		//Insert new routers
		for(int i=0; i<3; i++)
		{
			GetUUID(uuidBuf);
			memcpy_s(&g_routerUUID[i+9][0], sizeof(g_routerUUID[0]), uuidBuf, sizeof(uuidBuf));
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into ROUTER(ID, UPDATED, OS, IP, NET, MAC, ATTACKED, KEY ) Values('%s', '1', 'Cisco iOS', '192.168.%d.1/192.168.%d.1/192.168.%d.1', '192.168.%d.0/192.168.%d.0/192.168.%d.0', 'aa-bb-cc-dd-ee-ff', '0', '0')", uuidBuf, g_ip3[37+36*i], g_ip3[49+36*i], g_ip3[61+36*i], g_ip3[37+36*i], g_ip3[49+36*i], g_ip3[61+36*i]);			
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert ROUTER!\n");
				return FALSE;
			}
		}

		//Insert //SEGMENT_ROUTER_REL
		for(int i=0; i<3; i++)
		{
			GetUUID(uuidBuf);
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SEGMENT_ROUTER_REL(ID, UPDATED, SEGMENT_ID, ROUTER_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_sgmtUUID[3+i*3], g_routerUUID[9]);	
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert SEGMENT_ROUTER_REL!\n");
				return FALSE;
			}
			Sleep(1000);

			GetUUID(uuidBuf);
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SEGMENT_ROUTER_REL(ID, UPDATED, SEGMENT_ID, ROUTER_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_sgmtUUID[4+i*3], g_routerUUID[10]);	
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert SEGMENT_ROUTER_REL!\n");
				return FALSE;
			}
			Sleep(1000);

			GetUUID(uuidBuf);
			sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SEGMENT_ROUTER_REL(ID, UPDATED, SEGMENT_ID, ROUTER_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_sgmtUUID[5+i*3], g_routerUUID[11]);	
			hr = pConn->Execute(sqlBuf, NULL, adCmdText);
			if( FAILED(hr) )
			{
				printf("Fail to insert SEGMENT_ROUTER_REL!\n");
				return FALSE;
			}
			Sleep(1000);
		}

		//router_router
		GetUUID(uuidBuf);
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into ROUTER_ROUTER_REL(ID, UPDATED, ROUTER1_ID, ROUTER2_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_routerUUID[9], g_routerUUID[10]);	
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to insert SEGMENT_ROUTER_REL!\n");
			return FALSE;
		}
		Sleep(1000);
		GetUUID(uuidBuf);
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into ROUTER_ROUTER_REL(ID, UPDATED, ROUTER1_ID, ROUTER2_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_routerUUID[9], g_routerUUID[11]);	
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to insert SEGMENT_ROUTER_REL!\n");
			return FALSE;
		}
		Sleep(1000);
		GetUUID(uuidBuf);
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into ROUTER_ROUTER_REL(ID, UPDATED, ROUTER1_ID, ROUTER2_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_routerUUID[10], g_routerUUID[11]);	
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to insert SEGMENT_ROUTER_REL!\n");
			return FALSE;
		}
		Sleep(1000);
		

		//Update task
		if(!UpdateTask(pConn, "嗅探分析", "done", "正在还原网络拓扑", g_taskUUID[0]))
		{
			printf("Fail to update task!\n");
			return FALSE;
		}
		Sleep(3000);
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}


	return TRUE;
}


//-------------------------------------------common function-------------------------------------------
//get UUID
void GetUUID(char* uuidBuf)
{
	GUID guid;
	CoCreateGuid(&guid);
	sprintf_s(uuidBuf, 64, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}


//Update task
BOOL UpdateTask(_ConnectionPtr pConn, char* type, char* period, char* process, char* uuid)
{
	HRESULT hr;
	char sqlBuf[1024] = {0};

	//update TASK
	try
	{	
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Update TASK Set UPDATED='1', TYPE='%s', PERIOD='%s', PROCESS='%s' Where ID='%s' ", type, period, process, uuid);		
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to update task process!\n");
			return FALSE;
		}
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}

	return TRUE;
}

//add new segment
BOOL AddSegment(_ConnectionPtr pConn, int Seq, int ip3)
{
	HRESULT hr;
	char sqlBuf[1024] = {0};
	char uuidBuf[64] = {0};

	try
	{ 
		//SITE
		GetUUID(uuidBuf);
		memcpy_s(&g_siteUUID[Seq][0], sizeof(g_siteUUID[Seq]), uuidBuf, sizeof(uuidBuf));
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SITE(ID, UPDATED, STATUS, NAME, DETAIL, ADDRESS, NET, TYPE) Values('%s', '1', 'offline', 'site-%d', 'This is site-%d.', 'South Sea', '192.168.%d.0', 2)", uuidBuf, Seq, Seq, ip3); 
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to insert SITE!\n");
			return -1;
		}
		printf("SITE have been inserted!\n");


		//SEGMENT
		GetUUID(uuidBuf);
		memcpy_s(&g_sgmtUUID[Seq][0], sizeof(g_sgmtUUID[Seq]), uuidBuf, sizeof(uuidBuf));
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SEGMENT(ID, UPDATED,  NET, MASK) Values('%s', '1', '192.168.%d.0', '255.255.255.0')", g_sgmtUUID[Seq], ip3);
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to insert SEGMENT!\n");
			return FALSE;
		}
		printf("SEGMENT have been inserted!\n");


		//SITE_SEGMENT_REL
		GetUUID(uuidBuf);
		sprintf_s(sqlBuf, sizeof(sqlBuf), "Insert Into SITE_SEGMENT_REL(ID, UPDATED, SITE_ID, SEGMENT_ID, TRAFFIC) Values('%s', '1', '%s', '%s', '0.06kb/s')", uuidBuf, g_siteUUID[Seq], g_sgmtUUID[Seq]); 
		hr = pConn->Execute(sqlBuf, NULL, adCmdText);
		if( FAILED(hr) )
		{
			printf("Fail to insert SITE_SEGMENT_REL!\n");
			return -1;
		}
		printf("SITE_SEGMENT_REL have been inserted!\n");
	}
	catch(_com_error e)
	{
		printf("Exception Description：%s\n", (LPCTSTR)e.Description());
		printf("Exception Message：%s\n", e.ErrorMessage());
		return FALSE;
	}

	return TRUE;
}
