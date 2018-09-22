# _*_ coding:utf-8 _*_
import socket
import threading
import sys
import os
import base64
import hashlib
import struct
import time
import cx_Oracle
import re
import json
import uuid
import datetime
#import unittest

# ====== config ======
HOST = 'localhost'
PORT = 3368
MAGIC_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
HANDSHAKE_STRING = "HTTP/1.1 101 Switching Protocols\r\n" \
                   "Upgrade:websocket\r\n" \
                   "Connection: Upgrade\r\n" \
                   "Sec-WebSocket-Accept: {1}\r\n" \
                   "WebSocket-Location: ws://{2}/chat\r\n" \
                   "WebSocket-Protocol:chat\r\n\r\n"

#第一个参数，我们的数据库连接信息(dbconfigs)
#第二个参数，他们的数据库连接信息(dbconfigs_target)
comnand_arguments = sys.argv
if not (len(comnand_arguments)==3):
    print('error:incorrect argument')
    sys.exit(1)
dbconfigs = comnand_arguments[1]
dbconfigs_target = comnand_arguments[2]

#test db connection
#PROJECT/PROJECT@192.168.1.52:1521/ORCL 我们的
try:
	conn = cx_Oracle.connect(dbconfigs)
except:
	print('Exception: can not connect to the database')
	error_info = sys.exc_info()
	if len(error_info) > 1:
		print(str(error_info[0]) + ' '+str(error_info[1]))
	sys.exit(1)
cursor = conn.cursor()

#study/study@192.168.1.52:1521/ORCL 他们的
try:
	conn_target = cx_Oracle.connect(dbconfigs_target)
except:
	print('Exception: can not connect to the database')
	error_info = sys.exc_info()
	if len(error_info) > 1:
		print(str(error_info[0]) + ' '+str(error_info[1]))
	sys.exit(1)
cursor_target = conn_target.cursor()

#get username of our db
m_user = re.findall('^(.*)/(.*)@(.*):(.*)/(.*)$',dbconfigs.strip())
try:
    db_username = m_user[0][0].upper()
except:
    print('Exception:can not get database username')
    sys.exit(1)
	
#get username of their db
m_user = re.findall('^(.*)/(.*)@(.*):(.*)/(.*)$',dbconfigs_target.strip())
try:
    db_username_target = m_user[0][0].upper()
except:
    print('Exception:can not get database username')
    sys.exit(1)

def get_host_ip():
    """
    查询本机ip地址
    :return: ip
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    return ip

#将网络前缀转为子网掩码
def prefix2mask(mask_int):
	bin_arr = ['0' for i in range(32)]
	for i in range(mask_int):
		bin_arr[i] = '1'
	tmpmask = [''.join(bin_arr[i * 8:i * 8 + 8]) for i in range(4)]
	tmpmask = [str(int(tmpstr, 2)) for tmpstr in tmpmask]
	return '.'.join(tmpmask)

# run different functions based on different signals
class switch_case(object):
    def case_to_function(self, case):
        fun_name = "case_" + str(case)
        method = getattr(self, fun_name, self.case_default)
        return method
    #plz refer to document "task.odt"
    #correspond to 1
	#在一大轮探测中，该函数调用且仅调用一次
    def case_init_agents(self, msg):
		print("case_fun_init_agents: " + msg)
		#中心节点本身也需要加入表中且isAgent字段为2（不参与决策），只考虑插入我们的数据库
		localip = ""
		localip = get_host_ip()
		try:
			cursor.execute("""
						declare
							isAgent {username}.HOST.ISAGENT%TYPE;
						begin
							select ISAGENT into isAgent from {username}.HOST where IP=:ip;
								case isAgent
									when 0 then
										update {username}.HOST set ISAGENT = 2, ISNEW = 0, HISDEL = 0;
									when 1 then
										update {username}.HOST set ISAGENT = 2,ISNEW = 0,HISDEL = 0;
									when 2 then
										update {username}.HOST set ISNEW = 0,HISDEL = 0;
								end case;
						exception
								when NO_DATA_FOUND then
									insert into {username}.HOST values(:ip,0,0,0,NULL,0,NULL,NULL,0,NULL,
														0,0,2,0,0,0,0,0,0,NULL);
						end;
					""".format(username=db_username), ip=localip)
		except:
			print("Error:fail to insert info of localip")
			error_info = sys.exc_info()
			if len(error_info) > 1:
				print(str(error_info[0]) + ' ' + str(error_info[1]))
		#设置我们的数据库中的初始agent
		#要修改，因为第一轮可能有不止一个agent，不能简单地取一个
		#除了初始插入，还要把子网信息填上，子网信息就从config.json中获取
		with open("config.json","r") as load_f:
			load_dict = json.load(load_f)
			for item in load_dict['tasks']:
				if item['type'] == "activeDetection":
					s_index = item['hosts'][0].find(':')
					host_ip = item['hosts'][0][0:s_index]
					host_subnet = item['taskArguments']
					try:
						cursor.execute("""
							declare
								isAgent {username}.HOST.ISAGENT%TYPE;
							begin
								select ISAGENT into isAgent from {username}.HOST where IP=:ip;
									case isAgent
										when 0 then
											update {username}.HOST set ISAGENT=1,ISNEW=0,HISDEL=0;
										when 1 then
											update {username}.HOST set ISNEW=0,HISDEL=0;
										when 2 then
											update {username}.HOST set ISAGENT=1,ISNEW=0,HISDEL=0;
									end case;
							exception
									when NO_DATA_FOUND then
										insert into {username}.HOST values(:ip,0,0,0,NULL,0,NULL,NULL,0,NULL,
															0,0,1,0,0,0,0,0,0,:subnet);
							end;
						""".format(username=db_username),ip=host_ip,subnet=host_subnet)
					except:
						print("Error:can not initialize database")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					#设置别人数据中的初始agent
					#同样是config.json中的主机
					#步骤：1.更新HOST表
					try:
						cursor_target.execute("""
							declare
							t_count number(10);
							begin
								select count(*) into t_count from {username}.HOST where IP=:ip;
								if t_count>0 then
									update {username}.HOST set UPDATED=1,NET=:subnet;
								else
									insert into {username}.HOST(ID,UPDATED,OS,NET,IP,PORT,BUSINESSTYPE,MAC,PROCESS,ATTACKED,KEY,ENTRY) values(:id,'1','Unknown',:subnet,:ip,0,NULL,'Unknown',NULL,'0','0','1');
								end if;
							end;
						""".format(username=db_username_target),id=str(uuid.uuid1()),ip=host_ip,subnet=host_subnet)
					except:
						print("Error:can not initialize database")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					#2.更新INJECTION表,SAT注入开始。
					#插入一个注入，与本次循环所处理的主机相关联
					try:
						cursor_target.execute("""
						select ID from {username}.HOST where IP=:ip
						""".format(username=db_username_target),ip=host_ip)
						result = cursor_target.fetchall()
						#assertTrue(len(result) == 1)#取出来只能有一个
						if len(result) != 1:
							print("Error:more than one record noticing the same ip")
							#....
					except:
						print("Error:fail to fetch ID from HOST")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					try:
						in_id_t = str(uuid.uuid1())#暂存，用于后面更新注入
						host_id = result[0][0]
						cursor_target.execute("""
						insert into {username}.INJECTION(ID,UPDATED,TARGET_ID,PERIOD) values(:in_id,'1',:h_id,'start')
						""".format(username=db_username_target),in_id=in_id_t,h_id=host_id)
					except:
						print("Error:fail to insert new injection")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					#网段表，站点表，网段站点关系表，网段主机关系表，工具表初始化
					#和后面的addSegment()不一样，单独写
					#初始化网段表：
					prefix = (host_subnet.split('/',1))[1]
					subnet_addr = (host_subnet.split('/',1))[0]
					mask = prefix2mask(int(prefix))
					#segment_id = str(uuid.uuid1())
					try:
						cursor_target.execute("""
						declare
						t_count number(10);
						begin
							select count(*) into t_count from {username}.SEGMENT where NET=:sba and MASK=:tmask;
							if t_count=0 then
								insert into {username}.SEGMENT(ID,UPDATED,NET,MASK) values(:id,'1',:sba,:tmask);
							end if;
						end;
						""".format(username=db_username_target),id=str(uuid.uuid1()),sba=subnet_addr,tmask=mask)
					except:
						print("Error:fail to initialize the SEGMENT table")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					#初始化站点表
					#site_id = str(uuid.uuid1())
					#考虑到更新的情况，site_id要从数据中取，为填网段站点关系表做准备
					site_name = "default"#最大长度为10
					try:
						cursor_target.execute("""
						declare
						t_count number(10);
						begin
							select count(*) into t_count from {username}.SITE where NAME=:name;
							if t_count=0 then
								insert into {username}.SITE(ID,UPDATED,STATUS,NAME,DETAIL,ADDRESS,NET,TYPE) values(:id,'1','online',:name,NULL,NULL,:subnet,'2');
							else
								update {username}.SITE set NET=:subnet,UPDATED=1,STATUS='online';
							end if;
						end;
						""".format(username=db_username_target),id=str(uuid.uuid1()),name=site_name,subnet=subnet_addr)
					except:
						print("Error:fail to initialize the SITE table")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					#准备填网段站点关系表
					#这些ID号必须现取，完整性约束
					#取网段ID号
					try:
						cursor_target.execute("""
						select ID from {username}.SEGMENT where NET=:sba and MASK=:tmask
						""".format(username=db_username_target),sba=subnet_addr,tmask=mask)
						result = cursor_target.fetchall()
						if len(result) > 1:
							print("Error:more than one record noticing the same segment")
						segment_id = result[0][0]#存网段ID号
					except:
						print("Error:fail to fetch id from the SEGMENT table")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					#取站点ID号
					try:
						cursor_target.execute("""
						select ID from {username}.SITE where NAME=:name
						""".format(username=db_username_target),name=site_name)
						result = cursor_target.fetchall()
						if len(result) > 1:
							print("Error:more than one record noticing the same site name")
					except:
						print("Error:fail to fetch id from the SITE table")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					try:
						site_id_t = result[0][0]#如果已经有了的话，插入会失败
						cursor_target.execute("""
						declare t_count number(10);
						begin
							select count(*) into t_count from {username}.SITE_SEGMENT_REL where SITE_ID=:site_id and SEGMENT_ID=:seg_id;
							if t_count=0 then
								insert into {username}.SITE_SEGMENT_REL(ID,UPDATED,SITE_ID,SEGMENT_ID,TRAFFIC) values(:id,'1',:site_id,:seg_id,'0.06kb/s');
							else
								update {username}.SITE_SEGMENT_REL set UPDATED=1;
							end if;
						end;
						""".format(username=db_username_target),id=str(uuid.uuid1()),site_id=site_id_t,seg_id=segment_id)
					except:
						print("Error:fail to update SITE_SEGMENT_REL table")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					#网段主机关系表
					try:
						cursor_target.execute("""
						declare t_count number(10);
						begin
							select count(*) into t_count from {username}.SEGMENT_HOST_REL where SEGMENT_ID=:sg_id and HOST_ID=:ho_id;
							if t_count=0 then
								insert into {username}.SEGMENT_HOST_REL(ID,UPDATED,SEGMENT_ID,HOST_ID,TRAFFIC) values(:id,'1',:sg_id,:ho_id,'0.02kb/s');
							else
								update {username}.SEGMENT_HOST_REL set UPDATED=1;
							end if;
						end;
						""".format(username=db_username_target),id=str(uuid.uuid1()),sg_id=segment_id,ho_id=host_id)
					except:
						print("Error:fail to update SEGMENT_HOST_REL table")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					#工具表	ps：工具关系表怎么弄？模拟的程序中把工具关系表的更新设在构建自组织网络任务中
					#工具表中的编号何解？臆测1代表主动探测器，2代表被动探测器
					now_time_t = datetime.datetime.now()
					now_time = datetime.datetime.strftime(now_time_t,'%Y/%m/%d %H:%M:%S')#转为sql需要的日期形式
					
					try:
						cursor_target.execute("""
						declare t_count number(10);
						begin
							select count(*) into t_count from {username}.ENTITY where HOST_ID=:ho_id;
							if t_count=0 then
								insert into {username}.ENTITY(ID,UPDATED,PLATFORM,LOAD,DESCRIPTION,ONLINE_TIME,HOST_ID,NUM,STATUS) values(:id,'1',NULL,NULL,NULL,TO_TIMESTAMP(:time,'YYYY/MM/DD HH24:MI:SS'),:ho_id,'1','online');
							else
								update {username}.ENTITY set UPDATED=1,STATUS='online';
							end if;
						end;
						""".format(username=db_username_target),id=str(uuid.uuid1()),ho_id=host_id,time=now_time)
					except:
						print("Error:fail to update the ENTITY table")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					conn.commit()
					conn_target.commit()
    #correspond to 2
    def case_start_detect_live_host(self, msg):
		print("case_start_detect_live_host: " + msg)
		#test of 2 db connections
		try:
			cursor.execute("""
			select * from {username}.HOST
			""".format(username = db_username))
			result = cursor.fetchall()
		except:
			error_info = sys.exc_info()
			if len(error_info) > 1:
				print(str(error_info[0]) + ' ' + str(error_info[1]))
			sys.exit(1)
		time.sleep(2)
		conn.commit()
		cursor.close()
		conn.close()
		#应该不需要线程把数据库连接断开，整个常驻进程退出时才把数据库连接断开
		try:
			cursor_target.execute("""
			select * from {username}.HOST
			""".format(username = db_username_target))
			result = cursor_target.fetchall()
		except:
			error_info = sys.exc_info()
			if len(error_info) > 1:
				print(str(error_info[0]) + ' ' + str(error_info[1]))
			sys.exit(1)
		time.sleep(2)
		conn_target.commit()
		cursor_target.close()
		conn_target.close()

    #correspond to 3
    def case_start_file_transmitting(self, msg):
        print("case_start_file_transmitting: " + msg)
        time.sleep(1)

    #correspond to 4
    def case_end_file_transmitting(self, msg):
        print('case_end_file_transmitting: ' + msg)

    #correspond to 5   one argument indicating the directory
    def case_end_detect_live_host(self, msg):
        print('case_end_detect_live_host: ' + msg)

    #correspond to 6
    def case_start_recover_topo(self, msg):
        print('case_start_recover_topo: ' + msg)

    #correspond to 7
    def case_end_recover_topo(self, msg):
        print('case_end_recover_topo: ' + msg)

    #correspond to 8
    def case_start_agent_deciding(self, msg):
        print('case_start_agent_deciding: ' + msg)

    #correspond to 9
    def case_end_agent_deciding(self, msg):
        print('case_end_agent_deciding: ' + msg)

    #correspond to 10
    def case_start_deploy_agent(self, msg):
        print('case_start_deploy_agent: ' + msg)

    #correspond to 11
    def case_end_deploy_agent(self, msg):
        print('case_end_deploy_agent: ' + msg)

    # a method that is called by default
    # it is similar to the default segment in switch case structure
    def case_default(self, msg):
        print("case_default: Got an invalid instruction " + msg)


class Th(threading.Thread):
    def __init__(self, connection,):
        threading.Thread.__init__(self)
        self.con = connection
        
    def run(self):
        cls = switch_case()
        while True:
            try:
                print('thread is running')
                res = self.recv_data(1024)
                print(res)
                cls.case_to_function(res)("go!")
                # str = res.split()
                # for item in str:
                #     print(item)
                self.send_data('ok')
            except TypeError as e:
                print e
        self.con.close()
    
    def test_print(self):
        print('this connection has been initialized, now attempt to start it')

    def recv_data(self, num):
        try:
            all_data = self.con.recv(num)
            if not len(all_data):
                return False
        except:
            return False
        else:
            code_len = ord(all_data[1]) & 127
            if code_len == 126:
                masks = all_data[4:8]
                data = all_data[8:]
            elif code_len == 127:
                masks = all_data[10:14]
                data = all_data[14:]
            else:
                masks = all_data[2:6]
                data = all_data[6:]
            raw_str = ""
            i = 0
            for d in data:
                raw_str += chr(ord(d) ^ ord(masks[i % 4]))
                i += 1
            return raw_str
 
    # send data
    def send_data(self, data):
        if data:
            data = str(data)
        else:
            return False
        token = "\x81"
        length = len(data)
        if length < 126:
            token += struct.pack("B", length)
        elif length <= 0xFFFF:
            token += struct.pack("!BH", 126, length)
        else:
            token += struct.pack("!BQ", 127, length)
        #struct为Python中处理二进制数的模块，二进制流为C，或网络流的形式。
        data = '%s%s' % (token, data)
        self.con.send(data)
        return True
 
 
# handshake
def handshake(con):
    headers = {}
    shake = con.recv(1024)
 
    if not len(shake):
        return False
 
    header, data = shake.split('\r\n\r\n', 1)
    for line in header.split('\r\n')[1:]:
        key, val = line.split(': ', 1)
        headers[key] = val
 
    if 'Sec-WebSocket-Key' not in headers:
        print ('This socket is not websocket, client close.')
        con.close()
        return False
 
    sec_key = headers['Sec-WebSocket-Key']
    res_key = base64.b64encode(hashlib.sha1(sec_key + MAGIC_STRING).digest())
 
    str_handshake = HANDSHAKE_STRING.replace('{1}', res_key).replace('{2}', HOST + ':' + str(PORT))
    print str_handshake
    con.send(str_handshake)
    return True
 
def new_service():
    """start a service socket and listen
    when coms a connection, start a new thread to handle it"""
 
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('localhost', 3368))
        sock.listen(1000)
        #链接队列大小
        print "bind 3368,ready to use"
    except:
        print("Server is already running,quit")
        sys.exit()
 
    while True:
        connection, address = sock.accept()
        #返回元组（socket,add），accept调用时会进入waite状态
        print "Got connection from ", address
        if handshake(connection):
            print "handshake success"
            try:
                t = Th(connection)
                t.test_print()
                t.start()
                print 'new thread for client ...'
            except:
                print 'start new thread error'
                connection.close()
 
 
if __name__ == '__main__':
    new_service()