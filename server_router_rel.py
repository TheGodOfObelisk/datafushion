# _*_ coding:utf-8 _*_
from IPy import IP
import random
import pygeoip
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
import os_update
import resolve_file
import logging
import shutil
#import unittest

# ====== config ======
HOST = 'localhost'
PORT = 3368
MAGIC_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
os.environ['NLS_LANG'] = 'SIMPLIFIED CHINESE_CHINA.ZHS16GBK'

logging.basicConfig(filename = 'dbupdater.log', filemode = "w", 
					level = logging.DEBUG, format = '%(asctime)s - %(levelname)s - %(message)s')

def logwriter(logtype, logmessage):
	if logtype == "debug":
		logging.debug(logmessage)
		return
	elif logtype == "info":
		logging.info(logmessage)
	elif logtype == "warning":
		logging.warning(logmessage)
	elif logtype == "error":
		logging.error(logmessage)
	elif logtype == "critical":
		logging.critical(logmessage)
	else:
		logging.error("An unknown logmessage entered :(")
	print(logmessage)


#最后一次修改于2018年11月19日    injection前调用GetHostidByIp		读取result.json以及config.json处的修改       添加日志记录
#将sql写到日志文件中去，root agent不会自己给自己写传文件
#更正15号测试时发生的错误
#第一个参数，我们的数据库连接信息(dbconfigs)
#第二个参数，他们的数据库连接信息(dbconfigs_target)
comnand_arguments = sys.argv
if not (len(comnand_arguments)==3):
	logwriter('error', 'error:incorrect argument')
	sys.exit(1)
dbconfigs = comnand_arguments[1]
dbconfigs_target = comnand_arguments[2]

global entity_sequence
global root_parent_ip
root_parent_ip = ""#追本溯源
global root_parent_entity
root_parent_entity = ""
global entity_parent_id
entity_parent_id = ""#工具关系表中记录的父id


#test db connection
#PROJECT/PROJECT@192.168.1.52:1521/ORCL 我们的
try:
	conn = cx_Oracle.connect(dbconfigs)
except:
	logwriter('error', 'Exception: can not connect to the database')
	error_info = sys.exc_info()
	if len(error_info) > 1:
		logwriter('error', str(error_info[0]) + ' '+str(error_info[1]))
	sys.exit(1)
cursor = conn.cursor()

#study/study@192.168.1.52:1521/ORCL 他们的
try:
	conn_target = cx_Oracle.connect(dbconfigs_target)
except:
	logwriter('error', 'Exception: can not connect to the database')
	error_info = sys.exc_info()
	if len(error_info) > 1:
		logwriter('error', str(error_info[0]) + ' '+str(error_info[1]))
	sys.exit(1)
cursor_target = conn_target.cursor()

#get username of our db
m_user = re.findall('^(.*)/(.*)@(.*):(.*)/(.*)$',dbconfigs.strip())
try:
	db_username = m_user[0][0].upper()
except:
	logwriter('error', 'Exception:can not get database username')
	sys.exit(1)
	
#get username of their db
m_user = re.findall('^(.*)/(.*)@(.*):(.*)/(.*)$',dbconfigs_target.strip())
try:
	db_username_target = m_user[0][0].upper()
except:
	logwriter('error', 'Exception:can not get database username')
	sys.exit(1)

def get_result_list(root_dir):
	try:
		dirs = os.listdir(root_dir)
	except:
		error_info = sys.exc_info()
		if len(error_info) > 1:
			logwriter('error', str(error_info[0]) + ' ' + str(error_info[1]))
		else:
			logwriter('error', 'Unexpected error:can not get access to the root path of result')
		return -1
	ip_dirs = []
	for dir in dirs:
		if re.findall('^\d+\.\d+\.\d+\.\d+$', dir):
			ip_dirs.append(os.path.join(root_dir, dir))
	return ip_dirs

	
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

def prefix2mask(mask_int):#将网络前缀转为子网掩码
	bin_arr = ['0' for i in range(32)]
	for i in range(mask_int):
		bin_arr[i] = '1'
	tmpmask = [''.join(bin_arr[i * 8:i * 8 + 8]) for i in range(4)]
	tmpmask = [str(int(tmpstr, 2)) for tmpstr in tmpmask]
	return '.'.join(tmpmask)

def getPidOfEntity():#获取工具关系表要用的父id
	try:
		cursor_target.execute("""
		select ID from {username}.ENTITY
		""".format(username=db_username_target))
		result = cursor_target.fetchall()
		return result[0][0]
	except:
		logwriter('error', "Error:fail to get the ENTITY ID")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			logwriter('error', str(error_info[0]) + ' ' + str(error_info[1]))




"""start"""
def update_oracle(sql,var):    #update the database of ourselveslogwriter(conn.version())
	"""update contains:insert,update,delete"""
	logwriter("debug", "call update_oracle()")
	try:
		cursor.execute(sql,var)
		conn.commit()
		if cursor.rowcount != 0:
			return 0
	except cx_Oracle.OperationalError as err:
		logwriter("error", err)
		return -1

def update_oracle_target(sql,var):  #update the FSR database
	"""update contains:insert,update,delete"""
	logwriter("debug", "call update_oracle_target()")
	try:
		#logwriter(sql,var)
		cursor_target.execute(sql,var)
		conn_target.commit()
		if cursor_target.rowcount != 0:
			return 0
	except cx_Oracle.OperationalError as err:
		logwriter("error", err)
		return -1

def update_os():
	"""Update HOS field of the our HOST, only keep one operating system"""
	logwriter("debug", "call update_os()")
	try:
		cursor.execute('select IP,HOS from HOST where HISDEL=0')
		oslist = cursor.fetchall()
		if cursor.rowcount == 0:
			logwriter("warning", 'The table Host is empty!')
			return -1
	except cx_Oracle.OperationalError as err:
		logwriter("error", err)
		return -1
	for os in oslist:
		if os[1] == None:
			continue
		List = os_update.os_str_transfer(os[1])  # split all string to many little string
		osString = ''
		for L in List:
			# make sure the highest weight
			if (re.search('Windows Server 2008', L) and re.search('Windows Server 2008', osString) == None):
				osString = L
			elif (re.search('Windows 2000', L) and re.search('Windows Server 2008|Windows 2000', osString) == None):
				osString = L
			elif (re.search('Windows XP SP3', L) and re.search('Windows Server 2008|Windows 2000|Windows XP SP3',
															   osString) == None):
				osString = L
			elif (re.search('Windows 7', L) and re.search('Windows Server 2008|Windows 2000|Windows XP SP3|Windows 7',
														  osString) == None):
				osString = L
			elif (re.search('Windows 8', L) and re.search(
					'Windows Server 2008|Windows 2000|Windows XP SP3|Windows 7|Windows 8', osString) == None):
				osString = L
			elif (re.search('Windows 10', L) and re.search(
					'Windows Server 2008|Windows 2000|Windows XP SP3|Windows 7|Windows 8|Windows 10',
					osString) == None):
				osString = L
			elif (re.search('Linux', L) and re.search(
					'Windows Server 2008|Windows 2000|Windows XP SP3|Windows 7|Windows 8|Windows 10|Linux',
					osString) == None):
				osString = L
			elif re.search('Windows Server 2008|Windows 2000|Windows XP SP3|Windows 7|Windows 8|Windows 10|Linux',
						   osString) == None:
				osString = List[0]
		var = {'os': osString, 'ip': os[0]}
		sql = 'update HOST set HOS=:os where IP=:ip'
		if update_oracle(sql, var) == -1:
			return -1

def update_host():
	logwriter("debug", "call update_host()")
	"""Transfer data from table host to HOST"""  # and ISAGENT<>5 and (HDEVICE like '%general purpose%' or HDEVICE is null or HDEVICE like '%specialized%')
	if update_os() == -1:
		logwriter("error", 'Operating System update failed.')
	try:
		cursor.execute("select HOS,IP,HMAC,HMASK,SOURCE,HDEVICE from HOST where HISDEL=0 and ISAGENT!=5 and (HDEVICE like '%general purpose%' or HDEVICE is null or HDEVICE like '%specialized%')")
		hosts = cursor.fetchall()
		logwriter("error", "准备搬运" + str(cursor.rowcount) + "台主机")
		if cursor.rowcount == 0:
			logwriter("warning", 'No relevant info satisfied conditions in our HOST!')
			return -1
	except Exception as err:
		logwriter("error", err)
		return -1
	for host in hosts:
		os = host[0]  # Operating System
		ip = host[1]  # IP address
		ip_last_str = host[1].split('.')[3]   #last part of ip
		if ip_last_str == '255':    #broadcast ip address
			continue
		mac = host[2]  # MAC address
		NET = 'N/A'
		if host[3] == None:  # Mask is empty
			if host[4] == '2':  #source from passive.txt
				ip_str = host[1].split('.')
				if host[5] == None and (ip_str[3] == '1' or ip_str[3] == '254'):   #not transfer data from passive.txt when devicetype undefined
					continue
				NET = ip_str[0] + '.' + ip_str[1] + '.' + ip_str[2] + '.0/24'
		else:
			NET = host[3]
		if os == None:
			os = 'N/A'
		if mac == None:
			mac = 'N/A'
		port_str = ''
		try:
			var = {'host_ip':host[1]}
			cursor.execute('select PPORT from PORT where IP=:host_ip',var)
			ports = cursor.fetchall()
		except Exception as err:
			logwriter("error", err)
			return -1
		if cursor.rowcount<=0:
			port_str = '0'
		count = 0
		for port in ports:
			count = count + 1
			if count < len(ports):
				port_str = port_str + str(port[0]) + ','
				continue
			port_str = port_str + str(port[0])
		try:
			var = {'host_ip': host[1]}
			cursor_target.execute('select ID,OS,NET,MAC,PORT from HOST where IP=:host_ip', var)
			hosts = cursor_target.fetchall()
		except Exception as err:
			logwriter("error", err)
			return -1
		# If the ip has existed, then update. If not, insert into the HOST table.
		if cursor_target.rowcount == 0:  # The ip is new, insert
			var = {'id': str(uuid.uuid4()), 'os': os[0:64], 'net': NET, 'ip': ip, 'mac': mac,'port':port_str[0:128]}
			sql = (
				"insert into HOST (ID,UPDATED,OS,NET,IP,PORT,BUSINESSTYPE,MAC,PROCESS,ATTACKED,KEY,ENTRY)"
				"values(:id,'1',:os,:net,:ip,:port,'telnet',:mac,'chrome.exe','0','0','0')"
			)
		else:  # The ip exists, update
			for host in hosts:
				if host[1] != 'N/A' and os == 'N/A':  # No lastest info,Use previous info
					os = host[1]
				if host[2] != 'N/A' and NET == 'N/A':
					NET = host[2]
				if host[3] != 'N/A' and mac == 'N/A':
					mac = host[3]
				if host[4] != '0' and port_str == '0':
					port_str = host[4]
				var = {'id': host[0], 'os': os[0:64], 'net': NET, 'mac': mac,'port':port_str[0:128],'updated':'1'}
			sql = "update HOST set OS=:os,NET=:net,MAC=:mac,PORT=:port,UPDATED=:updated where ID=:id"
		if update_oracle_target(sql, var) == -1:
			return -1

def update_protocol(file_full_path):
	"""Prerequisites: update HOST table. Establish relationship between host and host"""
	logwriter("debug", "call update_protocol()")
	items = resolve_file.protocol_resolve(file_full_path)
	if items == -1:
		logwriter("warning", 'The protocol file is empty')
		return -1
	for item in items:
		pro = item['pro']  # protocol
		if pro == 'Unknown':
			pro = 'Unknown'
			#continue
		traffic = str(round(float(item['traffic'] / 1000), 2)) + 'kb/s'  # preserve two digit decimal place
		if len(pro) > 10:
			pro = pro[0:10]
		if 'domain' in pro:
			pro = "dns"
		if 'ICMP' in pro:
			pro = 'icmp'
		# look up the ID field of source and destination in HOST: if no the address, continue
		try:
			var = {'src': item['src']}
			cursor_target.execute('select ID from HOST where IP=:src', var)  # Judge the src address whether it exists
			host1_id = cursor_target.fetchone()
			if cursor_target.rowcount == 0:
				continue
			var = {'dst': item['dst']}
			cursor_target.execute('select ID from HOST where IP=:dst', var)  # Judge the dst address whether it exists
			host2_id = cursor_target.fetchone()
			if cursor_target.rowcount == 0:
				continue
			# whether the ip pair has existed
			var = {'host1_id': host1_id[0], 'host2_id': host2_id[0], 'proto': pro}
			cursor_target.execute('select * from PROTOCOL where HOST1_ID=:host1_id and HOST2_ID=:host2_id and TYPE=:proto', var)  # Judge the ip pair whether it existsprotocol = cursor_target.fetchone()
			protocol = cursor_target.fetchone()
		except Exception as err:
			logwriter("error", 'PROTOCOL Oracle OperationalError')
			return -1
		# logwriter('protocol=',protocol)
		# If the ip pair has existed, then update. If not, insert into the PROTOCOL table.
		if cursor_target.rowcount == 1:  # the ip pair has existed ,update the PROTOCOL table
			if protocol[2] != 'N/A' and pro == 'N/A':
				pro = protocol[2]
			if protocol[5] != '0.0kb/s' and traffic == '0.0kb/s':
				traffic = protocol[5]
			var = {'id': protocol[0], 'type': pro, 'traffic': traffic,'updated':'1'}
			sql = 'update PROTOCOL set TYPE=:type,TRAFFIC=:traffic,UPDATED=:updated where ID=:id'
		else:  # insert the ip pair
			var = {'id': str(uuid.uuid4()), 'type': pro, 'host1_id': host1_id[0], 'host2_id': host2_id[0],
				   'traffic': traffic}
			sql = "insert into PROTOCOL (ID,UPDATED,TYPE,HOST1_ID,HOST2_ID,TRAFFIC)values(:id,'1',:type,:host1_id,:host2_id,:traffic)"
		# logwriter(sql,var)
		if update_oracle_target(sql, var) == -1:
			return -1

def update_router_from_file(file_full_path):
	"""Update ROUTER of our database from router.txt"""
	logwriter("debug", "call update_router_from_file()")
	items = resolve_file.router_resolve(file_full_path)
	if items == -1:
		return -1
	for item in items:  # item represent a router
		flag = 0  # Judge whether all ips exist in our HOST or not. all no:0, one or more yes:1
		
		# save all ips of a router to a 'routers' string
		routers = ''  # store all ips of each router
		count = 0  # the last ip of router without ','
		for its in item['router']:
			routers = routers + its
			count = count + 1
			if count == len(item['router']):
				break
			routers = routers + ','

		#search ROUTER weather router existed or not.
		for router_ip in item['router']:
			try:
				cursor.execute('select ID,IP from ROUTER')
				router_ips = cursor.fetchall()
			except Exception as err:
				logwriter("error", err)
				return -1
			find_flag = 0
			if cursor.rowcount == 0:  # ROUTER table is empty, insert router info directly
				find_flag = 0  # The ROUTER will be updated later
			else:  # ROUTER table is not empty
				for ips in router_ips:
					if router_ip in ips[1]:  # the ip exist in a router_ips,then update the router
						find_flag = 1  # the router is found
						ips_str = str(ips[1])
						file_ips = routers.split(',')  # if file has a ip but table not, then add the ip
						for file_ip in file_ips:
							if file_ip in ips_str:
								continue
							ips_str = ips_str + ',' + file_ip
						# update the IP field of ROUTER
						var = {'id': ips[0], 'ip': ips_str[0:100],'updated':'1'}
						sql = 'update ROUTER set IP=:ip,UPDATED=:updated where ID=:id'
						if update_oracle(sql,var) == -1:
							return -1
		
		# Traverse all ROUTER ips, couldn't find the router. Then insert into ROUTER
		# if find_flag == 0:
		# 	var = {'id': str(uuid.uuid4()), 'os': 'N/A', 'ip': routers, 'net': 'N/A','port': 0, 'businesstype': 0, 'mac': 'N/A'}
		# 	sql = (
		# 		"insert into ROUTER (ID,UPDATED,OS,IP,NET,PORT,BUSINESSTYPE,MAC,PROCESS,ATTACKED,KEY)"
		# 		"values(:id,'1',:os,:ip,:net,:port,:businesstype,:mac,'server.exe','0','0')"
		# 	)
		# 	if update_oracle(sql, var) == -1:
		# 		return -1
	logwriter("info", 'Succeeded to Update our ROUTER from router.txt with repeated')
	# delete repeated data from ROUTER
	if update_router_deduplicate() == -1:
		return -1

def update_router_deduplicate():
	"""remove the repeated data from ROUTER"""
	logwriter("debug", "call update_router_deduplicate()")
	try:
		cursor.execute('select ID,OS,IP,NET,PORT,BUSINESSTYPE,MAC from ROUTER')
		front_routers = cursor.fetchall()
	except Exception as err:
		logwriter("error", err)
		return -1
	if cursor.rowcount == 0:  # The ROUTER table is empty
		return
	# The ROUTER table is not empty
	keep_items = []
	del_items = []
	for front_router in front_routers:  # find a router each time
		if front_router[0] in del_items:  # skip the router has been prepared to remove
			continue
		front_ips_str = str(front_router[2])
		front_ips = front_ips_str.split(',')
		try:
			cursor.execute('select ID,OS,IP,NET,PORT,BUSINESSTYPE,MAC from ROUTER')
			back_routers = cursor.fetchall()
		except Exception as err:
			logwriter("error", err)
			return -1
		for back_router in back_routers:
			if back_router[0] in del_items:  # skip the router has been prepared to remove
				continue
			if back_router[0] == front_router[0]:  # skip itself
				continue
			same_flag = 0
			back_ips_str = str(back_router[2])
			back_ips = back_ips_str.split(',')
			for ip in back_ips:  # judge the front router and back router
				if ip in front_ips_str:
					same_flag = 1  # the front router is same as back router
					break
			if same_flag == 1:  # fuse front router and back router to one
				#print('1front=',front_router)
				#print('1back=',back_router)
				if back_router[0] in keep_items:  # the back router prepared to keep should be keep
					for ip in front_ips:
						if ip in back_ips_str:
							continue
						back_ips_str = back_ips_str + ','
						back_ips_str = back_ips_str + ip
					os = back_router[1]
					net = back_router[3]
					portnum = int(back_router[4])
					servicenum = back_router[5]
					mac = back_router[6]
					if os == 'N/A' and front_router[1] != 'N/A':
						os = front_router[1]
					if net == 'N/A' and front_router[3] != 'N/A':
						net = front_router[3]
					if portnum < int(front_router[4]):
						portnum = front_router[4]
					if int(servicenum) < int(front_router[5]):
						servicenum = front_router[5]
					if mac == 'N/A' and front_router[6] != 'N/A':
						mac = front_router[6]
					var = {'id': back_router[0], 'ip': back_ips_str[0:100], 'os': os[0:64], 'net': net, 'port': int(portnum),
						   'business': servicenum, 'mac': mac,'updated':'1'}
					sql = 'update ROUTER set IP=:ip,OS=:os,NET=:net,PORT=:port,BUSINESSTYPE=:business,MAC=:mac,UPDATED=:updated where ID=:id'
					#print('1',sql,var)
					if update_oracle(sql, var) == -1:
						return -1
					#Get the lastest router info where ID=front_router[0]
					try:
						var = {'id': back_router[0]}
						cursor.execute('select ID,OS,IP,NET,PORT,BUSINESSTYPE,MAC from ROUTER where ID=:id',var)
						back_router = cursor.fetchone()
					except Exception as err:
						logwriter("error", err)
						return -1
					if front_router[0] not in del_items:
						del_items.append(front_router[0])  # add the router to delete list
				else:
					#print('2front=',front_router)
					#print('2back=',back_router)
					for ip in back_ips:
						if ip in front_ips_str:
							continue
						front_ips_str = front_ips_str + ','
						front_ips_str = front_ips_str + ip
					os = front_router[1]
					net = front_router[3]
					portnum = int(front_router[4])
					servicenum = front_router[5]
					mac = front_router[6]
					if os == 'N/A' and back_router[1] != 'N/A':
						os = back_router[1]
					if net == 'N/A' and back_router[3] != 'N/A':
						net = back_router[3]
					if portnum < int(back_router[4]):
						portnum = back_router[4]
					if int(servicenum) < int(back_router[5]):
						servicenum = back_router[5]
					if mac == 'N/A' and back_router[6] != 'N/A':
						mac = back_router[6]
					var = {'id': front_router[0], 'ip': front_ips_str[0:100], 'os': os[0:64], 'net': net,
						   'port': int(portnum), 'business': servicenum, 'mac': mac,'updated':'1'}
					sql = 'update ROUTER set IP=:ip,OS=:os,NET=:net,PORT=:port,BUSINESSTYPE=:business,MAC=:mac,UPDATED=:updated where ID=:id'
					#print('2',sql,var)
					if update_oracle(sql, var) == -1:
						return -1
					#Get the lastest router info where ID=front_router[0]
					try:
						var = {'id': front_router[0]}
						cursor.execute('select ID,OS,IP,NET,PORT,BUSINESSTYPE,MAC from ROUTER where ID=:id',var)
						front_router = cursor.fetchone()
					except Exception as err:
						logwriter("error", err)
						return -1
					if front_router[0] not in keep_items:
						keep_items.append(front_router[0])  # add the router to keep list
					if back_router[0] not in del_items:
						del_items.append(back_router[0])  # add the router to delete list
	# delete the repeated data from ROUTER
	for item in del_items:
		# delete repeated ROUTER from our database
		var = {'id': item}
		sql = 'delete from ROUTER where ID=:id'
		if update_oracle(sql, var) == -1:
			return -1

def update_router_of_host():
	"""Update ROUTER of our HOST from HOST"""
	logwriter("debug", "call update_router_of_host()")
	try:
		cursor.execute('select IP,HSERVICENUM,HOS,HOPENPORTNUM,HDEVICE,HMAC,HMASK from HOST')
		hosts = cursor.fetchall()
	except Exception as err:
		logwriter("error", err)
		return -1
	if cursor.rowcount == 0:
		logwriter("warning", 'Our HOST table is empty')
		return
	for host in hosts:
		ip = host[0]    #the ip address of device
		devicetype = host[4]  #the type of device
		ip_last_str = ip.split('.')[3]
		if (devicetype != None and ('router' in devicetype or 
			'WAP' in devicetype or 'switch' in devicetype)):   #"ip_last_str == '254' or ip_last_str == '1' or "all device contains these options are router
			servicenum = host[1]
			os = 'N/A'   #default
			portnum = host[3]
			#print(ip,devicetype,'type= ',type(portnum))
			mac = 'N/A'   #default
			net = 'N/A'   #default
			if host[2] != None:  #os
				os = host[2]
			if host[5] != None:  #mac
				mac = host[5]
			if host[6] != None:  #net without mask
				net = host[6].split('/')[0]
			try:
				cursor.execute('select ID,OS,IP,NET,PORT,BUSINESSTYPE,MAC from ROUTER')  # Judge the router whether exists
				routers = cursor.fetchall()
			except Exception as err:
				logwriter("error", err)
				return -1
			exist_flag = 0
			if cursor.rowcount > 0:
				for router in routers:
					if ip in router[2]:
						exist_flag = 1  # found the router ip
						if router[1] != 'N/A' and os == 'N/A':  # No lastest info,Use previous info
							os = router[1]
						if router[3] != 'N/A' and net == 'N/A':
							net = router[3]
						if int(router[4]) > int(portnum):
							portnum = router[4]
						if int(router[5]) > int(servicenum):
							servicenum = router[5]
						if router[6] != 'N/A' and mac == 'N/A':
							mac = router[6]
						var = {'id': router[0], 'os': os[0:64], 'net': net, 'port': int(portnum), 'business': servicenum,'mac': mac,'updated':'1'}
						sql = 'update ROUTER set OS=:os,NET=:net,PORT=:port,BUSINESSTYPE=:business,MAC=:mac,UPDATED=:updated where ID=:id'
						if update_oracle(sql, var) == -1:
							return -1
			if exist_flag == 0:  # Not found the router ip
				var = {'id': str(uuid.uuid4()), 'os': os[0:64], 'ip': ip, 'net': net, 'port': int(portnum),
					   'business': servicenum, 'mac': mac}
				sql = (
					"insert into ROUTER (ID,UPDATED,OS,IP,NET,PORT,BUSINESSTYPE,MAC,PROCESS,ATTACKED,KEY)"
					"values(:id,'1',:os,:ip,:net,:port,:business,:mac,'server.exe','0','0')"
				)
				if update_oracle(sql, var) == -1:
					return -1

def update_router_of_target():
	"""Update ROUTER of target database from HOST"""
	logwriter("debug", "call update_router_of_host()")
	try:
		cursor.execute('select IP,HSERVICENUM,HOS,HOPENPORTNUM,HDEVICE,HMAC,HMASK from HOST')
		hosts = cursor.fetchall()
	except Exception as err:
		logwriter("error", err)
		return -1
	if cursor.rowcount == 0:
		logwriter("warning", 'Our HOST table is empty')
		return
	for host in hosts:
		ip = host[0]    #the ip address of device
		devicetype = host[4]  #the type of device
		ip_last_str = ip.split('.')[3]
		if (devicetype != None and ('router' in devicetype or 
			'WAP' in devicetype or 'switch' in devicetype)):   #"ip_last_str == '254' or ip_last_str == '1' or "all device contains these options are router
			servicenum = host[1]
			os = 'N/A'   #default
			portnum = host[3]
			#print(ip,devicetype,'type= ',type(portnum))
			mac = 'N/A'   #default
			net = 'N/A'   #default
			if host[2] != None:  #os
				os = host[2]
			if host[5] != None:  #mac
				mac = host[5]
			if host[6] != None:  #net without mask
				net = host[6].split('/')[0]
			try:
				cursor_target.execute('select ID,OS,IP,NET,PORT,BUSINESSTYPE,MAC from ROUTER')  # Judge the router whether exists
				routers = cursor_target.fetchall()
			except Exception as err:
				logwriter("error", err)
				return -1
			exist_flag = 0
			if cursor_target.rowcount > 0:
				for router in routers:
					if ip in router[2]:
						exist_flag = 1  # found the router ip
						if router[1] != 'N/A' and os == 'N/A':  # No lastest info,Use previous info
							os = router[1]
						if router[3] != 'N/A' and net == 'N/A':
							net = router[3]
						if int(router[4]) > int(portnum):
							portnum = router[4]
						if int(router[5]) > int(servicenum):
							servicenum = router[5]
						if router[6] != 'N/A' and mac == 'N/A':
							mac = router[6]
						var = {'id': router[0], 'os': os[0:64], 'net': net, 'port': int(portnum), 'business': servicenum,'mac': mac,'updated':'1'}
						sql = 'update ROUTER set OS=:os,NET=:net,PORT=:port,BUSINESSTYPE=:business,MAC=:mac,UPDATED=:updated where ID=:id'
						if update_oracle_target(sql, var) == -1:
							return -1
			if exist_flag == 0:  # Not found the router ip
				var = {'id': str(uuid.uuid4()), 'os': os[0:64], 'ip': ip, 'net': net, 'port': int(portnum),
					   'business': servicenum, 'mac': mac}
				sql = (
					"insert into ROUTER (ID,UPDATED,OS,IP,NET,PORT,BUSINESSTYPE,MAC,PROCESS,ATTACKED,KEY)"
					"values(:id,'1',:os,:ip,:net,:port,:business,:mac,'server.exe','0','0')"
				)
				if update_oracle_target(sql, var) == -1:
					return -1

def update_router_from_host():
	"""Transfer data to ROUTER(endpoint) to ROUTER(frontend)"""
	logwriter("debug", "call update_router_from_host()")
	try:
		cursor.execute('select * from ROUTER')
		front_routers = cursor.fetchall()
	except Exception as err:
		logwriter("error", err)
		return -1
	if cursor.rowcount == 0:
		logwriter("warning", 'Our ROUTER table is empty')
		return
	for front_router in front_routers:
		#print('1111111111',front_router)
		router_id = front_router[0]
		router_os = front_router[2]
		router_ip_str = front_router[3]
		router_net = front_router[4]
		router_port = front_router[5]
		router_businesstype = front_router[6]
		router_mac = front_router[7]
		#delete ROUTER firstly
		try:
			cursor_target.execute('select * from ROUTER')
			routers = cursor_target.fetchall()
		except Exception as err:
			logwriter("error", err)
			return -1
		router_exist_flag = 0  #default
		if cursor_target.rowcount == 0:
			logwriter("warning", 'ROUTER table is empty')
			router_exist_flag = 0
		else:
			for router in routers:
				if router[3] in router_ip_str:  #only update changed router
				  	if (router_os == router[2] and router_ip_str == router[3] and
						router_net == router[4] and router_port == router[5] and 
						router_businesstype == router[6] and router_mac == router[7]):
				  		router_exist_flag = 1
				  		break
				  	else:
				  		var = {'id':router[0]}
				  		# sql = 'delete from SEGMENT_ROUTER_REL where ROUTER_ID=:id'
				  		# if update_oracle_target(sql, var) == -1:
				  		# 	return -1
				  		# sql = 'delete from ROUTER_ROUTER_REL where ROUTER1_ID=:id or ROUTER2_ID=:id'
				  		# if update_oracle_target(sql,var) == -1:
				  		# 	return -1
				  		# sql = 'delete from ROUTER where ID=:id'
				  		# if update_oracle_target(sql,var) == -1:
				  		# 	return -1
				  		cursor_target.execute('select * from ROUTER_DELETE where ID=:id',var);
				  		cursor_target.fetchall()
				  		if cursor_target.rowcount > 0:
				  			continue
				  		var = {'id':router[0],'updated':'1'}
				  		sql = 'insert into ROUTER_DELETE (ID,UPDATED)values(:id,:updated)'
				  		if update_oracle_target(sql,var) == -1:
				  			return -1
		if router_exist_flag == 1:
			continue
		var = {'id':str(uuid.uuid4()),'os':router_os,'ip':router_ip_str,'net':router_net,'port':router_port,'businesstype':router_businesstype,'mac':router_mac}
		sql = (
			"insert into ROUTER (ID,UPDATED,OS,IP,NET,PORT,BUSINESSTYPE,MAC,PROCESS,ATTACKED,KEY)"
			"values(:id,'1',:os,:ip,:net,:port,:businesstype,:mac,'server.exe','0','0')"
			)
		#print('222222222222222222',sql,var)
		if update_oracle_target(sql,var) == -1:
			return -1

def update_router_with_file(file_full_path):
	if update_router_from_file(file_full_path) == -1:
		logwriter('debug','Failed to update ROUTER from file')
		return -1
	logwriter('debug','Succeeded to update ROUTER from file')
	if update_router_of_host() == -1:
		logwriter('debug','Failed to update ROUTER of host')
		return -1
	logwriter('debug','Succeeded to update ROUTER of host')

def update_router_without_file():
	if update_router_of_host() == -1:
		logwriter('debug','Failed to update ROUTER of host')
		return -1
	logwriter('debug','Succeeded to update ROUTER of host')
	if update_router_of_target() == -1:
		logwriter('debug','Failed to update ROUTER of target')
		return -1

def update_mask(mask_int):
	"""Transfer number to mask"""
	logwriter("debug", "call update_mask()")
	bin_arr = ['0' for i in range(32)]
	for i in range(mask_int):
		bin_arr[i] = '1'
	tmpmask = [''.join(bin_arr[i * 8:i * 8 + 8]) for i in range(4)]
	tmpmask = [str(int(tmpstr, 2)) for tmpstr in tmpmask]
	return '.'.join(tmpmask)

def update_segment_from_file(file_full_path):
	"""Update SEGMENT from segment.txt,only update, not insert"""
	logwriter("debug", "call update_segment_from_file()")
	items = resolve_file.segment_resolve(file_full_path)
	# data from segment.txt
	if items != -1 and items != []:
		for item in items:
			try:
				var = {'net': item['net']}
				cursor_target.execute('select ID,MASK from SEGMENT where NET=:net', var)
				segments = cursor_target.fetchall()
			except Exception as err:
				logwriter("error", err)
				return -1
			if cursor_target.rowcount <= 0:   #The segment table is empty
				continue
			else:
				for segment in segments:
					if segment[1] == 'N/A':  
						var = {'id': segment[0], 'mask': item['mask'],'updated':'1'}#update the mask field
						sql = 'update SEGMENT set MASK=:mask,UPDATED=:updated where ID=:id'
						if update_oracle_target(sql, var) == -1:
							return -1

def update_segment_router_rel():
	"""estiblish the table SEGMENT and ROUTER"""
	logwriter("debug", "call update_segment_router_rel()")
	try:
		# Get ID,NET from table ROUTER
		cursor_target.execute('select ID,NET,IP from ROUTER')
		routers = cursor_target.fetchall()
	except Exception as err:
		logwriter("error", err)
		return -1
	# logwriter('The table ROUTER rows is %d'%cursor_target.rowcount)
	if cursor_target.rowcount == 0:
		logwriter("info", 'The table ROUTER is empty!')
		return

	# Get ID,NET form table SEGMENT
	try:
		cursor_target.execute('select ID,NET,MASK from SEGMENT')
		segments = cursor_target.fetchall()
	except Exception as err:
		logwriter("error", err)
		return -1
	# logwriter('The table SEGMENT rows is %d'%cursor_target.rowcount)
	if cursor_target.rowcount == 0:
		logwriter("info", 'The table SEGMENT is empty!')
		return

	# update the table SEGMENT_ROUTER_REL
	for router in routers:
		for segment in segments:
			router_net = router[1]
			if router[1] != 'N/A' or router[1] != None:  # NET of ROUTER has values
				if router_net == segment[1]:  # the network number is equal
					# Judge the segment-router pair exist or not
					var = {'sid': segment[0], 'rid': router[0]}
					try:
						cursor_target.execute(
							'select * from SEGMENT_ROUTER_REL where SEGMENT_ID=:sid and ROUTER_ID=:rid', var)
						cursor_target.fetchone()
					except Exception as err:
						logwriter("error", err)
						return -1
					if cursor_target.rowcount == 0:
						var = {'id': str(uuid.uuid4()), 'sid': segment[0], 'rid': router[0],
							   'traffic': str(round(float(random.randint(1, 900) / 1000), 2)) + 'kb/s'}
						sql = 'insert into SEGMENT_ROUTER_REL (ID,UPDATED,SEGMENT_ID,ROUTER_ID,TRAFFIC)values(:id,1,:sid,:rid,:traffic)'
						if update_oracle_target(sql, var) == -1:
							return -1
			# update potential net=make&ip(of ips)
			ips_str = str(router[2])
			ips = ips_str.split(',')
			for ip in ips:
				if segment[2] == 'N/A':
					continue
				router_net = str(IP(ip).make_net(segment[2])).split('/', 1)[0]
				if router_net == segment[1]:  # the network number is equal
					# Judge the segment-router pair exist or not
					var = {'sid': segment[0], 'rid': router[0]}
					try:
						cursor_target.execute(
							'select * from SEGMENT_ROUTER_REL where SEGMENT_ID=:sid and ROUTER_ID=:rid', var)
						cursor_target.fetchone()
					except Exception as err:
						logwriter("error", err)
						return -1
					if cursor_target.rowcount == 0:
						var = {'id': str(uuid.uuid4()), 'sid': segment[0], 'rid': router[0],
							   'traffic': str(round(float(random.randint(1, 5000) / 1000), 2)) + 'kb/s'}
						sql = 'insert into SEGMENT_ROUTER_REL (ID,UPDATED,SEGMENT_ID,ROUTER_ID,TRAFFIC)values(:id,1,:sid,:rid,:traffic)'
						if update_oracle_target(sql, var) == -1:
							return -1

def update_segment_host_rel():
	"""connect the table segment and host"""
	logwriter("debug", "call update_segment_host_rel()")
	try:
		# Get ip address from table HOST
		cursor_target.execute('select ID,NET,IP from HOST')
		host_ips = cursor_target.fetchall()
		if cursor_target.rowcount == 0:
			logwriter("info", 'The table HOST is empty!')
			return -1
		# Get NET,MASK form table SEGMENT
		cursor_target.execute('select ID,NET,MASK from SEGMENT')
		segments = cursor_target.fetchall()
		if cursor_target.rowcount == 0:
			logwriter("info", 'The table SEGMENT is empty!')
			return -1
	except Exception as err:
		logwriter("error", err)
		return -1
	# update the table SEGMENT_HOST_REL
	id = 0
	for ip in host_ips:
		for segment in segments:
			if ip[1] == 'N/A' or ip[1] == None:  # network number not known or empty
				if segment[2] == 'N/A':   #the mask is 'N/A'
					ip_str = ip[2].split('.')
					ip_net = ip_str[0] + '.' + ip_str[1] + '.' + ip_str[2] + '.0'
				else:
					ip_net = str(IP(ip[2]).make_net(segment[2]))
					ip_net = ip_net.split('/', 1)[0]
			else:
				ip_net = ip[1].split('/')[0]
			#logwriter(ip_net,segment[1])
			if ip_net == segment[1]:  # the network number is equal
				# Judge the segment-host pair exist or not
				var = {'sid': segment[0], 'hid': ip[0]}
				try:
					cursor_target.execute('select * from SEGMENT_HOST_REL where SEGMENT_ID=:sid and HOST_ID=:hid', var)
					# cursor.execute('select * from SEGMENT_HOST_REL where SEGMENT_ID='+segment[0]+' and HOST_ID='+ip[0]+'')
					cursor_target.fetchone()
					if cursor_target.rowcount == 0:
						var = {'id': str(uuid.uuid4()), 'sid': segment[0], 'hid': ip[0],
							   'traffic': str(round(float(random.randint(1, 900) / 1000), 2)) + 'kb/s'}
						sql = 'insert into SEGMENT_HOST_REL (ID,UPDATED,SEGMENT_ID,HOST_ID,TRAFFIC)values(:id,1,:sid,:hid,:traffic)'
						# logwriter(sql,var)
						if update_oracle_target(sql, var) == -1:
							return -1
						break
				except Exception as err:
					logwriter("error", err)
					return -1

def update_router_rel(file_full_path):
	"""Transfer data from router connection.txt to our table ROUTER_REL """
	items = resolve_file.router_connection_resolve(file_full_path)
	if items == -1 or items == []:
		return -1
	for item in items:
		routerip1 = item['router1']
		routerip2 = item['router2']
		var = {'router1':routerip1,'router2':routerip2}
		try:
			cursor.execute('select * from ROUTER_REL where ROUTER1=:router1 and ROUTER2=:router2',var)
			routers = cursor.fetchall()
		except Exception as err:
			logwriter('error', err)
			return -1
		if cursor.rowcount > 0:  # ROUTER is not empty
			continue
		sql = 'insert into ROUTER_REL (ROUTER1,ROUTER2) values(:router1,:router2)'
		if update_oracle(sql,var) == -1:
			return -1

def update_router_router_rel(file_full_path):
	"""Transfer data from table ROUTER_REL to ROUTER_ROUTER_REL"""
	if update_router_rel(file_full_path) == -1:
		logwriter('debug', 'Failed to update our table ROUTER_REL')
	try:
		cursor.execute('select * from ROUTER_REL')
		routers = cursor.fetchall()
	except Exception as err:
		logwriter('error', err)
		return -1
	for router in routers:
		routerip1 = router[0]
		routerip2 = router[1]
		#print(routerip1,routerip2)
		try:
			cursor_target.execute('select ID,IP from ROUTER')
			router_ips = cursor_target.fetchall()
		except Exception as err:
			logwriter('error', err)
			return -1
		#print(cursor_target.rowcount)	
		if cursor_target.rowcount <= 0 :
			continue
		router1_flag = 0  # router exists router1_flag=1, if not router1_flag= 0
		router2_flag = 0
		for router_ip in router_ips:
			if routerip1 in router_ip[1]:
				router1_flag = 1
				router1_id = router_ip[0]   #get router1's id
			if routerip2 in router_ip[1]:
				router2_flag = 1
				router2_id = router_ip[0]   #get router2's id
			if router1_flag == 1 and router2_flag == 1:
				break
		if router1_flag == 1 and router2_flag == 1 and router1_id != router2_id:
			#print(router1_id,router2_id)
			var = {'ROUTER1_ID': router1_id, 'ROUTER2_ID': router2_id}  # Judge the router connection whether exists
			try:
				cursor_target.execute(
					'select * from ROUTER_ROUTER_REL where ROUTER1_ID=:ROUTER1_ID and ROUTER2_ID=:ROUTER2_ID', var)
				cursor_target.fetchall()
			except Exception as err:
				logwriter('error', err)
				return -1
			if cursor_target.rowcount > 0:
				continue
			var = {'ID': str(uuid.uuid4()), 'ROUTER1_ID': router1_id, 'ROUTER2_ID': router2_id,
				   'TRAFFIC': str(round(float(random.randint(1, 5000) / 1000), 2)) + 'kb/s'}
			sql = (
				"insert into ROUTER_ROUTER_REL (ID,UPDATED,ROUTER1_ID,ROUTER2_ID,TRAFFIC)"
				"values(:ID,'1',:ROUTER1_ID,:ROUTER2_ID,:TRAFFIC)"
			)
			#print(sql,var)
			if update_oracle_target(sql, var) == -1:
				return -1

def update_router_router_rel_last():
	"""Transfer data from table ROUTER_REL to ROUTER_ROUTER_REL"""
	try:
		cursor.execute('select * from ROUTER_REL')
		routers = cursor.fetchall()
	except Exception as err:
		logwriter('error', err)
		return -1
	for router in routers:
		routerip1 = router[0]
		routerip2 = router[1]
		#print(routerip1,routerip2)
		try:
			cursor_target.execute('select ID,IP from ROUTER')
			router_ips = cursor_target.fetchall()
		except Exception as err:
			logwriter('error', err)
			return -1
		#print(cursor_target.rowcount)	
		if cursor_target.rowcount <= 0 :
			continue
		router1_flag = 0  # router exists router1_flag=1, if not router1_flag= 0
		router2_flag = 0
		for router_ip in router_ips:
			if routerip1 in router_ip[1]:
				router1_flag = 1
				router1_id = router_ip[0]   #get router1's id
			if routerip2 in router_ip[1]:
				router2_flag = 1
				router2_id = router_ip[0]   #get router2's id
			if router1_flag == 1 and router2_flag == 1:
				break
		if router1_flag == 1 and router2_flag == 1 and router1_id != router2_id:
			#print(router1_id,router2_id)
			var = {'ROUTER1_ID': router1_id, 'ROUTER2_ID': router2_id}  # Judge the router connection whether exists
			try:
				cursor_target.execute(
					'select * from ROUTER_ROUTER_REL where ROUTER1_ID=:ROUTER1_ID and ROUTER2_ID=:ROUTER2_ID', var)
				cursor_target.fetchall()
			except Exception as err:
				logwriter('error', err)
				return -1
			if cursor_target.rowcount > 0:
				continue
			var = {'ID': str(uuid.uuid4()), 'ROUTER1_ID': router1_id, 'ROUTER2_ID': router2_id,
				   'TRAFFIC': str(round(float(random.randint(1, 5000) / 1000), 2)) + 'kb/s'}
			sql = (
				"insert into ROUTER_ROUTER_REL (ID,UPDATED,ROUTER1_ID,ROUTER2_ID,TRAFFIC)"
				"values(:ID,'1',:ROUTER1_ID,:ROUTER2_ID,:TRAFFIC)"
			)
			#print(sql,var)
			if update_oracle_target(sql, var) == -1:
				return -1

gi = pygeoip.GeoIP(r"GeoLiteCity.dat")
def regGeoStr(ip):
	"""Get location based on ip addr"""
	try:
		rec = gi.record_by_addr(ip)
		if rec == None:
			return
		city = rec['city']
		country = rec['country_name']
		location = str(country)  +' ' + str(city)
		return location
	except Exception as e:
		logwriter("error", e)
		return 'Unregistered'

def update_site_segment_pairs():
	"""Transfer data to SEGMENT ,from our HOST where ISAGENT = 1(individual agent)"""	
	logwriter("debug", "call update_site_segment_pairs()")	
	#update SEGMENT from HOST
	try:
		cursor.execute('select HMASK,IP,SOURCE from HOST where HISDEL=0 and (ISAGENT=1 or SOURCE=2)')
		nets = cursor.fetchall()
		if cursor.rowcount == 0:  #The HOST IS EMPTY
			return -1
	except Exception as err:
		logwriter("error",err)
	for net in nets:
		if net[2] == '2':
			if net[0] == None:
				ip_str = net[1].split('.')
				NET = ip_str[0] + '.' + ip_str[1] + '.' + ip_str[2] + '.0'
				MASK = 'N/A'
			else:
				NET = net[0].split('/')[0]
				prefix = net[0].split('/')[1]
				MASK = update_mask(int(prefix))
		else:
			NET = net[0].split('/')[0]
			prefix = net[0].split('/')[1]
			MASK = update_mask(int(prefix))
		try:
			var = {'Net':NET}
			cursor_target.execute('select NET,MASK from SEGMENT where NET=:Net',var)  #Judging the network number whether exists
			segments = cursor_target.fetchall()
		except Exception as err:
			logwriter("error",err)
			return -1
		if cursor_target.rowcount > 0:   #the segment exists in SEGMENT, then update SEGMENT
			for segment in segments:
				if MASK != 'N/A':
					var = {'Net':NET,'Mask':MASK,'updated':'1'}
					sql = 'update SEGMENT set MASK=:Mask,UPDATED=:updated where NET=:Net'
					if update_oracle_target(sql,var) == -1:
						return -1
			continue
		else:
			segment_ID = str(uuid.uuid4())
			var = {'id':segment_ID,'Net':NET,'Mask':MASK}
			sql = 'insert into SEGMENT (ID,UPDATED,NET,MASK)values(:id,1,:Net,:Mask)'
			if update_oracle_target(sql,var) == -1:
				return -1
			# update SITE based on SEGMENT

			location = regGeoStr(NET)
			if location == None:
				location = 'N/A'
			site_ID = str(uuid.uuid4())
			number = str(random.randint(1,100))
			var = {'id':site_ID,'name':'site-' + number,'detail':'This is site-' + number + '.','address':'South Sea','net':NET}#location[0:20]
			sql = (
				"insert into SITE (ID,UPDATED,STATUS,NAME,DETAIL,ADDRESS,NET,TYPE)"
				"values(:id,'1','offline',:name,:detail,:address,:net,2)"
  				)
			if update_oracle_target(sql,var)==-1:
				return -1
			#update SITE_SITE_REL based on SITE and SEGMENT
			var = {'id':str(uuid.uuid4()),'site_id':site_ID,'segment_id':segment_ID,'traffic':str(round(float(random.randint(1,900)/1000),2))+'kb/s'}
			sql = (
				"insert into SITE_SEGMENT_REL (ID,UPDATED,SITE_ID,SEGMENT_ID,TRAFFIC)"
				"values(:id,'1',:site_id,:segment_id,:traffic)"
				)
			if update_oracle_target(sql,var)==-1:
				return -1
"""end"""
		
def GetHostIdByIp(ip):
	logwriter("debug", "call GetHostIdByIp()")
	host_id = ""
	try:
		cursor_target.execute("""
		select ID from {username}.HOST where IP=:tip
		""".format(username=db_username_target),tip=ip)
		result = cursor_target.fetchall()
		if len(result) > 1:
			logwriter("warning", "more than one record in HOST table noticing the same ip")
		elif len(result) == 0:
			logwriter("warning", "no host_id related to this specified ip")
		host_id = result[0][0]
	except:
		logwriter("error", "fail to fetch id from the HOST table")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
	return host_id

def GetEntityIdByHostId(host_id):
	logwriter("debug", "call GetEntityIdByHostId()")
	entity_id = ""
	try:
		cursor_target.execute("""
		select ID from {username}.ENTITY where HOST_ID=:ho_id
		""".format(username=db_username_target),ho_id=host_id)
		result = cursor_target.fetchall()
		if len(result) > 1:
			logwriter("warning", "more than one record in ENTITY table referencing to the same host")
		entity_id = result[0][0]
	except:
		logwriter("error", "fail to fetch id from the ENTITY table")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
	return entity_id

def SetAllInstructionDone():
	logwriter("debug", "call SetAllInstructionDone()")
	try:
		cursor_target.execute("""
		update {username}.TASK set PERIOD="done", UPDATED=1 where TYPE="指令传输"
		""".format(username = db_username_target))
	except:
		logwriter("error", "fail to set all the instruction tasks done")
		error_info = sys.exc_info()
		if len(error_info) > 1:
				logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))


# 已修改，未测
#承担了更新及插入两种操作
def UpdateTask(host_id, entity_id, Type, period, process):
	logwriter("debug", "call update_task()")
	taskmessage = "host_id: " + host_id + " entity_id: " + entity_id + " type: " + Type + " " + " period: " + period + " process: " + process
	logwriter("debug", taskmessage)
	task_id_tmp = str(uuid.uuid4())
	if Type == "嗅探分析": #不需要插入target_id
		sql_t = """
		declare t_count number(10);
			begin
				select count(*) into t_count from {username}.TASK where EXECUTOR_ID={e_id} and TYPE={tasktype};
				if t_count=0 then
					insert into {username}.TASK(ID,UPDATED,EXECUTOR_ID,TYPE,PERIOD,PROCESS,TARGET_ID) values({id},'1',{e_id},{tasktype},{taskperiod},{taskprocess},NULL);
				else
					update {username}.TASK set UPDATED=1,PERIOD={taskperiod},PROCESS={taskprocess} where EXECUTOR_ID={e_id} and TYPE={tasktype};
				end if;
			end;
		""".format(username = db_username_target, id = task_id_tmp, e_id = entity_id, tasktype = Type, taskperiod = period, taskprocess = process)
		logwriter("debug", "任务表sql:")
		logwriter("debug", sql_t)
		try:
			cursor_target.execute("""
			declare t_count number(10);
			begin
				select count(*) into t_count from {username}.TASK where EXECUTOR_ID=:e_id and TYPE=:tasktype;
				if t_count=0 then
					insert into {username}.TASK(ID,UPDATED,EXECUTOR_ID,TYPE,PERIOD,PROCESS,TARGET_ID) values(:id,'1',:e_id,:tasktype,:taskperiod,:taskprocess,NULL);
				else
					update {username}.TASK set UPDATED=1,PERIOD=:taskperiod,PROCESS=:taskprocess where EXECUTOR_ID=:e_id and TYPE=:tasktype;
				end if;
			end;
			""".format(username=db_username_target),id=task_id_tmp,e_id=entity_id,tasktype=Type,taskperiod=period,taskprocess=process)
		except:
			logwriter("error", "fail to insert new task into the TASK table")
			error_info = sys.exc_info()
			if len(error_info) > 1:
				logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
	#更新任务表，若为“指令传输”，则TARGET_ID代表路由器ID
	elif Type == "文件传输" or Type == "渗透扩散" or Type == "指令传输":
		sql_t = """
			declare t_count number(10);
			begin
				select count(*) into t_count from {username}.TASK where EXECUTOR_ID={e_id} and TARGET_ID={ho_id} and TYPE={tasktype};
				if t_count=0 then
					insert into {username}.TASK(ID,UPDATED,EXECUTOR_ID,TYPE,PERIOD,PROCESS,TARGET_ID) values({id},'1',{e_id},{tasktype},{taskperiod},{taskprocess},{ho_id});
				else
					update {username}.TASK set UPDATED=1,PERIOD={taskperiod},PROCESS={taskprocess} where EXECUTOR_ID={e_id} and TARGET_ID={ho_id} and TYPE={tasktype};
				end if;
			end;		
			""".format(username = db_username_target, id = task_id_tmp, e_id = entity_id, ho_id = host_id, tasktype = Type, taskperiod = period, taskprocess = process)
		logwriter("debug", "任务表sql")
		logwriter("debug", sql_t)
		try:
			cursor_target.execute("""
			declare t_count number(10);
			begin
				select count(*) into t_count from {username}.TASK where EXECUTOR_ID=:e_id and TARGET_ID=:ho_id and TYPE=:tasktype;
				if t_count=0 then
					insert into {username}.TASK(ID,UPDATED,EXECUTOR_ID,TYPE,PERIOD,PROCESS,TARGET_ID) values(:id,'1',:e_id,:tasktype,:taskperiod,:taskprocess,:ho_id);
				else
					update {username}.TASK set UPDATED=1,PERIOD=:taskperiod,PROCESS=:taskprocess where EXECUTOR_ID=:e_id and TARGET_ID=:ho_id and TYPE=:tasktype;
				end if;
			end;
			""".format(username=db_username_target),id=task_id_tmp,e_id=entity_id,ho_id=host_id,tasktype=Type,taskperiod=period,taskprocess=process)
		except:
			logwriter("error", "fail to insert new task into the TASK table")
			error_info = sys.exc_info()
			if len(error_info) > 1:
				logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
	else:
		logwriter("error", "Unknown task type. Fail to updatetask")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
	conn_target.commit()

# 新增，未测
def updateEty_Ety_Rel(entity_id_p, entity_id_c):
	logwriter("debug", "call updateEty_Ety_Rel()")
	try:
		cursor_target.execute("""
			declare t_count number(10);
			begin
				select count(*) into t_count from {username}.ENTITY_ENTITY_REL where PARENT_ID=:e_pid and CHILD_ID=:e_cid;
				if t_count=0 then
					insert into {username}.ENTITY_ENTITY_REL(ID, UPDATED, PARENT_ID, CHILD_ID) values(:id,'1',:e_pid,:e_cid);
				else
					update {username}.ENTITY_ENTITY_REL set UPDATED=1 where PARENT_ID=:e_pid and CHILD_ID=:e_cid;
				end if;
			end;
			""".format(username=db_username_target),id=(str(uuid.uuid4())),e_pid=entity_id_p,e_cid=entity_id_c)
	except:
		logwriter("error", "fail to update entity_entity_rel")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
	conn_target.commit()


# 找出父节点的工具id
def find_entity_pid(entity_id):
	logwriter("debug", "call find_entity_pid()")
	try:
		cursor_target.execute("""
			select PARENT_ID from {username}.ENTITY_ENTITY_REL where CHILD_ID=:e_cid
			""".format(username=db_username_target),e_cid=entity_id)
		result = cursor_target.fetchall()
		if not result:
			logwriter("warning", "this entity has no parent entity. is it a root entity? :(")
			hid = GetHostIdByEntityId(entity_id)
			logwriter("info", "Its host_id is " + hid)
			global root_parent_ip
			if hid:
				if hid == GetHostIdByIp(root_parent_ip):
					logwriter("info", "yes it is the root_parent_ip")
				else:
					logwriter("error", "Unknown error")
			else:
				logwriter("error", "this entity is not embedded in any host?")
			return False
		if len(result) > 1:
			logwriter("error", "this entity has more than on entity. fatal error!")
			return False
		return result[0][0]
	except:
		logwriter("error", "fail to find the parent entity id of specified entity id")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))

# 根据entity_id取host_id
def GetHostIdByEntityId(entity_id):
	logwriter("debug", "call GetHostIdByEntityId()")
	try:
		logwriter("info", "ready to call GetHostIdByEntityId, entity_id=" + entity_id)
		cursor_target.execute("""
			select HOST_ID from {username}.ENTITY where ID=:e_id
			""".format(username=db_username_target),e_id=entity_id)
		result = cursor_target.fetchall()
		if not result:
			logwriter("error", "cannot find host_id of a specified entity")
			return False
		if len(result) > 1:
			logwriter("error", "A specified agent should only have one entity!")
			return False
		return result[0][0]
	except:
		logwriter("error", "fail to fecth host_id by entity id")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
		return False

def whoDiscoverMe(ip):
	logwriter("debug", "call whoDiscoverMe()")
	try:
		cursor.execute("""
			select PIP from {username}.HOST where IP=:tip
			""".format(username=db_username),tip=ip)
		result = cursor.fetchall()
		if not result:
			logwriter("error", "who discovered this new agent? :(")
		if len(result) > 1:
			logwriter("critical", "break the law of 1nf")
		return result[0][0]
	except:
		logwriter("error", "fail to find the discoverer of the new agent")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
			
def GetRouterIds():
	logwriter("debug", "call GetRouterIds()")
	r_ids = []
	try:
		cursor_target.execute("""
		select ID from {username}.ROUTER
		""".format(username = db_username_target))
		res = cursor_target.fetchall()
		for item in res:
			r_ids.append(item[0])
	except:
		logwriter("error", "fail to fetch id of routers")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
	return r_ids

def GetChildEntityIdsByParentEntityId(entity_id):
	logwriter("debug", "call GetChildEntityIdsByParentEntityId")
	entity_ids = []
	try:
		cursor_target.execute("""
			select CHILD_ID from {username}.ENTITY_ENTITY_REL where PARENT_ID=:pid
			""".format(username = db_username_target), pid=entity_id)
		res = cursor_target.fetchall()
		if not res:
			return entity_ids
		for item in res:
			entity_ids.append(item[0])
	except:
		logwriter("error", "fail to fetch child id of a specified parent entity")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
	return entity_ids

def GetParentEntityIdByChildEntityId(entity_id):
	logwriter("debug", "call GetParentEntityIdByChildEntityId")
	try:
		cursor_target.execute("""
			select PARENT_ID from {username}.ENTITY_ENTITY_REL where CHILD_ID=:cid
		""".format(username = db_username_target), cid = entity_id)
		res = cursor_target.fetchall()
		if not res:
			return -1
		else:
			return res[0][0]
	except:
		logwriter("error", "fail to fetch parent id of a specified child entity")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
		return -1

def GetRouterDiscoveredByAgents(ip):
	#返回一个agent所发现的router在ROUTER表中的id
	logwriter("debug", "call GetRouterDiscoveredByAgents")
	router_ips = []
	router_ids = []
	try:
		cursor.execute("""
		select IP,HDEVICE from {username}.HOST where PIP = :tip
		""".format(username = db_username), tip = ip)
		res = cursor.fetchall()
		if not res:
			return router_ids
		for item in res:
			if item[1] != None:
				if "router" in item[1] or "WAP" in item[1] or "switch" in item[1]:
					router_ips.append(item[0])
	except:
		logwriter("error", "fail to fetch ip of router from our HOST table")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
	try:
		cursor_target.execute("""
		select ID,IP from {username}.HOST
		""".format(username = db_username_target))
		res = cursor_target.fetchall()
		for item in res:
			for ip in router_ips:
				if ip in item[1]:
					router_ids.append(item[0])
	except:
		logwriter("error", "fail to fetch id,ip from their ROUTER table")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
	return router_ids

# run different functions based on different signals
class switch_case(object):
	def case_to_function(self, case):
		fun_name = "case_" + str(case)
		logwriter("info", "ready to call function " + fun_name + "()")
		method = getattr(self, fun_name, self.case_default)
		return method
	#plz refer to document "task.odt"
	#correspond to 1
	#在一大轮探测中，该函数调用且仅调用一次
	
	def case_init_agents(self, msg):
		logwriter("info", "case_fun_init_agents: " + msg)
		#中心节点本身也需要加入表中且isAgent字段为2（不参与决策），只考虑插入我们的数据库
		global entity_sequence
		entity_sequence = 1
		localip = ""
		localip = get_host_ip()
		# 先清理前一大轮的数据，HISDEL置1
		try:
			cursor.execute("""
					update {username}.HOST set HISDEL=1
					""".format(username=db_username))
		except:
			logwriter("info", "fail to clear data")
			error_info = sys.exc_info()
			if len(error_info) > 1:
				logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
		# 清空AGENT表
		try:
			cursor.execute("""
			delete from {username}.AGENT
			""".format(username=db_username))
		except:
			logwriter("error", "fail to delete content of AGENT table")
			error_info = sys.exc_info()
			if len(error_info) > 1:
				logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
		conn.commit()
		# 真正的中心节点不要直接往他们的数据库里插，在我们的数据库中，真正的中心节点的isAgent仍然为2
		# try:
		# 	cursor.execute("""
		# 				declare
		# 					isAgent {username}.HOST.ISAGENT%TYPE;
		# 				begin
		# 					select ISAGENT into isAgent from {username}.HOST where IP=:ip;
		# 						case isAgent
		# 							when 0 then
		# 								update {username}.HOST set ISAGENT = 2, ISNEW = 0, HISDEL = 0 where IP=:ip;
		# 							when 1 then
		# 								update {username}.HOST set ISAGENT = 2,ISNEW = 0,HISDEL = 0 where IP=:ip;
		# 							when 2 then
		# 								update {username}.HOST set ISNEW = 0,HISDEL = 0 where IP=:ip;
		# 						end case;
		# 				exception
		# 						when NO_DATA_FOUND then
		# 							insert into {username}.HOST values(:ip,0,0,0,NULL,0,NULL,NULL,0,NULL,
		# 												0,0,2,0,0,0,0,0,0,NULL,NULL,0);
		# 				end;
		# 			""".format(username=db_username), ip=localip)
		# except:
		# 	logwriter("Error:fail to insert info of localip")
		# 	error_info = sys.exc_info()
		# 	if len(error_info) > 1:
		# 		logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
		#设置我们的数据库中的初始agent
		#要修改，因为第一轮可能有不止一个agent，不能简单地取一个
		#除了初始插入，还要把子网信息填上，子网信息就从config.json中获取
		#config.json中设置有多个主机，要将其中一个设置为父Agent
		global root_parent_ip
		root_parent_ip = ""
		has_parent_agent_set = False
		init_agents = []
		with open("config.json","r") as load_f:
			load_dict = json.load(load_f)
			for item in load_dict['projects']:
				for task in item["tasks"]:
					if task['type'] == "activeDetection":
						host_ip = item["hosts"][0].split(':')[0]
						logwriter("info", "初始的ip，从config.json中读到的: " + host_ip)
						host_subnet = task['taskArguments']
						init_agents.append(host_ip)
						host_subnet_without_prefix = host_subnet.split('/')[0]
						if not has_parent_agent_set:
							root_parent_ip = host_ip
							has_parent_agent_set = True
						try:
							cursor.execute("""
								declare
									isAgent {username}.HOST.ISAGENT%TYPE;
								begin
									select ISAGENT into isAgent from {username}.HOST where IP=:ip;
										case isAgent
											when 0 then
												update {username}.HOST set ISAGENT=1,ISNEW=0,HISDEL=0,HMASK=:subnet,SOURCE=1 where IP=:ip;
											when 1 then
												update {username}.HOST set ISNEW=0,HISDEL=0,HMASK=:subnet,SOURCE=1 where IP=:ip;
											when 2 then
												update {username}.HOST set ISAGENT=1,ISNEW=0,HISDEL=0,HMASK=:subnet,SOURCE=1 where IP=:ip;
										end case;
								exception
										when NO_DATA_FOUND then
											insert into {username}.HOST values(:ip,0,0,0,NULL,0,NULL,NULL,0,NULL,
																0,0,1,0,0,0,0,0,0,:subnet,NULL,1);
								end;
							""".format(username=db_username),ip=host_ip,subnet=host_subnet)
						except:
							logwriter("Error", "can not initialize database FAKE CENTER")
							error_info = sys.exc_info()
							if len(error_info) > 1:
								logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
						conn.commit()
						#需要初始化我们数据库中的AGENT表
						try:
							cursor.execute("""
								declare t_count number(10);
								begin
									select count(*) into t_count from {username}.AGENT where NET=:subnet;
									if t_count=0 then
										insert into {username}.AGENT(NET,AGSUM) values(:subnet, 1);
									end if;
								end;
							""".format(username=db_username),subnet=host_subnet)
						except:
							logwriter("error", "can not initialize database AGENT")
							error_info = sys.exc_info()
							if len(error_info) > 1:
								logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
						conn.commit()
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
										update {username}.HOST set UPDATED=1,NET=:subnet where IP=:ip;
									else
										insert into {username}.HOST(ID,UPDATED,OS,NET,IP,PORT,BUSINESSTYPE,MAC,PROCESS,ATTACKED,KEY,ENTRY) values(:id,'1','N/A',:subnet,:ip,0,'0','N/A','chrome.exe','0','0','1');
									end if;
								end;
							""".format(username=db_username_target),id=str(uuid.uuid4()),ip=host_ip,subnet=host_subnet_without_prefix)
						except:
							logwriter("error", "can not initialize database HOST")
							error_info = sys.exc_info()
							if len(error_info) > 1:
								logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
						conn_target.commit()
		time.sleep(10)
		#2.更新INJECTION表,SAT注入开始，这部分要移走，等到初始的agent全都加到别人的host表中以后再注入
		parent_host_id = ""
		if has_parent_agent_set and root_parent_ip != "":
			parent_host_id = GetHostIdByIp(root_parent_ip)
			# 取出host_id后，更新INJECTION表
			try:
				#in_id_t = str(uuid.uuid4())#暂存，用于后面更新注入
				cursor_target.execute("""
				declare t_count number(10);
					begin
						select count(*) into t_count from {username}.INJECTION where TARGET_ID=:h_id;
						if t_count=0 then
							insert into {username}.INJECTION(ID,UPDATED,TARGET_ID,PERIOD) values(:in_id,'1',:h_id,'start');
						else
							update {username}.INJECTION set UPDATED='1',PERIOD='start' where TARGET_ID=:h_id;
						end if;
					end;
				""".format(username=db_username_target),in_id=str(uuid.uuid4()),h_id=parent_host_id)
				logwriter("info", "SAT injection ok")
				conn_target.commit()
				logwriter("info", "看看卫星出来了没？")
				time.sleep(10)
			except:
				logwriter("error", "fail to insert new injection")
				error_info = sys.exc_info()
				if len(error_info) > 1:
					logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
		else:
			logwriter("error", "fail to get ready for injection, plz check your config.json :(")
		# 后续工作，重新读一下config.json
		with open("config.json","r") as load_f:
			load_dict = json.load(load_f)
			for item in load_dict['projects']:
				for task in item["tasks"]:
					if task['type'] == "activeDetection":
						host_ip = item["hosts"][0].split(':')[0]
						host_subnet = task['taskArguments']
						host_id = GetHostIdByIp(host_ip)
						host_subnet_without_prefix = host_subnet.split('/')[0]
						#网段表，站点表，网段站点关系表，网段主机关系表，工具表初始化
						#和后面的addSegment()不一样，单独写
						#初始化网段表：
						prefix = (host_subnet.split('/',1))[1]
						#subnet_addr = (host_subnet.split('/',1))[0]
						mask = prefix2mask(int(prefix))
						subnet_addr = str(IP(host_subnet_without_prefix).make_net(mask)).split('/')[0]
						#按照模拟程序的要求，先更新site表再更新segment表，最后更新关系表
						#site_id = str(uuid.uuid4())
						#考虑到更新的情况，site_id要从数据中取，为填网段站点关系表做准备
						site_name = "site-" + str(entity_sequence)#最大长度为10
						site_detail = 'This is site-' + str(entity_sequence) + '.'
						# site_id_tmp = str(uuid.uuid4())
						# logwriter(site_id_tmp)
						# logwriter(subnet_addr)
						try:
							cursor_target.execute("""
							insert into {username}.SITE(ID,UPDATED,STATUS,NAME,DETAIL,ADDRESS,NET,TYPE) values(:id,'1','offline',:name,:detail,'South Sea',:subnet,2)
							""".format(username=db_username_target),id=str(uuid.uuid4()),name=site_name,detail=site_detail,subnet=subnet_addr)
						except:
							logwriter("error", "fail to initialize the SITE table")
							error_info = sys.exc_info()
							if len(error_info) > 1:
								logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
						conn_target.commit()
						#segment_id = str(uuid.uuid4())
						# segment_id_tmp = str(uuid.uuid4())
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
							""".format(username=db_username_target),id=str(uuid.uuid4()),sba=subnet_addr,tmask=mask)
						except:
							logwriter("error", "fail to initialize the SEGMENT table")
							error_info = sys.exc_info()
							if len(error_info) > 1:
								logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
						conn_target.commit()
						# 准备填网段站点关系表
						# 这些ID号必须现取，完整性约束
						# 取网段ID号
						try:
							cursor_target.execute("""
							select ID from {username}.SEGMENT where NET=:sba and MASK=:tmask
							""".format(username=db_username_target),sba=subnet_addr,tmask=mask)
							result = cursor_target.fetchall()
							if len(result) > 1:
								logwriter("error", "more than one record noticing the same segment")
							segment_id = result[0][0]#存网段ID号
						except:
							logwriter("error", "fail to fetch id from the SEGMENT table")
							error_info = sys.exc_info()
							if len(error_info) > 1:
								logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
						#取站点ID号
						try:
							cursor_target.execute("""
							select ID from {username}.SITE where NAME=:name and NET=:sba
							""".format(username=db_username_target),name=site_name,sba=subnet_addr)
							result = cursor_target.fetchall()
							if len(result) > 1:
								logwriter("error", "more than one record noticing the same site name")
						except:
							logwriter("error", "fail to fetch id from the SITE table")
							error_info = sys.exc_info()
							if len(error_info) > 1:
								logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
						# logwriter("site_id_tmp:", site_id_tmp)
						# logwriter("segment_id_tmp:", segment_id_tmp)
						try:
							site_id_t = result[0][0]#如果已经有了的话，插入会失败
							cursor_target.execute("""
							declare t_count number(10);
							begin
								select count(*) into t_count from {username}.SITE_SEGMENT_REL where SITE_ID=:site_id and SEGMENT_ID=:seg_id;
								if t_count=0 then
									insert into {username}.SITE_SEGMENT_REL(ID,UPDATED,SITE_ID,SEGMENT_ID,TRAFFIC) values(:id,'1',:site_id,:seg_id,'0.06kb/s');
								else
									update {username}.SITE_SEGMENT_REL set UPDATED=1 where SITE_ID=:site_id and SEGMENT_ID=:seg_id;
								end if;
							end;
							""".format(username=db_username_target),id=str(uuid.uuid4()),site_id=site_id_t,seg_id=segment_id)
						except:
							logwriter("error", "fail to update SITE_SEGMENT_REL table")
							error_info = sys.exc_info()
							if len(error_info) > 1:
								logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
						conn_target.commit()
						#网段主机关系表
						try:
							cursor_target.execute("""
							declare t_count number(10);
							begin
								select count(*) into t_count from {username}.SEGMENT_HOST_REL where SEGMENT_ID=:sg_id and HOST_ID=:ho_id;
								if t_count=0 then
									insert into {username}.SEGMENT_HOST_REL(ID,UPDATED,SEGMENT_ID,HOST_ID,TRAFFIC) values(:id,'1',:sg_id,:ho_id,'0.02kb/s');
								else
									update {username}.SEGMENT_HOST_REL set UPDATED=1 where SEGMENT_ID=:sg_id and HOST_ID=:ho_id;
								end if;
							end;
							""".format(username=db_username_target),id=str(uuid.uuid4()),sg_id=segment_id,ho_id=host_id)
						except:
							logwriter("error", "fail to update SEGMENT_HOST_REL table")
							error_info = sys.exc_info()
							if len(error_info) > 1:
								logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
						conn_target.commit()
						#工具表	ps：工具关系表怎么弄？模拟的程序中把工具关系表的更新设在构建自组织网络任务中
						#工具表中的编号何解？
						now_time_t = datetime.datetime.now()
						now_time = datetime.datetime.strftime(now_time_t,'%Y/%m/%d %H:%M:%S')#转为sql需要的日期形式
						
						try:
							cursor_target.execute("""
							declare t_count number(10);
							begin
								select count(*) into t_count from {username}.ENTITY where HOST_ID=:ho_id;
								if t_count=0 then
									insert into {username}.ENTITY(ID,UPDATED,PLATFORM,LOAD,DESCRIPTION,ONLINE_TIME,HOST_ID,NUM,STATUS) values(:id,'1',NULL,NULL,NULL,TO_TIMESTAMP(:time,'YYYY/MM/DD HH24:MI:SS'),:ho_id,:e_seq,'online');
								else
									update {username}.ENTITY set UPDATED=1,STATUS='online' where HOST_ID=:ho_id;
								end if;
							end;
							""".format(username=db_username_target),id=str(uuid.uuid4()),ho_id=host_id,time=now_time,e_seq=entity_sequence)
							entity_sequence += 1
						except:
							logwriter("error", "fail to update the ENTITY table")
							error_info = sys.exc_info()
							if len(error_info) > 1:
								logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
						conn_target.commit()
		#只更新那一个Injection
		#再次更新注入表，先取出本轮的注入id号
		try:
			cursor_target.execute("""
			select ID from {username}.INJECTION where TARGET_ID=:ho_id
			""".format(username=db_username_target),ho_id=parent_host_id)
			result = cursor_target.fetchall()
			if len(result) > 1:
				logwriter("info", "more than one record noticing the same host in INJECTION table")
			injection_id = result[0][0]
		except:
			logwriter("error", "fail to fetch ID from the INJECTION table")
			error_info = sys.exc_info()
			if len(error_info) > 1:
				logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
		conn_target.commit()
		try:
			cursor_target.execute("""
			update {username}.INJECTION set UPDATED=1,PERIOD='done' where ID=:in_id
			""".format(username=db_username_target),in_id=injection_id)
		except:
			logwriter("error", "fail to update the INJECTION table")
			error_info = sys.exc_info()
			if len(error_info) > 1:
				logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
		conn_target.commit()
		time.sleep(10)
		#to make agent net
		for ip in init_agents:
			host_id = GetHostIdByIp(ip)
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask("", entity_id, "嗅探分析", "start", "正在构建自组织网络")
		conn_target.commit()
		global root_parent_entity
		# host_id = GetHostIdByIp(r)
		root_parent_entity = GetEntityIdByHostId(parent_host_id)
		time.sleep(10)
		# 更新ENTITY_ENTITY_REL表
		for ip in init_agents:
			if ip == root_parent_ip:
				continue
			else:
				host_id = GetHostIdByIp(ip)
				entity_id = GetEntityIdByHostId(host_id)
				updateEty_Ety_Rel(root_parent_entity, entity_id)
				time.sleep(10)
		# 更新task
		for ip in init_agents:
			host_id = GetHostIdByIp(ip)
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask("", entity_id, "嗅探分析", "done", "正在构建自组织网络")
		time.sleep(10)
		#确定工具关系表的父id，存在全局变量中，以后备用
		global entity_parent_id
		entity_parent_id = getPidOfEntity()
		conn.commit()
		conn_target.commit()
	#correspond to 2
	#start of editing
	#本条指令在中心节点给个体节点发探测指令之前执行
	#将本轮执行探测的主机ip地址以数组的形式传入（中心节点应该知道这个信息）
	#根据主机ip取主机id
	#再根据主机id取工具id
	#输入参数 形同"['192.168.0.1','192.168.0.2']"的字符串
	#封装过后的还没有测
	def case_start_detect_live_host(self, ips):
		logwriter("info", "case_start_detect_live_host: " + ips)
		#准备开始探测，将任务插入task表，要先取执行本轮任务的主机的id以及执行探测的工具的id
		reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
		ips_t = re.findall(reg, ips)
		for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具id，按照目前的设计，一个主机仅对应一个工具id（第一轮初始的节点外，后面决策出来的节点也要注册相应的工具）
			entity_id = GetEntityIdByHostId(host_id)
			#插入新任务（或者更新任务，仿照模拟程序写在一个UpdateTask()里面）
			#判断重复不仅需要看工具id和主机id，还要看任务类型
			UpdateTask("", entity_id, "嗅探分析", "start", "正在探测存活主机")
			#the end of the for loop
		conn_target.commit()
		#任务表更新完成
	#end of editing
	
		#correspond to 3
	#开始文件传输，本条指令在中心节点给个体节点发送探测指令时触发
	#本指令根据个体节点ip地址更新task表
	def case_start_file_transmitting(self, ips):
		logwriter("info", "case_start_file_transmitting: " + ips)
		#开始文件传输
		#这里的缩进可能有问题
		reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
		ips_t = re.findall(reg, ips)
		# 其实这里只传一个ip过来
		for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具的id
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask("", entity_id, "嗅探分析", "done", "正在探测存活主机")
		conn_target.commit()
		time.sleep(10)
		for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具id，按照目前的设计，一个主机仅对应一个工具id（第一轮初始的节点外，后面决策出来的节点也要注册相应的工具，可以写在决策完成的指令中）
			entity_id = GetEntityIdByHostId(host_id)
			parent_entity_id = find_entity_pid(entity_id)
			if not parent_entity_id:
				# 值为False
				logwriter("info", "it is the root agent")
				# UpdateTask(host_id, entity_id, "文件传输", "start", "正在进行探测任务并回传探测结果")# root agent自己的host_id
				continue
			parent_host_id = GetHostIdByEntityId(parent_entity_id)
			#root_parent_id = GetHostIdByIp(root_parent_ip)
			# 这里更新要取它的父节点的id，表明它和它的父节点之间在做文件传输
			UpdateTask(parent_host_id, entity_id, "文件传输", "start", "正在进行探测任务并回传探测结果")
		conn_target.commit()

	#correspond to 4
	#结束文件传输，本条指令在中心节点收集到本轮所有的个体节点的回复时触发
	#本指令根据个体节点ip地址更新task表
	def case_end_file_transmitting(self, ips):
		logwriter("info", 'case_end_file_transmitting: ' + ips)
		reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
		ips_t = re.findall(reg, ips)
		root_parent_id = GetHostIdByIp(root_parent_ip)
		time.sleep(10)
		for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具id，按照目前的设计，一个主机仅对应一个工具id（第一轮初始的节点外，后面决策出来的节点也要注册相应的工具，可以写在决策完成的指令中）
			entity_id = GetEntityIdByHostId(host_id)
			parent_entity_id = find_entity_pid(entity_id)
			if not parent_entity_id:
				# 值为False
				logwriter("info", "it is the root agent")
				# UpdateTask(host_id, entity_id, "文件传输", "start", "正在进行探测任务并回传探测结果")# root agent自己的host_id
				continue
			parent_host_id = GetHostIdByEntityId(parent_entity_id)
			#root_parent_id = GetHostIdByIp(root_parent_ip)
			# 这里更新要取它的父节点的id，表明它和它的父节点之间在做文件传输
			UpdateTask(parent_host_id, entity_id, "文件传输", "done", "正在进行探测任务并回传探测结果")
			time.sleep(10)
			# #取主机id
			# host_id = GetHostIdByIp(ip)
			# #取该主机对应工具的id
			# entity_id = GetEntityIdByHostId(host_id)
			# entity_id_p = find_entity_pid(entity_id)
			# if not entity_id_p:
			# 	logwriter("info", "it is the root agent")
			# 	# parent_host_id = root_parent_id
			# 	# UpdateTask(parent_host_id, entity_id, "文件传输", "done", "正在进行探测任务并回传探测结果")
			# 	continue
			# parent_host_id = GetHostIdByEntityId(entity_id_p)
			# while parent_host_id != root_parent_id:
			# 	time.sleep(10)
			# 	UpdateTask(parent_host_id, entity_id, "文件传输", "done", "正在进行探测任务并回传探测结果")
			# 	# 回溯
			# 	entity_id = GetEntityIdByHostId(parent_host_id) #父节点的工具id
			# 	parent_entity_id = find_entity_pid(entity_id)#父节点的父节点的工具id
			# 	if not parent_entity_id:
			# 		# 值为False
			# 		logwriter("info", "it is the root agent")
			# 		# UpdateTask(root_parent_id, entity_id, "文件传输", "start", "正在进行探测任务并回传探测结果")
			# 		break
			# 	parent_host_id = GetHostIdByEntityId(parent_entity_id)#父节点的父节点的主机id
			# 	UpdateTask(parent_host_id, entity_id, "文件传输", "start", "正在进行探测任务并回传探测结果")
			# #退出while循环的时候(parent_host_id和root_parent_id相同的时候)，处理第二层子节点和根节点的连线，这个连线也是过2s再done
			# time.sleep(10)# 显示第二层节点和根节点之间的文件传输动画
			# UpdateTask(root_parent_id, entity_id, "文件传输", "done", "正在进行探测任务并回传探测结果")
		conn_target.commit()

	#本条指令在中心节点收到数据融合第一部分的反馈时执行（我们的数据的主机表内容已经基本填完）
	#由本条指令把主机信息从我们的数据库搬运到别人的数据库，此外还要填上路由器表以及网段路由关系表
	#最后更新TASK表
	#correspond to 5   one argument indicating the directory
	def case_end_detect_live_host(self, ips, rootdir):
		logwriter("info", 'case_end_detect_live_host: ' + ips)
		logwriter("info", 'got a file path: ' + rootdir)
		reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
		ips_t = re.findall(reg, ips)
		for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具id，按照目前的设计，一个主机仅对应一个工具id（第一轮初始的节点外，后面决策出来的节点也要注册相应的工具）
			entity_id = GetEntityIdByHostId(host_id)
			#插入新任务（或者更新任务，仿照模拟程序写在一个UpdateTask()里面）
			#判断重复不仅需要看工具id和主机id，还要看任务类型
			UpdateTask("", entity_id, "嗅探分析", "start", "正在分析嗅探结果并更新拓扑")
			#the end of the for loop
		conn_target.commit()
		#填充HOST表，在此之前要更新我们的数据库的HOST表的OS字段（消歧）
		#Update the filed 'HOS' of table HOST
		# if update_os() == -1:
		# 	logwriter('Failed to update HOS filed of table HOST')
		# else:
		# 	logwriter('Succeeded to update HOS filed of table HOST')
		#Update table HOST
		if update_host() == -1:
			logwriter("error", 'Failed to update HOST')
		else:
			logwriter("info", 'Succeeded to update HOST')
		if update_router_without_file() == -1:
			logwriter("error", 'Failed to update ROUTER from HOST')
		else:
			logwriter("info", 'Succeeded to update ROUTER from HOST')
		#填充SEGMENT表（暂时不在这里了，写在上面了）
		if update_site_segment_pairs() == -1:
			logwriter("error", 'Failed to update site_segment_pairs')
		else:
			logwriter("info", 'Succeeded to update site_segment_pairs')
		#填充SEGMENT_HOST_REL表
		if update_segment_host_rel() == -1:
			logwriter("error", 'Failed to update  SEGMENT_HOST_REL')
		else:
			logwriter("info", 'Succeeded to update SEGMENT_HOST_REL')
		time.sleep(10)

		#填充PROTOCOL表
		#待处理文件放在当前目录下以ip地址命名的所有文件夹中
		ip_dirs = get_result_list(rootdir)
		for path in ip_dirs:
			logwriter("info", '处理来自 ' + os.path.basename(path) + ' 的探测结果')
			file_full_path = path + "\\protocol.txt"
			if update_protocol(file_full_path) == -1:
				logwriter("error", 'Failed to update PROTOCOL')
			else:
				logwriter("info", 'Succeeded to update PROTOCOL')
			#填充ROUTER表
			file_full_path = path + "\\router.txt"
			if update_router_with_file(file_full_path) == -1:
				logwriter("error", 'Failed to update ROUTER from router.txt')
			else:
				logwriter("info", 'Succeeded to update ROUTER from router.txt')
			#更新SEGMENT表
			file_full_path = path + "\\segment.txt"
			if update_segment_from_file(file_full_path) == -1:
				logwriter("error", 'Failed to update SEGMENT from segment.txt')
			else:
				logwriter("info", 'Succeeded to update SEGMENT from segment.txt')
		#填充SEGMENT_HOST_REL表
		if update_segment_host_rel() == -1:
			logwriter("error", 'Failed to update  SEGMENT_HOST_REL')
		else:
			logwriter("info", 'Succeeded to update SEGMENT_HOST_REL')
		#填充SEGMENT_ROUTER_REL表
		if update_segment_router_rel() == -1:
			logwriter("error", 'Failed to update SEGMENT_ROUTER_REL')
		else:
			logwriter("info", 'Succeeded to update SEGMENT_ROUTER_REL')
		#更新TASK表
		for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具的id
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask("", entity_id, "嗅探分析", "done", "正在分析嗅探结果并更新拓扑")
			time.sleep(10)
		conn_target.commit()
		#指令传输？怎么说
		#这里是不是添加一个“指令传输，正在尝试获取路由表”？
		#指令传输的对象仅仅是这个agent所发现的路由器
		#指令传输由父节点的发给子节点，取子节点的host_id
		global root_parent_ip
		#如果是第一轮，那么ips_t中含有root_parent_ip
		host_ids = []
		parent_entity_ids = []
		if root_parent_ip in ips_t:
			for ip in ips_t:
				if ip == root_parent_ip:
					host_id = GetHostIdByIp(ip)
					entity_id = GetEntityIdByHostId(host_id)
					host_ids = GetChildEntityIdsByParentEntityId(entity_id)
					for h_id in host_ids:
						UpdateTask(h_id, entity_id, "指令传输", "start", "正在尝试获取路由表")
			time.sleep(10)
			SetAllInstructionDone()
			time.sleep(10)
		else:#不是第一轮
			for ip in ips_t:
				host_id = GetHostIdByIp(ip)
				entity_cid = GetEntityIdByHostId(host_id)
				entity_pid = GetParentEntityIdByChildEntityId(entity_cid)# remain to implement
				if entity_pid == -1: # handle error
					logwriter("error", "unpected error, lack of entity_entity_rel")
					continue
				if entity_pid not in parent_entity_ids:
					parent_entity_ids.append(entity_pid)
			for item in parent_entity_ids:
				host_ids = GetChildEntityIdsByParentEntityId(item)
				for h_id in host_ids:
					UpdateTask(h_id, item, "指令传输", "start", "正在尝试获取路由表")
			time.sleep(10)
			SetAllInstructionDone()
			time.sleep(10)

		# router_ids = []
		# for ip in ips_t:
		# 	host_id = GetHostIdByIp(ip)
		# 	entity_id = GetEntityIdByHostId(host_id)
		# 	router_ids = GetRouterDiscoveredByAgents(ip)
		# 	for r_id in router_ids:
		# 		UpdateTask(r_id, entity_id, "指令传输", "start", "正在尝试获取路由表")
		# time.sleep(10)
		# for ip in ips_t:
		# 	host_id = GetHostIdByIp(ip)
		# 	entity_id = GetEntityIdByHostId(host_id)
		# 	router_ids = GetRouterDiscoveredByAgents(ip)
		# 	for r_id in router_ids:
		# 		UpdateTask(r_id, entity_id, "指令传输", "done", "正在尝试获取路由表")
		# time.sleep(10)
		# 指令传输的目标id是什么id？是主机id？还是子agent的工具id？

		for ip in ips_t:
			host_id = GetHostIdByIp(ip)
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask("", entity_id, "嗅探分析", "start", "获取路由表")
		conn.commit()
		conn_target.commit()

	#本条指令在上条指令获得反馈之后执行
	#开始进行拓扑还原
	#correspond to 6
	def case_start_recover_topo(self, ips, rootdir):
		logwriter("info", 'case_start_recover_topo: ' + ips)
		#更新任务
		reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
		ips_t = re.findall(reg, ips)
		for ip in ips_t:
			time.sleep(10)
			host_id = GetHostIdByIp(ip)
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask("", entity_id, "嗅探分析", "done", "获取路由表")
		time.sleep(10)
		for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具的id
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask("", entity_id, "嗅探分析", "start", "正在还原网络拓扑")
		#填充ROUTER_ROUTER_REL表
		ip_dirs = get_result_list(rootdir)
		for path in ip_dirs:
			logwriter("info", '处理来自 ' + os.path.basename(path) + ' 的探测结果')
			file_full_path = path + "\\router_connection.txt"
			if update_router_router_rel(file_full_path) == -1:
				logwriter("error", 'Failed to update ROUTER_ROUTER_REL')
			else:
				logwriter("info",'Succeeded to update ROUTER_ROUTER_REL')
			try:
				shutil.rmtree(path)
			except Exception as err:
				#print(err)
				logwriter("error",err)
			
		conn.commit()
		conn_target.commit()

	#本条指令在上条指令获得反馈之后执行
	#correspond to 7
	def case_end_recover_topo(self, ips):
		logwriter("info", 'case_end_recover_topo: ' + ips)
		reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
		ips_t = re.findall(reg, ips)
		for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具的id
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask("", entity_id, "嗅探分析", "done", "正在还原网络拓扑")
			time.sleep(10)
			UpdateTask("", entity_id, "嗅探分析", "start", "准备决策中...")
		conn_target.commit()

	#本条指令在执行准备调用数据融合的第二个模块且收到上一个命令的反馈的时候执行
	#correspond to 8
	def case_start_agent_deciding(self, ips):
		logwriter("info", 'case_start_agent_deciding: ' + ips)
		reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
		ips_t = re.findall(reg, ips)
		time.sleep(10)
		for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具的id
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask("", entity_id, "嗅探分析", "done", "准备决策中...")
			time.sleep(10)
			UpdateTask("", entity_id, "嗅探分析", "start", "正在决策选取新的Agent")
		conn_target.commit()

	#本条指令在数据融合的第二个模块执行结束且收到上一个命令的反馈的时候执行
	#correspond to 9
	def case_end_agent_deciding(self, ips):
		logwriter("info", 'case_end_agent_deciding: ' + ips)
		reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
		ips_t = re.findall(reg, ips)
		time.sleep(10)
		for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具的id
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask("", entity_id, "嗅探分析", "done", "正在决策选取新的Agent")
			time.sleep(10)
			UpdateTask("", entity_id, "嗅探分析", "start", "准备向新的Agent注入...")
		conn_target.commit()

	#本条指令在上一条指令得到反馈之后执行
	#correspond to 10
	def case_start_deploy_agent(self, ips):
		logwriter("info", 'case_start_deploy_agent: ' + ips)#ips好像没用了
		reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
		ips_t = re.findall(reg, ips)
		# Update table HOST
		#if update_host() == -1:
		#	logwriter("error", 'Failed to update HOST')
		#else:
		#	logwriter("info", 'Succeeded to update HOST')
		time.sleep(10)
		for ip in ips_t:
			host_id = GetHostIdByIp(ip)
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask("", entity_id, "嗅探分析", "done", "准备向新的Agent注入...")
		time.sleep(10)
		with open("result.json","r") as load_f:
			load_dict = json.load(load_f)
			for item in load_dict['projects']:
				for task in item["tasks"]:
					if task["type"] == "activeDetection":
						ip_new = item["hosts"][0].split(':')[0]
						discoverer_ip = whoDiscoverMe(ip_new)
						logwriter("info", "ip_new: " + ip_new)
						#是哪个agent发现了我
						discoverer_id = GetHostIdByIp(discoverer_ip)
						discoverer_entity_id = GetEntityIdByHostId(discoverer_id)
						host_id = GetHostIdByIp(ip_new)
						UpdateTask(host_id, discoverer_entity_id, "渗透扩散", "start", "部署新的Agent")
						time.sleep(10)
						UpdateTask(host_id, discoverer_entity_id, "渗透扩散", "done", "部署新的Agent")
						time.sleep(10)
		conn.commit()
		conn_target.commit()

	#本条指令在上一条指令得到反馈之后执行，本条指令的反馈代表一轮探测+决策已经结束
	#要为新一轮的子节点做好准备工作，如注入工作表的更新，工具表的更新，工具关系表的更新。。。（仿照初始化的准备工作来做）
	#ips_old为本轮的旧节点，ips_new为刚刚选出的新节点 = =也可以从result.json中读取，可以修改
	#correspond to 11
	def case_end_deploy_agent(self, ips_old):
		logwriter("info", 'case_end_deploy_agent: ' + ips_old)
		reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
		ips_old_t = re.findall(reg, ips_old)
		#ips_new_t = re.findall(reg, ips_new)
		global entity_sequence
		with open("result.json","r") as load_f:
			load_dict = json.load(load_f)
			for item in load_dict['projects']:
				for task in item["tasks"]:#to avoid dulipcation
					if task["type"] == "activeDetection":
						ip_new = item["hosts"][0].split(':')[0]
						#修改工具表，为新选出的子节点增加工具
						host_id = GetHostIdByIp(ip_new)
						now_time_t = datetime.datetime.now()
						now_time = datetime.datetime.strftime(now_time_t,'%Y/%m/%d %H:%M:%S')
						try:
							cursor_target.execute("""
							declare t_count number(10);
							begin
								select count(*) into t_count from {username}.ENTITY where HOST_ID=:ho_id;
								if t_count=0 then
									insert into {username}.ENTITY(ID,UPDATED,PLATFORM,LOAD,DESCRIPTION,ONLINE_TIME,HOST_ID,NUM,STATUS) values(:id,'1',NULL,NULL,NULL,TO_TIMESTAMP(:time,'YYYY/MM/DD HH24:MI:SS'),:ho_id,:e_seq,'online');
								else
									update {username}.ENTITY set UPDATED=1,STATUS='online' where HOST_ID=:ho_id;
								end if;
							end;
							""".format(username=db_username_target),id=str(uuid.uuid4()),ho_id=host_id,time=now_time,e_seq=entity_sequence)
							entity_sequence += 1
						except:
							logwriter("error", "fail to update the ENTITY table")
							error_info = sys.exc_info()
							if len(error_info) > 1:
								logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
						conn_target.commit()
						#修改工具关系表
						discoverer_ip = whoDiscoverMe(ip_new)
						discoverer_id = GetHostIdByIp(discoverer_ip)
						discoverer_entity_id = GetEntityIdByHostId(discoverer_id)
						agent_entity_id = GetEntityIdByHostId(host_id)
						updateEty_Ety_Rel(discoverer_entity_id, agent_entity_id)
		conn_target.commit()

	# update all the tasks to 'done' state
	# correspond to 12
	def case_finish(self, msg):
		logwriter("info", "prepare to finish this task: " + msg)
		if update_router_from_host() == -1:
			logwriter('debug', 'Failed to update ROUTER from host')
		if update_segment_router_rel() == -1:
			logwriter('debug', 'Failed to update SEGMENT_ROUTER_REL')
		if update_router_router_rel_last() == -1:
			logwriter('debug', 'Failed to update ROUTER_ROUTER_REL from ROUTER_REL')
		try:
			cursor_target.execute("""
			update {username}.TASK set UPDATED=1,PERIOD=:period
			""".format(username = db_username_target), period = "done")
		except:
			logwriter("error", "fail to set all tasks to done state!")
			error_info = sys.exc_info()
			if len(error_info) > 1:
				logwriter("error", str(error_info[0]) + ' ' + str(error_info[1]))
		conn_target.commit()
		sys.exit(0) # exit this program iff all projects finished :)


	# a method that is called by default
	# it is similar to the default segment in switch case structure
	def case_default(self, msg):
		logwriter("info", "case_default: Got an invalid instruction " + msg)

class Th(threading.Thread):
	def __init__(self, connection,):
		threading.Thread.__init__(self)
		self.con = connection
		
	def run(self):
		cls = switch_case()
		while True:
			try:
				logwriter("info", 'thread is running')
				res = self.recv_data(1024)
				logwriter("info", res)
				#res为中心节点传来的命令，命令分两种形式
				#1.无参数命令 如"init_agents"，此时调用case_init_agents()
				#2.带参数命令 如"start_detect_live_host ['192.168.0.2','192.168.0.3','192.168.0.4']"，此时调用case_start_detect_live_host()，并将ip数组作为参数传入
				#后期先在这里处理res再决定调用哪个方法，把方法名和参数分离开来
				str = res.split()
				command = ""
				args = []
				if len(str) == 1:
					command = str[0]
					cls.case_to_function(command)("go!")
				elif len(str) > 1:
					command = str[0]
					for item in str:
						if item == command:
							continue
						args.append(item)
					if command == "start_detect_live_host" or command == "start_file_transmitting" or command == "end_file_transmitting" or command == "end_recover_topo" or command == "start_agent_deciding" or command == "end_agent_deciding" or command == "start_deploy_agent" or command == "end_deploy_agent":
						if len(args) != 1:
							logwriter("error", "Incorrect arguments, fail to execute this command")
						else:
							cls.case_to_function(command)(args[0])
					elif command == "end_detect_live_host" or command == "start_recover_topo":
						# logwriter("info", args)
						# logwriter("info", "the number of arguments " + str(len(args)))
						if len(args) != 2:
							logwriter("error", "Incorrect arguments, fail to execute this command, please confirm that there in no space in your file path")
						else:
							cls.case_to_function(command)(args[0], args[1])
					else:
						cls.case_to_function(res)("go!")
				# str = res.split()
				# for item in str:
				#     logwriter(item)
				self.send_data('ok')#每个指令执行完之后都要向中心节点反馈确认信息
			except TypeError as e:
				logwriter ("error", e)
		self.con.close()
	
	def test_logwriter(self):
		logwriter("info", 'this connection has been initialized, now attempt to start it')

	def recv_data(self, num):
		try:
			all_data = self.con.recv(num)
			if not len(all_data):
				return False
		except:
			return False
		else:
			code_len = all_data[1] & 127
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
				raw_str += chr(d ^ masks[i % 4])
				i += 1
			return raw_str
 
	# send data
	def send_data(self, data):
		if data:
			logwriter("info", "send data:" + data)
		else:
			return False
		token = struct.pack('B', 129)
		length = len(data)
		if length < 126:
			token += struct.pack("B", length)
		elif length <= (2 ** 16 - 1):
			token += struct.pack("!BH", 126, length)
		elif length <= (2 ** 64 - 1):
			token += struct.pack("!BQ", 127, length)
		else:
			logging.error("message is too long")
			return
		# struct为Python中处理二进制数的模块，二进制流为C，或网络流的形式。
		token += bytes(data, encoding='utf-8')
		self.con.send(token)
		return True

 
# handshake
def handshake(con):
	headers = {}
	shake = str(con.recv(1024))
	
	if not len(shake):
		return False
	
	header, data = shake.split(r'\r\n\r\n', 1)
	for line in header.split(r'\r\n')[1:]:
		key, val = line.split(': ', 1)
		headers[key] = val
	
	if 'Sec-WebSocket-Key' not in headers:
		logwriter("info", 'This socket is not websocket, client close.')
		con.close()
		return False
	
	sec_key = headers['Sec-WebSocket-Key']
	res_key = base64.b64encode(hashlib.sha1(bytes(sec_key + MAGIC_STRING,encoding='utf-8')).digest())
	key_str = str(res_key)[2:30]
	response = "HTTP/1.1 101 Switching Protocols\r\n" \
                        "Connection: Upgrade\r\n" \
                        "Upgrade:websocket\r\n" \
                       "Sec-WebSocket-Accept: {0}\r\n" \
                       "WebSocket-Protocol:chat\r\n\r\n".format(key_str)
	# str_handshake = HANDSHAKE_STRING.replace('{1}', str(res_key)).replace('{2}', HOST + ':' + str(PORT))
	logwriter("info", response)
	con.send(bytes(response,encoding='utf-8'))
	return True
 
def new_service():
	"""start a service socket and listen
	when coms a connection, start a new thread to handle it"""
	
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		sock.bind(('localhost', 3368))
		sock.listen(1000)
		#链接队列大小
		logwriter("critical", "bind 3368,ready to use")
	except:
		logwriter("critical", "Server is already running,quit")
		sys.exit()
 
	while True:
		connection, address = sock.accept()
		#返回元组（socket,add），accept调用时会进入waite状态
		print ("Got connection from ", address)
		if handshake(connection):
			logwriter ("info", "handshake success")
			try:
				t = Th(connection)
				t.test_logwriter()
				t.start()
				logwriter ("info", 'new thread for client ...')
			except:
					logwriter ("error", 'start new thread error')
					connection.close()
 
 
if __name__ == '__main__':
	new_service()
