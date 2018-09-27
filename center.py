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

os.environ['NLS_LANG'] = 'SIMPLIFIED CHINESE_CHINA.ZHS16GBK'

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

def get_result_list(root_dir):
    try:
        dirs = os.listdir(root_dir)
    except:
        error_info = sys.exc_info()
        if len(error_info) > 1:
            print(str(error_info[0]) + ' ' + str(error_info[1]))
        else:
            print('Unexpected error:can not get access to the root path of result')
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

"""start"""
def update_oracle(sql,var):    #update the database of ourselvesprint(conn.version())
	"""update contains:insert,update,delete"""
	try:
		cursor.execute(sql,var)
		conn.commit()
		if cursor.rowcount != 0:
			print('Oracle Update Successfully!')
	except cx_Oracle.OperationalError as err:
		print('Oracle Update OperationalError:',err)

def update_oracle_target(sql,var):  #update the FSR database
	"""update contains:insert,update,delete"""
	try:
		cursor_target.execute(sql,var)
		conn_target.commit()
		if cursor_target.rowcount != 0:
			print('Oracle Update Successfully!')
	except cx_Oracle.OperationalError as err:
		print('Oracle Update OperationalError:',err)

def update_os():
	"""Update Hos of the table Host, only hold one"""
	try:
		cursor.execute('select IP,HOS from HOST  where HISDEL=0')
		oslist = cursor.fetchall()
		print(cursor.rowcount)
		if cursor.rowcount==0:
			print('The table Host is empty!')
			return -1
	except cx_Oracle.OperationalError as err:
		print('Oracle Select OperationalError:',err)
		return -1
	for os in oslist:
		if os[1] == None:
			continue
		List = os_update.os_str_transfer(os[1]) #split all string to many little string
		osString = ''
		for L in List:
			# make sure the highest weight
			if (re.search('Windows Server 2008',L) and re.search('Windows Server 2008',osString)==None):
				osString = L
			elif (re.search('Windows 2000',L) and re.search('Windows Server 2008|Windows 2000',osString)==None):
				osString = L
			elif (re.search('Windows XP SP3',L) and re.search('Windows Server 2008|Windows 2000|Windows XP SP3',osString)==None):
				osString = L
			elif (re.search('Windows 7',L) and re.search('Windows Server 2008|Windows 2000|Windows XP SP3|Windows 7',osString)==None):
				osString = L
			elif (re.search('Windows 8',L) and re.search('Windows Server 2008|Windows 2000|Windows XP SP3|Windows 7|Windows 8',osString)==None):
				osString = L
			elif (re.search('Windows 10',L) and re.search('Windows Server 2008|Windows 2000|Windows XP SP3|Windows 7|Windows 8|Windows 10',osString)==None):
				osString = L
			elif (re.search('Linux',L) and re.search('Windows Server 2008|Windows 2000|Windows XP SP3|Windows 7|Windows 8|Windows 10|Linux',osString)==None):
				osString = L
			elif re.search('Windows Server 2008|Windows 2000|Windows XP SP3|Windows 7|Windows 8|Windows 10|Linux',osString)==None:
				osString = List[0]
		var = {'os':osString,'ip':os[0]}
		sql = 'update HOST set HOS=:os where IP=:ip' 
		update_oracle(sql,var)

def update_host():
	"""Transfer data from table host to HOST"""
	try:
		cursor.execute('select HOS,IP,HMAC,HMASK from HOST where HISDEL=0')
		hosts = cursor.fetchall()
		print(cursor.rowcount)
		if cursor.rowcount==0:
			print('The table Host is empty!')
			return -1
	except cx_Oracle.OperationalError as err:
		print('Oracle Select OperationalError:',err)
		return -1
	for host in hosts:
		print('IP:',host[1])
		os = host[0]    #Operating System
		ip = host[1]    #IP address
		mac = host[2]   #MAC address
		if host[3] == None:  #Mask is empty
			NET = 'Unknown'
		else:
			NET = host[3].split('/',1)[0]
		if os == None:
			os = 'Unknown'
		if mac == None:
			mac = 'Unknown'
		try:
			var = {'host_ip':host[1]}
			cursor_target.execute('select ID,OS,NET,MAC from HOST where IP=:host_ip',var)
			hosts = cursor_target.fetchall()
			#update the table HOST
			print("The rowcount",cursor_target.rowcount)
			if cursor_target.rowcount == 0:
				#print("The rowcount",cursor.rowcount)
				var = {'id':str(uuid.uuid1()),'os':os,'net':NET,'ip':ip,'mac':mac}
				sql = (
					"insert into HOST (ID,UPDATED,OS,NET,IP,PORT,BUSINESSTYPE,MAC,PROCESS,ATTACKED,KEY,ENTRY)"
					"values(:id,'1',:os,:net,:ip,34,'telnet',:mac,'chrome.exe','0','1','1')"
					) 
			else:
				print("The ip exits!")
				for host in hosts:
					if host[1] != 'Unknown' and os == 'Unknown':  #No lastest info,Use previous info 
						os = host[1]
					if host[2] != 'Unknown' and NET == 'Unknown':
						NET = host[2]
					if host[3] != 'Unknown' and mac == 'Unknown':
						mac = host[3] 
					var = {'id':'%s'%host[0],'os':os,'net':NET,'mac':mac}
				sql = "update HOST set OS=:os,NET=:NET,MAC=:mac where IP=:id"
			update_oracle_target(sql,var)
		except Exception as err:
			print('Oracle Error:',err)
			return -1	

def update_protocol(file_full_path):
	"""Prerequisites: update HOST table.Establish relationship between host and host"""
	items = resolve_file.protocol_resolve(file_full_path)
	if items == -1:
		print('The protocol file is empty')
		return -1
	try:
		for item in items:
			pro = item['pro']   # protocol
			traffic = item['traffic']
			if len(pro)>10:
				pro = pro[0:10]
			var = {'src':item['src']}
			cursor_target.execute('select ID from HOST where IP=:src',var)  #Judge the src address whether it exists
			host1_id = cursor_target.fetchone()
			if cursor_target.rowcount == 0:
				continue
			var = {'dst':item['dst']}
			cursor_target.execute('select ID from HOST where IP=:dst',var)   #Judge the dst address whether it exists
			host2_id = cursor_target.fetchone()
			if cursor_target.rowcount == 0:
				continue
			var = {'host1_id':host1_id[0],'host2_id':host2_id[0]}
			cursor_target.execute('select * from PROTOCOL where HOST1_ID=:host1_id and HOST2_ID=:host2_id',var)  #Judge the ip pair whether it exists
			protocol = cursor_target.fetchone()
			if cursor_target.rowcount == 1:    #the ip pairs has existed ,update the PROTOCOL table
				if protocol[2]!='Unknown' and pro == 'Unknown':
					pro = protocol[2]
				if protocol[5] != 0 and traffic == 0:
					traffic = int(protocol[5])
				var = {'id':protocol[0],'type':pro,'traffic':traffic}
				sql = 'update PROTOCOL set TYPE=:type,TRAFFIC=:traffic where ID=:id'
			else:
				var = {'id':str(uuid.uuid1()),'type':pro,'host1_id':host1_id[0],'host2_id':host2_id[0],'traffic':traffic}
				sql = "insert into PROTOCOL (ID,UPDATED,TYPE,HOST1_ID,HOST2_ID,TRAFFIC)values(:id,'1',:type,:host1_id,:host2_id,:traffic)"
			update_oracle_target(sql,var)
	except Exception as err:
		print(err)

def update_router_ips(file_full_path):#仅操作我们的数据库
	"""conserve router interface info to table ROUTER and ROUTER_INTERFACE"""
	items = resolve_file.router_resolve(file_full_path)
	if items == -1:
		return -1
	for item in items:
		for i in item['router']:    #Traverse router data ,if found router unique ip,conserve other data;if not conserve unique ip and other ips
			Router = ''
			try:
				var = {'ip':i}
				cursor.execute('select ROUTER_ID from ROUTER_INTERFACE where ip=:ip',var)
				Router_id = cursor.fetchone()
				if cursor.rowcount == 0:
					continue
				else:
					Router = Router_id[0]
					break;
			except Exception as err:
				print('Oracle Operating error:',err)
				return -1
		if Router != '':   #had get unique ip id
			for i in item['router']:
				try:
					var = {'ip':i}
					cursor.execute('select ROUTER_ID from ROUTER_INTERFACE where ip=:ip',var)
					cursor.fetchone()
					if cursor.rowcount == 0:
						var = {'id':str(uuid.uuid1()),'router_id':Router,'ip':i}
						sql = 'insert into ROUTER_INTERFACE (ID,ROUTER_ID,IP)values(:id,:router_id,:ip)'
						update_oracle(sql,var)
				except Exception as err:
					print('Oracle Operating error:',err)
					return -1
		else:           #Not got unique ip id ,need to insert default unique ip(usually the first one)
			for i in item['router']:
				var = {'ip':i}
				cursor.execute('select * from ROUTER_INTERFACE where ip=:ip',var)
				cursor.fetchone()
				if cursor.rowcount == 0:
					if i == item['router'][0]: #first ip is router unique ip
						var = {'id':str(uuid.uuid1()),'ip':i}
						sql = 'insert into ROUTER (ID,IP)values(:id,:ip)'
						update_oracle(sql,var)
					var = {'ip':item['router'][0]}
					cursor.execute('select ID from ROUTER where IP=:ip',var)
					router_id = cursor.fetchone()
					var = {'id':str(uuid.uuid1()),'router_id':router_id[0],'ip':i}
					sql = 'insert into ROUTER_INTERFACE (ID,ROUTER_ID,IP)values(:id,:router_id,:ip)'
					update_oracle(sql,var)

def update_router_ip(ip):#仅操作我们的数据库
	"""Insert data(not in router.txt) to ROUTER and ROUTER_INTERFACE"""
	try:
		var = {'id':str(uuid.uuid1()),'IP':ip}
		sql = 'insert into ROUTER (ID,IP)values(:id,:IP)'
		update_oracle(sql,var)
		var = {'IP':ip}
		cursor.execute('select ID from ROUTER where IP=:IP',var)
		router_id = cursor.fetchone()
		var = {'ID':str(uuid.uuid1()),'ROUTER_ID':router_id[0],'IP':ip}
		sql = 'insert into ROUTER_INTERFACE (ID,ROUTER_ID,IP)values(:ID,:ROUTER_ID,:IP)'
		update_oracle(sql,var)
		return router_id[0]
	except Exception as err:
		print('Oracle Operating error:',err)
		return -1
	
def update_router(file_full_path):
	"""Transfer data to ROUTER ,from HOST or router.txt"""
	status = update_router_ips(file_full_path)
	if status == -1:
		print('Failed to update routers')
	#data from HOST,find device type is "router"
	try:
		cursor.execute('select IP,HSERVICENUM,HOS,HOPENPORTNUM,HDEVICE,HMAC,HMASK from HOST where HISDEL=0')
		hosts = cursor.fetchall()
	except Exception as err:
		print('Oracle Operating error',err)
		return -1
	if cursor.rowcount == 0:
		print('Our HOST table is empty')
		return
	else:
		for host in hosts:   #Traserve HOST table
			if host[4] == 'router':
				ip = host[0]
				servicenum = str(host[1])
				os = host[2]
				portnum = host[3]
				mac = host[5]
				net = host[6].split('/')[0]
				if os == None:
					os = 'Unknown'
				if mac == None:
					mac = 'Unknown'
				if net == None:
					net = 'Unknown'
				try:
					var = {'ip':ip}
					cursor.execute('select ROUTER_ID from ROUTER_INTERFACE where IP=:ip',var) #Judge the router whether was recorded
					r = cursor.fetchone()
					if cursor.rowcount == 0:
						if update_router_ip(ip) == -1:    #Record the ip and get unique ip id
							print('Failed to update router ip')
						else:
							Router = update_router_ip(ip) 
					else:
						Router = r[0]  #get router unique id
					var = {'id':Router}
					cursor.execute('select IP from ROUTER where ID=:id',var)  #Get the unique ip
					IP = cursor.fetchone()
					var = {'ip':IP[0]}
					cursor_target.execute('select ID,OS,NET,MAC from ROUTER where IP=:ip',var)   #Judge the router whether exists
					router = cursor_target.fetchone()
				except Exception as err:
					print('Oracle Operating error',err)
					return -1
				if cursor_target.rowcount == 1:
					if router[1] != 'Unknown' and os == 'Unknown':  #No lastest info,Use previous info 
						os = router[1]
					if router[2] != 'Unknown' and net == 'Unknown':
						net = router[2]
					if router[3] != 'Unknown' and mac == 'Unknown':
						mac = router[3] 
					var = {'id':router[0],'os':os,'net':net,'port':portnum,'business':servicenum,'mac':mac}
					sql = 'update ROUTER set OS=:os,NET=:net,PORT=:port,BUSINESSTYPE=:business,MAC=:mac where ID=:id'
				else:
					var = {'id':str(uuid.uuid1()),'os':os,'ip':IP[0],'net':net,'port':portnum,'business':servicenum,'mac':mac}
					sql = (
						"insert into ROUTER (ID,UPDATED,OS,IP,NET,PORT,BUSINESSTYPE,MAC,PROCESS,ATTACKED,KEY)"
						"values(:id,'1',:os,:ip,:net,:port,:business,:mac,'chrome.exe','0','0')"
						)
				update_oracle_target(sql,var)

def update_mask(mask_int):
	"""Transfer number to mask"""
	bin_arr = ['0' for i in range(32)]
	for i in range(mask_int):
		bin_arr[i] = '1'
	tmpmask = [''.join(bin_arr[i * 8:i * 8 + 8]) for i in range(4)]
	tmpmask = [str(int(tmpstr,2)) for tmpstr in tmpmask]
	return '.'.join(tmpmask)

def update_segment(file_full_path):
	"""Transfer data to SEGMENT ,from HOST or segment.txt"""
	items = resolve_file.segment_resolve(file_full_path)
	#data from segment.txt
	if items != -1:
		for item in items:
			try:
				var = {'net':item['net'],'mask':item['mask']}
				cursor_target.execute('select * from SEGMENT where NET=:net and MASK=:mask',var)
				cursor_target.fetchone()
				if cursor_target.rowcount == 1:
					continue
				else:
					print('insert',item['net'])
					var = {'id':str(uuid.uuid1()),'net':item['net'],'mask':item['mask']}
					sql = 'insert into SEGMENT (ID,UPDATED,NET,MASK)values(:id,1,:net,:mask)'
					update_oracle_target(sql,var)
			except Exception as err:
				print('Oracle Operating error:',err)
				return -1
			
	#data from HOST
	try:
		cursor.execute('select HMASK from HOST where HISDEL=0')
		nets = cursor.fetchall()
		print('select',cursor.rowcount)
		if cursor.rowcount == 0:
			return -1
	except Exception as err:
		print('Oracle Operating error:',err)
	for net in nets:
		if net[0] == None:
			continue
		NET = net[0].split('/')[0]
		prefix = net[0].split('/')[1]
		MASK = update_mask(int(prefix))
		try:
			var = {'Net':NET,'Mask':MASK}
			cursor_target.execute('select * from SEGMENT where NET=:Net and MASK=:Mask',var)  #Judging the network number whether exists
			cursor_target.fetchone()
			if cursor_target.rowcount ==1:
				continue
			else:
				var = {'id':str(uuid.uuid1()),'Net':NET,'Mask':MASK}
				sql = 'insert into SEGMENT (ID,UPDATED,NET,MASK)values(:id,1,:Net,:Mask)'
				update_oracle_target(sql,var)
		except Exception as err:
			print('Oracle Operating error:',err)
			return -1
		
def update_segment_router_rel():
	"""estiblish the table SEGMENT and ROUTER"""
	try:
		#Get ID,NET from table ROUTER
		cursor_target.execute('select ID,NET,IP from ROUTER')
		routers = cursor_target.fetchall()
		#print('The table ROUTER rows is %d'%cursor_target.rowcount)
		if cursor_target.rowcount == 0:
			print('The table ROUTER is empty!')
			return -1
		#Get ID,NET form table SEGMENT
		cursor_target.execute('select ID,NET,MASK from SEGMENT')
		segments = cursor_target.fetchall()
		#print('The table SEGMENT rows is %d'%cursor_target.rowcount)
		if cursor_target.rowcount == 0:
			print('The table SEGMENT is empty!')
			return -1
	except Exception as err:
		print('Oracle Operating error:',err)
		return -1
	#update the table SEGMENT_ROUTER_REL
	for router in routers:
		for segment in segments:
			router_net = router[1]
			if router[1] == 'Unknown' or router[1] == None:
				router_net = str(IP(router[2]).make_net(segment[2]))
				router_net = router_net.split('/',1)[0]
			if router_net == segment[1]:   #the network number is equal
				#print('Network Number:%s'%router_net)
				#print('IP:%s'%router[2])
				#Judge the segment-router pair exist or not
				var = {'sid':segment[0],'rid':router[0]}
				try:
					cursor_target.execute('select * from SEGMENT_ROUTER_REL where SEGMENT_ID=:sid and ROUTER_ID=:rid',var)
					cursor_target.fetchone()
					if (cursor_target.rowcount) == 0:
						var = {'id':str(uuid.uuid1()),'sid':segment[0],'rid':router[0],'traffic':random.randint(1,5000)}
						sql = 'insert into SEGMENT_ROUTER_REL (ID,UPDATED,SEGMENT_ID,ROUTER_ID,TRAFFIC)values(:id,1,:sid,:rid,:traffic)'
						update_oracle_target(sql,var)
						break
				except Exception as err:
					print('Oracle Operating error:',err)
					return -1

def update_segment_host_rel():
	"""connect the table segment and host"""
	try:
		#Get ip address from table HOST
		cursor_target.execute('select ID,NET,IP from HOST')
		host_ips = cursor_target.fetchall()
		print('The table HOST rows is %d'%cursor_target.rowcount)
		if cursor_target.rowcount == 0:
			print('The table HOST is empty!')
			return -1
		#Get NET,MASK form table SEGMENT
		cursor_target.execute('select ID,NET,MASK from SEGMENT')
		segments = cursor_target.fetchall()
		print('The table SEGMENT rows is %d'%cursor_target.rowcount)
		if cursor_target.rowcount == 0:
			print('The table SEGMENT is empty!')
			return -1
	except Exception as err:
		print('Oracle Operating error:',err)
		return -1
	#update the table SEGMENT_HOST_REL
	id = 0
	for ip in host_ips:
		for segment in segments:
			ip_net = ip[1]
			if ip[1] == 'Unknown' or ip[1] == None:   #network number not known
				ip_net = str(IP(ip[2]).make_net(segment[2]))
				ip_net = ip_net.split('/',1)[0]
			if ip_net == segment[1]:   #the network number is equal
				print('Network Number:%s'%ip_net)
				print('IP:%s'%ip[2])
				#Judge the segment-host pair exist or not
				var = {'sid':segment[0],'hid':ip[0]}
				try:
					cursor_target.execute('select * from SEGMENT_HOST_REL where SEGMENT_ID=:sid and HOST_ID=:hid',var)
					#cursor.execute('select * from SEGMENT_HOST_REL where SEGMENT_ID='+segment[0]+' and HOST_ID='+ip[0]+'')
					cursor_target.fetchone()
					if (cursor_target.rowcount) == 0:
						var = {'id':str(uuid.uuid1()),'sid':segment[0],'hid':ip[0],'traffic':random.randint(1,2000)}
						sql = 'insert into SEGMENT_HOST_REL (ID,UPDATED,SEGMENT_ID,HOST_ID,TRAFFIC)values(:id,1,:sid,:hid,:traffic)'
						update_oracle_target(sql,var)
						break
				except Exception as err:
					print('Oracle Operating error:',err)
					return -1

def update_router_router_rel(file_full_path):
	"""Transfer data from router connection.txt to ROUTER_ROUTER_REL"""
	items = resolve_file.router_connection_resolve(file_full_path)
	print(items)
	if items == -1:
		return -1
	for item in items:
		try:
			var = {'router1':item['router1']}
			cursor_target.execute('select ID from ROUTER where ip=:router1',var)
			router1_id = cursor_target.fetchone()
			if cursor_target.rowcount == 0:  #No this router ip
				update_router_ip(item['router1'])
				var = {'id':str(uuid.uuid1()),'ip':item['router1']}
				sql = (
					"insert into ROUTER (ID,UPDATED,OS,IP,NET,PORT,BUSINESSTYPE,MAC,PROCESS,ATTACKED,KEY)"
					"values(:id,'1','Unknown',:ip,'Unknown',0,'0','Unknown','System.exe','0','0')"
					)
				update_oracle_target(sql,var)
				var = {'router1':item['router1']}
				cursor_target.execute('select ID from ROUTER where ip=:router1',var)
				router1_id = cursor_target.fetchone()  #got router1 id
			var = {'router2':item['router2']}
			cursor_target.execute('select ID from ROUTER where ip=:router2',var)
			router2_id = cursor_target.fetchone()
			if cursor_target.rowcount == 0:    #No this router ip
				update_router_ip(item['router2'])
				var = {'id':str(uuid.uuid1()),'ip':item['router2']}
				sql = (
					"insert into ROUTER (ID,UPDATED,OS,IP,NET,PORT,BUSINESSTYPE,MAC,PROCESS,ATTACKED,KEY)"
					"values(:id,'1','Unknown',:ip,'Unknown',0,'0','Unknown','System.exe','0','0')"
					)
				update_oracle_target(sql,var)
				var = {'router2':item['router2']}
				cursor_target.execute('select ID from ROUTER where ip=:router2',var)
				router2_id = cursor_target.fetchone()
			var = {'ROUTER1_ID':router1_id[0],'ROUTER2_ID':router2_id[0]}  #Judge the router connection whether exists
			cursor_target.execute('select * from ROUTER_ROUTER_REL where ROUTER1_ID=:ROUTER1_ID and ROUTER2_ID=:ROUTER2_ID',var)
			cursor_target.fetchone()
			if cursor_target.rowcount == 1:
				print('The router connection relationship existed')
				continue
			var = {'ID':str(uuid.uuid1()),'ROUTER1_ID':router1_id[0],'ROUTER2_ID':router2_id[0],'TRAFFIC':random.randint(1,5000)}
			sql = (
				"insert into ROUTER_ROUTER_REL (ID,UPDATED,ROUTER1_ID,ROUTER2_ID,TRAFFIC)"
				"values(:ID,'1',:ROUTER1_ID,:ROUTER2_ID,:TRAFFIC)"
				)
			update_oracle_target(sql,var)
		except Exception as err:
			print('Oracle Operating error',err)
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
		location = country  +' ' + city
		print('location:',location)
		return location
	except Exception as e:
		print(e)
		return 'Unregistered'

global number
number = 0
def update_site(number):
	"""Updata table SITE based on table SEGMENT"""
	try:
		cursor_target.execute('select NET from SEGMENT')
		nets = cursor_target.fetchall()
	except Exception as err:
		print(err)
		return -1
	if cursor_target.rowcount <= 0:
		print('The table SEGMENT is empty')
		return -1
	for net in nets:
		try:
			var = {'net':net[0]}
			cursor_target.execute('select * from SITE where NET=:net',var)
			cursor_target.fetchone()
			if cursor_target.rowcount > 0:
				continue
		except Exception as err:
			print(err)
			return -1
		location = regGeoStr(net[0])
		if location == None:
			location = 'Unknown'
		number = number + 1
		var = {'id':str(uuid.uuid1()),'name':'site' + str(number),'detail':'This is site-' + str(number),'address':location,'net':net[0]}
		sql = (
			"insert into SITE (ID,UPDATED,STATUS,NAME,DETAIL,ADDRESS,NET,TYPE)"
			"values(:id,'1','online',:name,:detail,:address,:net,2)"
  			)
		update_oracle_target(sql,var)

def update_site_segment_rel():
	try:
		cursor_target.execute('select ID,NET from SITE')
		sites = cursor_target.fetchall()
		if cursor_target.rowcount <= 0:   #table SITE is empty
			return -1
		cursor_target.execute('select ID,NET from SEGMENT')
		segments = cursor_target.fetchall()
		if cursor_target.rowcount <= 0:   #table SEGMENT is empty
			return -1
		for segment in segments:
			for site in sites:
				if segment[1] == site[1]:
					var = {'id':str(uuid.uuid1()),'site_id':site[0],'segment_id':segment[0],'traffic':random.randint(1,5000)}
					sql = (
						"insert into SITE_SEGMENT_REL (ID,UPDATED,SITE_ID,SEGMENT_ID,TRAFFIC)"
						"values(:id,'1',:site_id,:segment_id,:traffic)"
						)
					update_oracle_target(sql,var)
	except Exception as err:
		print(err)
		return -1
		
"""end"""
		
def GetHostIdByIp(ip):
	host_id = ""
	try:
		cursor_target.execute("""
		select ID from {username}.HOST where IP=:tip
		""".format(username=db_username_target),tip=ip)
		result = cursor_target.fetchall()
		if len(result) > 1:
			print("Error:more than one record in HOST table noticing the same ip")
		host_id = result[0][0]
	except:
		print("Error:fail to fetch id from the HOST table")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			print(str(error_info[0]) + ' ' + str(error_info[1]))
	return host_id

def GetEntityIdByHostId(host_id):
	entity_id = ""
	try:
		cursor_target.execute("""
		select ID from {username}.ENTITY where HOST_ID=:ho_id
		""".format(username=db_username_target),ho_id=host_id)
		result = cursor_target.fetchall()
		if len(result) > 1:
			print("Error:more than one record in ENTITY table referencing to the same host")
		entity_id = result[0][0]
	except:
		print("Error:fail to fetch id from the ENTITY table")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			print(str(error_info[0]) + ' ' + str(error_info[1]))
	return entity_id

#承担了更新及插入两种操作
def UpdateTask(host_id, entity_id, Type, period, process):
	#更新任务表
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
		""".format(username=db_username_target),id=(str(uuid.uuid1())),e_id=entity_id,ho_id=host_id,tasktype=Type,taskperiod=period,taskprocess=process)
	except:
		print("Error:fail to insert new task into the TASK table")
		error_info = sys.exc_info()
		if len(error_info) > 1:
			print(str(error_info[0]) + ' ' + str(error_info[1]))


# run different functions based on different signals
class switch_case(object):
    def case_to_function(self, case):
        fun_name = "case_" + str(case)
        print("ready to call function " + fun_name + "()")
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
						#in_id_t = str(uuid.uuid1())#暂存，用于后面更新注入
						host_id = result[0][0]
						cursor_target.execute("""
						declare t_count number(10);
						begin
							select count(*) into t_count from {username}.INJECTION where TARGET_ID=:h_id;
							if t_count=0 then
								insert into {username}.INJECTION(ID,UPDATED,TARGET_ID,PERIOD) values(:in_id,'1',:h_id,'start');
							else
								update {username}.INJECTION set UPDATED=1,PERIOD='start';
							end if;
						end;
						""".format(username=db_username_target),in_id=str(uuid.uuid1()),h_id=host_id)
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
					#工具表中的编号何解？
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
					#再次更新注入表，先取出本轮的注入id号
					try:
						cursor_target.execute("""
						select ID from {username}.INJECTION where TARGET_ID=:ho_id
						""".format(username=db_username_target),ho_id=host_id)
						result = cursor_target.fetchall()
						if len(result) > 1:
							print("Error:more than one record noticing the same host in INJECTION table")
						injection_id = result[0][0]
					except:
						print("Error:fail to fetch ID from the INJECTION table")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					try:
						cursor_target.execute("""
						update {username}.INJECTION set UPDATED=1,PERIOD='done' where TARGET_ID=:ho_id and ID=:in_id
						""".format(username=db_username_target),ho_id=host_id,in_id=injection_id)
					except:
						print("Error:fail to update the INJECTION table")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
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
        print("case_start_detect_live_host: " + ips)
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
			UpdateTask(host_id, entity_id, "嗅探分析", "start", "正在探测存活主机")
			#the end of the for loop
        conn_target.commit()
		#任务表更新完成
	#end of editing
	
    #correspond to 3
	#开始文件传输，本条指令在中心节点给个体节点发送探测指令时触发
	#本指令根据个体节点ip地址更新task表
    def case_start_file_transmitting(self, ips):
        print("case_start_file_transmitting: " + ips)
		#开始文件传输
		#这里的缩进可能有问题
        reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
        ips_t = re.findall(reg, ips)
        for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具id，按照目前的设计，一个主机仅对应一个工具id（第一轮初始的节点外，后面决策出来的节点也要注册相应的工具，可以写在决策完成的指令中）
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask(host_id, entity_id, "文件传输", "start", "正在回传探测结果")
        conn_target.commit()

    #correspond to 4
	#结束文件传输，本条指令在中心节点收集到本轮所有的个体节点的回复时触发
	#本指令根据个体节点ip地址更新task表
    def case_end_file_transmitting(self, ips):
        print('case_end_file_transmitting: ' + ips)
        reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
        ips_t = re.findall(reg, ips)
        for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具的id
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask(host_id, entity_id, "文件传输", "done", "正在回传探测结果")
        conn_target.commit()

	#本条指令在中心节点收到数据融合第一部分的反馈时执行（我们的数据的主机表内容已经基本填完）
	#由本条指令把主机信息从我们的数据库搬运到别人的数据库，此外还要填上路由器表以及网段路由关系表
	#最后更新TASK表
    #correspond to 5   one argument indicating the directory
    def case_end_detect_live_host(self, ips, rootdir):
        print('case_end_detect_live_host: ' + ips)
        print('got a file path: ' + rootdir)
		#填充HOST表，在此之前要更新我们的数据库的HOST表的OS字段（消歧）
		#Update the filed 'HOS' of table HOST
        if update_os() == -1:
			print('Failed to update HOS filed of table HOST')
        else:
			print('Successed to update HOS filed of table HOST')
		#Update table HOST
        if update_host() == -1:
			print('Failed to update HOST')
        else:
			print('Succeeded to update HOST')
		#填充PROTOCOL表
		#待处理文件放在当前目录下以ip地址命名的所有文件夹中
        ip_dirs = get_result_list(rootdir)
        for path in ip_dirs:
			print('处理来自 ' + os.path.basename(path) + ' 的探测结果')
			file_full_path = path + "/protocol.txt"
			if update_protocol(file_full_path) == -1:
				print('Failed to update PROTOCOL')
			else:
				print('Succeeded to update PROTOCOL')
			#填充ROUTER表
			file_full_path = path + "/router.txt"
			if update_router(file_full_path) == -1:
				print('Failed to update ROUTER')
			else:
				print('Succeeded to update ROUTER')
			#更新SEGMENT表
			file_full_path = path + "/segment.txt"
			if update_segment(file_full_path) == -1:
				print('Failed to update SEGMENT')
			else:
				print('Succeeded to update SEGMENT')
		#填充SEGMENT_ROUTER_REL表
        if update_segment_router_rel() == -1:
			print('Failed to update SEGMENT_ROUTER_REL')
        else:
			print('Succeeded to update SEGMENT_ROUTER_REL')
		#更新TASK表
        reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
        ips_t = re.findall(reg, ips)
        for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具的id
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask(host_id, entity_id, "嗅探分析", "done", "正在探测存活主机")
        conn.commit()
        conn_target.commit()

	#本条指令在上条指令获得反馈之后执行
	#开始进行拓扑还原
    #correspond to 6
    def case_start_recover_topo(self, ips, rootdir):
        print('case_start_recover_topo: ' + ips)
		#更新任务
        reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
        ips_t = re.findall(reg, ips)
        for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具的id
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask(host_id, entity_id, "嗅探分析", "start", "正在还原网络拓扑")
        #填充SEGMENT表（暂时不在这里了，写在上面了）
		#填充SEGMENT_HOST_REL表
        if update_segment_host_rel() == -1:
			print('Failed to update  SEGMENT_HOST_REL')
        else:
			print('Succeeded to update SEGMENT_HOST_REL')
		#填充ROUTER_ROUTER_REL表
        ip_dirs = get_result_list(rootdir)
        for path in ip_dirs:
			print('处理来自 ' + os.path.basename(path) + ' 的探测结果')
			file_full_path = path + "/router_connection.txt"
			if update_router_router_rel(file_full_path) == -1:
				print('Failed to update ROUTER_ROUTER_REL')
			else:
				print('Succeeded to update ROUTER_ROUTER_REL')
		#填充SITE表
        if update_site(int(number))== -1:
			print('Failed to update SITE')
        else:
			print('Successed to update SITE')
		#填充SITE_SEGMENT_REL表
        if update_site_segment_rel()== -1:
			print('Failed to update SITE_SEGMENT_REL')
        else:
			print('Succeeded to update SITE_SEGMENT_REL')
        conn.commit()
        conn_target.commit()

	#本条指令在上条指令获得反馈之后执行
    #correspond to 7
    def case_end_recover_topo(self, ips):
        print('case_end_recover_topo: ' + ips)
        reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
        ips_t = re.findall(reg, ips)
        for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具的id
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask(host_id, entity_id, "嗅探分析", "done", "正在还原网络拓扑")
        conn_target.commit()

	#本条指令在执行准备调用数据融合的第二个模块且收到上一个命令的反馈的时候执行
    #correspond to 8
    def case_start_agent_deciding(self, ips):
        print('case_start_agent_deciding: ' + ips)
        reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
        ips_t = re.findall(reg, ips)
        for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具的id
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask(host_id, entity_id, "嗅探分析", "start", "正在决策选取新的Agent")
        conn_target.commit()

	#本条指令在数据融合的第二个模块执行结束且收到上一个命令的反馈的时候执行
    #correspond to 9
    def case_end_agent_deciding(self, ips):
        print('case_end_agent_deciding: ' + ips)
        reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
        ips_t = re.findall(reg, ips)
        for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具的id
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask(host_id, entity_id, "嗅探分析", "done", "正在决策选取新的Agent")
        conn_target.commit()

	#本条指令在上一条指令得到反馈之后执行
    #correspond to 10
    def case_start_deploy_agent(self, ips):
        print('case_start_deploy_agent: ' + ips)
        reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
        ips_t = re.findall(reg, ips)
        for ip in ips_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具的id
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask(host_id, entity_id, "渗透扩散", "start", "正在决策选取新的Agent")
        conn_target.commit()

	#本条指令在上一条指令得到反馈之后执行，本条指令的反馈代表一轮探测+决策已经结束
	#要为新一轮的子节点做好准备工作，如注入工作表的更新，工具表的更新，工具关系表的更新。。。（仿照初始化的准备工作来做）
	#ips_old为本轮的旧节点，ips_new为刚刚选出的新节点 = =也可以从result.json中读取，可以修改
    #correspond to 11
    def case_end_deploy_agent(self, ips_old):
        print('case_end_deploy_agent: ' + ips_old)
        reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
        ips_old_t = re.findall(reg, ips_old)
        #ips_new_t = re.findall(reg, ips_new)
        with open("result.json","r") as load_f:
			load_dict = json.load(load_f)
			for item in load_dict['tasks']:
				if item['type'] == "activeDetection":#to avoid dulipcation
					s_index = item['hosts'][0].find(':')
					ip_new = item['hosts'][0][0:s_index]
					#修改注入表（可能不需要，不需要的话就删掉）
					try:
						cursor_target.execute("""
						select ID from {username}.HOST where IP=:ip
						""".format(username=db_username_target),ip=ip_new)
						result = cursor_target.fetchall()
						host_id = result[0][0]
						if len(result) > 1:
							print("Error: more than one record noticing the same ip")
						elif len(result) == 0:
							print("Error: the new agent ip hasn't been inserted into the HOST table")
					except:
						print("Error:fail to fetch ID from HOST")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					try:
						cursor_target.execute("""
						declare t_count number(10);
						begin
							select count(*) into t_count from {username}.INJECTION where TARGET_ID=:h_id;
							if t_count=0 then
								insert into {username}.INJECTION(ID,UPDATED,TARGET_ID,PERIOD) values(:in_id,'1',:h_id,'start');
							else
								update {username}.INJECTION set UPDATED=1,PERIOD='start';
							end if;
						end;
						""".format(username=db_username_target),in_id=str(uuid.uuid1()),h_id=host_id)
					except:
						print("Error:fail to update the INJECTION table")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					#修改工具表
					
					#修改工具关系表
					
					#再次修改注入表（可能不需要，不需要的话就删掉）
					try:
						cursor_target.execute("""
						select ID from {username}.INJECTION where TARGET_ID=:ho_id
						""".format(username=db_username_target),ho_id=host_id)
						result = cursor_target.fetchall()
						if len(result) > 1:
							print("Error:more than one record noticing the same host in INJECTION table")
						injection_id = result[0][0]
					except:
						print("Error:fail to fetch ID from the INJECTION table")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
					try:
						cursor_target.execute("""
						update {username}.INJECTION set UPDATED=1,PERIOD='done' where TARGET_ID=:ho_id and ID=:in_id
						""".format(username=db_username_target),ho_id=host_id,in_id=injection_id)
					except:
						print("Error:fail to update the INJECTION table")
						error_info = sys.exc_info()
						if len(error_info) > 1:
							print(str(error_info[0]) + ' ' + str(error_info[1]))
		#更新任务表
        for ip in ips_old_t:
			#取主机id
			host_id = GetHostIdByIp(ip)
			#取该主机对应工具的id
			entity_id = GetEntityIdByHostId(host_id)
			UpdateTask(host_id, entity_id, "渗透扩散", "done", "正在决策选取新的Agent")
        conn_target.commit()

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
							print("Error:Incorrect arguments, fail to execute this command")
						else:
							cls.case_to_function(command)(args[0])
					elif command == "end_detect_live_host" or command == "start_recover_topo":
						if len(args) != 2:
							print("Error:Incorrect arguments, fail to execute this command, please confirm that there in no space in your file path")
						else:
							cls.case_to_function(command)(args[0], args[1])
					else:
						cls.case_to_function(res)("go!")
                # str = res.split()
                # for item in str:
                #     print(item)
                self.send_data('ok')#每个指令执行完之后都要向中心节点反馈确认信息
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