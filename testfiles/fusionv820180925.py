# Connet the table HOST and SEGMENT 
# Insert the result into the table SEGMENT_HOST_REL
import cx_Oracle  # import oracle database module
from IPy import IP
import random
import uuid
import re
import os_update
import resolve_file
import pygeoip


def connect_oracle():      #connect to our database
	"""connect the oracle database and set the cursor"""
	global conn
	global cursor
	try:
		conn = cx_Oracle.connect('PROJECT/PROJECT@127.0.0.1/orcl')
		cursor = conn.cursor()
		#print(conn.version)
	except cx_Oracle.OperationalError as err:
		print('Oracle Connect OperationalError:',err)

def disconnect_oracle():     #disconnect to our database
	"""diconnect the cursor and oracle database"""
	try:
		cursor.close()
		conn.close()
	except cx_Oracle.OperationalError as err:
		print('Oracle Disconnect OperationalError:',err)

def update_oracle(sql,var):    #update the database of ourselvesprint(conn.version())
	"""update contains:insert,update,delete"""
	print(sql)
	print(var)
	try:
		cursor.execute(sql,var)
		conn.commit()
		if cursor.rowcount != 0:
			print('Oracle Update Success!')
	except cx_Oracle.OperationalError as err:
		print('Oracle Update OperationalError:',err)

def connect_oracle1():    #connect to FSR database
	"""connect the oracle database and set the cursor"""
	global conn1
	global cursor1
	try:
		conn1 = cx_Oracle.connect('study/study@127.0.0.1/orcl')
		cursor1 = conn1.cursor()
		#print(conn1.version)
	except cx_Oracle.OperationalError as err:
		print('Oracle Connect OperationalError:',err)

def disconnect_oracle1():    #disconnect to FSR database
	"""diconnect the cursor and oracle database"""
	try:
		cursor1.close()
		conn1.close()
	except cx_Oracle.OperationalError as err:
		print('Oracle Disconnect OperationalError:',err)

def update_oracle1(sql,var):  #update the FSR database
	"""update contains:insert,update,delete"""
	print(sql)
	print(var)
	try:
		cursor1.execute(sql,var)
		conn1.commit()
		if cursor1.rowcount != 0:
			print('Oracle Update Success!')
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
		print('IP：',host[1])
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
			cursor1.execute('select ID,OS,NET,MAC from HOST where IP=:host_ip',var)
			hosts = cursor1.fetchall()
			#update the table HOST
			print("The rowcount",cursor1.rowcount)
			if cursor1.rowcount == 0:
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
			update_oracle1(sql,var)
		except Exception as err:
			print('Oracle Error:',err)
			return -1	

def update_segment_host_rel():
	"""connect the table segment and host"""
	try:
		#Get ip address from table HOST
		cursor1.execute('select ID,NET,IP from HOST')
		host_ips = cursor1.fetchall()
		print('The table HOST rows is %d'%cursor1.rowcount)
		if cursor1.rowcount == 0:
			print('The table HOST is empty!')
			return -1
		#Get NET,MASK form table SEGMENT
		cursor1.execute('select ID,NET,MASK from SEGMENT')
		segments = cursor1.fetchall()
		print('The table SEGMENT rows is %d'%cursor1.rowcount)
		if cursor1.rowcount == 0:
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
					cursor1.execute('select * from SEGMENT_HOST_REL where SEGMENT_ID=:sid and HOST_ID=:hid',var)
					#cursor.execute('select * from SEGMENT_HOST_REL where SEGMENT_ID='+segment[0]+' and HOST_ID='+ip[0]+'')
					cursor1.fetchone()
					if (cursor1.rowcount) == 0:
						var = {'id':str(uuid.uuid1()),'sid':segment[0],'hid':ip[0],'traffic':random.randint(1,2000)}
						sql = 'insert into SEGMENT_HOST_REL (ID,UPDATED,SEGMENT_ID,HOST_ID,TRAFFIC)values(:id,1,:sid,:hid,:traffic)'
						update_oracle1(sql,var)
						break
				except Exception as err:
					print('Oracle Operating error:',err)
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
			cursor1.execute('select ID from HOST where IP=:src',var)  #Judge the src address whether it exists
			host1_id = cursor1.fetchone()
			if cursor1.rowcount == 0:
				continue
			var = {'dst':item['dst']}
			cursor1.execute('select ID from HOST where IP=:dst',var)   #Judge the dst address whether it exists
			host2_id = cursor1.fetchone()
			if cursor1.rowcount == 0:
				continue
			var = {'host1_id':host1_id[0],'host2_id':host2_id[0]}
			cursor1.execute('select * from PROTOCOL where HOST1_ID=:host1_id and HOST2_ID=:host2_id',var)  #Judge the ip pair whether it exists
			protocol = cursor1.fetchone()
			if cursor1.rowcount == 1:    #the ip pairs has existed ,update the PROTOCOL table
				if protocol[2]!='Unknown' and pro == 'Unknown':
					pro = protocol[2]
				if protocol[5] != 0 and traffic == 0:
					traffic = int(protocol[5])
				var = {'id':protocol[0],'type':pro,'traffic':traffic}
				sql = 'update PROTOCOL set TYPE=:type,TRAFFIC=:traffic where ID=:id'
			else:
				var = {'id':str(uuid.uuid1()),'type':pro,'host1_id':host1_id[0],'host2_id':host2_id[0],'traffic':traffic}
				sql = "insert into PROTOCOL (ID,UPDATED,TYPE,HOST1_ID,HOST2_ID,TRAFFIC)values(:id,'1',:type,:host1_id,:host2_id,:traffic)"
			update_oracle1(sql,var)
	except Exception as err:
		print(err)

def update_segment(file_full_path):
	"""Transfer data to SEGMENT ,from HOST or segment.txt"""
	items = resolve_file.segment_resolve(file_full_path)
	#data from segment.txt
	if items != -1:
		for item in items:
			try:
				var = {'net':item['net'],'mask':item['mask']}
				cursor1.execute('select * from SEGMENT where NET=:net and MASK=:mask',var)
				cursor1.fetchone()
				if cursor1.rowcount == 1:
					continue
				else:
					print('insert',item['net'])
					var = {'id':str(uuid.uuid1()),'net':item['net'],'mask':item['mask']}
					sql = 'insert into SEGMENT (ID,UPDATED,NET,MASK)values(:id,1,:net,:mask)'
					update_oracle1(sql,var)
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
			cursor1.execute('select * from SEGMENT where NET=:Net and MASK=:Mask',var)  #Judging the network number whether exists
			cursor1.fetchone()
			if cursor1.rowcount ==1:
				continue
			else:
				var = {'id':str(uuid.uuid1()),'Net':NET,'Mask':MASK}
				sql = 'insert into SEGMENT (ID,UPDATED,NET,MASK)values(:id,1,:Net,:Mask)'
				update_oracle1(sql,var)
		except Exception as err:
			print('Oracle Operating error:',err)
			return -1

def update_mask(mask_int):
	"""Transfer number to mask"""
	bin_arr = ['0' for i in range(32)]
	for i in range(mask_int):
		bin_arr[i] = '1'
	tmpmask = [''.join(bin_arr[i * 8:i * 8 + 8]) for i in range(4)]
	tmpmask = [str(int(tmpstr,2)) for tmpstr in tmpmask]
	return '.'.join(tmpmask)

def update_router_ips(file_full_path):
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

def update_router_ip(ip):
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
					cursor1.execute('select ID,OS,NET,MAC from ROUTER where IP=:ip',var)   #Judge the router whether exists
					router = cursor1.fetchone()
				except Exception as err:
					print('Oracle Operating error',err)
					return -1
				if cursor1.rowcount == 1:
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
				update_oracle1(sql,var)

def update_router_router_rel(file_full_path):
	"""Transfer data from router connection.txt to ROUTER_ROUTER_REL"""
	items = resolve_file.router_connection_resolve(file_full_path)
	print(items)
	if items == -1:
		return -1
	for item in items:
		try:
			var = {'router1':item['router1']}
			cursor1.execute('select ID from ROUTER where ip=:router1',var)
			router1_id = cursor1.fetchone()
			if cursor1.rowcount == 0:  #No this router ip
				update_router_ip(item['router1'])
				var = {'id':str(uuid.uuid1()),'ip':item['router1']}
				sql = (
					"insert into ROUTER (ID,UPDATED,OS,IP,NET,PORT,BUSINESSTYPE,MAC,PROCESS,ATTACKED,KEY)"
					"values(:id,'1','Unknown',:ip,'Unknown',0,'0','Unknown','System.exe','0','0')"
					)
				update_oracle1(sql,var)
				var = {'router1':item['router1']}
				cursor1.execute('select ID from ROUTER where ip=:router1',var)
				router1_id = cursor1.fetchone()  #got router1 id
			var = {'router2':item['router2']}
			cursor1.execute('select ID from ROUTER where ip=:router2',var)
			router2_id = cursor1.fetchone()
			if cursor1.rowcount == 0:    #No this router ip
				update_router_ip(item['router2'])
				var = {'id':str(uuid.uuid1()),'ip':item['router2']}
				sql = (
					"insert into ROUTER (ID,UPDATED,OS,IP,NET,PORT,BUSINESSTYPE,MAC,PROCESS,ATTACKED,KEY)"
					"values(:id,'1','Unknown',:ip,'Unknown',0,'0','Unknown','System.exe','0','0')"
					)
				update_oracle1(sql,var)
				var = {'router2':item['router2']}
				cursor1.execute('select ID from ROUTER where ip=:router2',var)
				router2_id = cursor1.fetchone()
			var = {'ROUTER1_ID':router1_id[0],'ROUTER2_ID':router2_id[0]}  #Judge the router connection whether exists
			cursor1.execute('select * from ROUTER_ROUTER_REL where ROUTER1_ID=:ROUTER1_ID and ROUTER2_ID=:ROUTER2_ID',var)
			cursor1.fetchone()
			if cursor1.rowcount == 1:
				print('The router connection relationship existed')
				continue
			var = {'ID':str(uuid.uuid1()),'ROUTER1_ID':router1_id[0],'ROUTER2_ID':router2_id[0],'TRAFFIC':random.randint(1,5000)}
			sql = (
				"insert into ROUTER_ROUTER_REL (ID,UPDATED,ROUTER1_ID,ROUTER2_ID,TRAFFIC)"
				"values(:ID,'1',:ROUTER1_ID,:ROUTER2_ID,:TRAFFIC)"
				)
			update_oracle1(sql,var)
		except Exception as err:
			print('Oracle Operating error',err)
			return -1

def update_segment_router_rel():
	"""estiblish the table SEGMENT and ROUTER"""
	try:
		#Get ID,NET from table ROUTER
		cursor1.execute('select ID,NET,IP from ROUTER')
		routers = cursor1.fetchall()
		#print('The table ROUTER rows is %d'%cursor1.rowcount)
		if cursor1.rowcount == 0:
			print('The table ROUTER is empty!')
			return -1
		#Get ID,NET form table SEGMENT
		cursor1.execute('select ID,NET,MASK from SEGMENT')
		segments = cursor1.fetchall()
		#print('The table SEGMENT rows is %d'%cursor1.rowcount)
		if cursor1.rowcount == 0:
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
					cursor1.execute('select * from SEGMENT_ROUTER_REL where SEGMENT_ID=:sid and ROUTER_ID=:rid',var)
					cursor1.fetchone()
					if (cursor1.rowcount) == 0:
						var = {'id':str(uuid.uuid1()),'sid':segment[0],'rid':router[0],'traffic':random.randint(1,5000)}
						sql = 'insert into SEGMENT_ROUTER_REL (ID,UPDATED,SEGMENT_ID,ROUTER_ID,TRAFFIC)values(:id,1,:sid,:rid,:traffic)'
						update_oracle1(sql,var)
						break
				except Exception as err:
					print('Oracle Operating error:',err)
					return -1

gi = pygeoip.GeoIP(r"C:\IP\GeoLiteCity.dat")
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

#Not yet tested
global number
number = 0
def update_site(number):
	"""Updata table SITE based on table SEGMENT"""
	try:
		cursor1.execute('select NET from SEGMENT')
		nets = cursor1.fetchall()
	except Exception as err:
		print(err)
		return -1
	if cursor1.rowcount <= 0:
		print('The table SEGMENT is empty')
		return -1
	for net in nets:
		try:
			var = {'net':net[0]}
			cursor1.execute('select * from SITE where NET=:net',var)
			cursor1.fetchone()
			if cursor1.rowcount > 0:
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
		update_oracle1(sql,var)

#Not yet tested
def update_site_segment_rel():
	try:
		cursor1.execute('select ID,NET from SITE')
		sites = cursor1.fetchall()
		if cursor1.rowcount <= 0:   #table SITE is empty
			return -1
		cursor1.execute('select ID,NET from SEGMENT')
		segments = cursor1.fetchall()
		if cursor1.rowcount <= 0:   #table SEGMENT is empty
			return -1
		for segment in segments:
			for site in sites:
				if segment[1] == site[1]:
					var = {'id':str(uuid.uuid1()),'site_id':site[0],'segment_id':segment[0],'traffic':random.randint(1,5000)}
					sql = (
						"insert into SITE_SEGMENT_REL (ID,UPDATED,SITE_ID,SEGMENT_ID,TRAFFIC)"
						"values(:id,'1',:site_id,:segment_id,:traffic)"
						)
					update_oracle1(sql,var)
	except Exception as err:
		print(err)
		return -1

#Function mudulation
connect_oracle1()
connect_oracle()
#Update the filed 'HOS' of table HOST
#if update_os() == -1:
	#print('Failed to update HOS filed of table HOST')
#else:
#	print('Successed to update HOS filed of table HOST')

#Update table HOST
#if update_host() == -1:
#	print('Failed to update HOST')
#else:
#	print('Successed to update HOST')

#Update table PROTOCOL
#file_full_path = 'C:\\usr\\test\\protocol.txt'
#if update_protocol(file_full_path) == -1:
#	print('Failed to update PROTOCOL')
#else:
#	print('Successed to update PROTOCOL')

#Update table SEGMENT_HOST_REL
#if update_segment_host_rel() == -1:
#	print('Failed to update  SEGMENT_HOST_REL')
#else:
#	print('Successed to update SEGMENT_HOST_REL')

#Update table PROTOCOL
#if update_protocol() == -1:
#	print('Failed to update PROTOCOL')
#else:
#	print('Successed to update PROTOCOL')

#Update table SEGMENT
#file_full_path = 'C:\\usr\\test\\segment.txt'
#if update_segment(file_full_path) == -1:
#	print('Failed to update SEGMENT')
#else:
#	print('Successed to update SEGMENT')
#
#update table ROUTER
#file_full_path = 'C:\\usr\\test\\router.txt'
#if update_router(file_full_path) == -1:
#	print('Failed to update ROUTER')
#else:
#	print('Successed to update ROUTER')

#Update table ROUTER_ROUTER_REL
#file_full_path = 'C:\\usr\\test\\router_connection.txt'
#if update_router_router_rel(file_full_path) == -1:
#	print('Failed to update ROUTER_ROUTER_REL')
#else:
#	print('Successed to update ROUTER_ROUTER_REL')

#Update table SEGMENT_ROUTER_REL
#if update_segment_router_rel() == -1:
#	print('Failed to update SEGMENT_ROUTER_REL')
#else:
#	print('Successed to update SEGMENT_ROUTER_REL')

#Update table SITE
#if update_site(int(number))== -1:
#	print('Failed to update SITE')
#else:
#	print('Successed to update SITE')

#Update table SITE_SEGMENT_REL
if update_site_segment_rel()== -1:
	print('Failed to update SITE_SEGMENT_REL')
else:
	print('Successed to update SITE_SEGMENT_REL')

disconnect_oracle1()
disconnect_oracle()