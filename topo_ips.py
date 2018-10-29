import cx_Oracle
from IPy import IP
def connect_target_oracle():    #connect to FSR database
	"""connect the oracle database and set the cursor"""
	global conn_target
	global cursor_target
	try:
		conn_target = cx_Oracle.connect('study/study@127.0.0.1/orcl')
		cursor_target = conn_target.cursor()
		#print(conn1.version)
	except cx_Oracle.OperationalError as err:
		print('Oracle Connect OperationalError:',err)

def disconnect_target_oracle():    #disconnect to FSR database
	"""diconnect the cursor and oracle database"""
	try:
		cursor_target.close()
		conn_target.close()
	except cx_Oracle.OperationalError as err:
		print('Oracle Disconnect OperationalError:',err)

def get_topo_ips(items):
	"""obtain relevant routers' ip based on subnet"""
	composite_items = []
	if items == []:
		return -1
	for item in items:
		atom_item = []
		router_flag = 0
		atom_item.append(item)
		net_prefix = item.split(',')[1]
		net = net_prefix.split('/')[0]
		mask = update_mask(int(net_prefix.split('/')[1]))
		default_gateway = item.split(',')[2]
		try:
			cursor_target.execute('select IP,NET from ROUTER')
			routers = cursor_target.fetchall() 
		except Exception as err:
			print(err)
			return -1
		#read data from ROUTER
		if cursor_target.rowcount == 0:
			return -1
		for router in routers:
			ips_str = str(router[0])
			if router[1]!='Unknown': #the net field is not empty
				if router[1]==net:
					router_flag = 1
					atom_item.append(ips_str.split(',')[0])   #get the first ip
					composite_items.append(atom_item)
					break
			ips = ips_str.split(',')
			for ip in ips:
				router_net = str(IP(ip).make_net(mask)).split('/',1)[0]
				if router_net == net:
					router_flag = 1
					atom_item.append(ip)
					composite_items.append(atom_item)
					break
			if router_flag == 1:
				break

		#not get router ip
		if router_flag == 0:
			if default_gateway!='Unknown':
				atom_item.append(default_gateway)
				composite_items.append(atom_item)
				continue
			net_split = net.split('.')
			ip = net_split[0]+'.'+net_split[1]+'.'+net_split[2]+'.1'
			atom_item.append(ip)
			composite_items.append(atom_item)

	return composite_items

def parse_items(double_items):
	ip_item = []
	if double_items == []:
		return -1
	for items in double_items:
		host_ip = items[0].split(',')[0]
		router_ip = items[1]
		ips = host_ip + ',' + router_ip
		ip_item.append(ips)
	return ip_item


def update_mask(mask_int):
	"""Transfer number to mask"""
	bin_arr = ['0' for i in range(32)]
	for i in range(mask_int):
		bin_arr[i] = '1'
	tmpmask = [''.join(bin_arr[i * 8:i * 8 + 8]) for i in range(4)]
	tmpmask = [str(int(tmpstr,2)) for tmpstr in tmpmask]
	return '.'.join(tmpmask)

connect_target_oracle()
items =  ['192.168.0.13,192.168.0.0/24,Unknown','192.10.5.2,192.10.5.0/24,Unknown','192.10.11.2,192.10.11.0/24,192.168.11.1','192.10.14.2,192.10.14.0/24,Unknown']
print('composite_items=',get_topo_ips(items))
#composite_items= [['192.168.0.13,192.168.0.0/24,Unknown', '192.10.1.2'], ['192.10.5.2,192.10.5.0/24,Unknown', '192.10.5.1'], ['192.10.11.2,192.10.11.0/24,192.168.11.1', '192.168.11.1'], ['192.10.14.2,192.10.14.0/24,Unknown', '192.10.14.1']]
print('ips_items=',parse_items(get_topo_ips(items)))
#ips_items= ['192.168.0.13,192.10.1.2', '192.10.5.2,192.10.5.1', '192.10.11.2,192.168.11.1', '192.10.14.2,192.10.14.1']
#last_parse....
ips_items = parse_items(get_topo_ips(items))
for ips_item in ips_items:
	host_ip = ips_item.split(',')[0]
	router_ip = ips_item.split(',')[1]
	print(host_ip)
	print(router_ip)
disconnect_target_oracle()