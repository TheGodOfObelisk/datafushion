import re
def protocol_resolve(file_full_path):
	"""resolve the protocol file"""
	try:
		f = open(file_full_path,'r')
	except FileNotFoundError as err:
		print('No Found File:%s,%s',str(file_full_path),err)
		return -1
	items = []
	for line in f.readlines():
		if line.strip():
			m1 = re.findall('^src:(.*)',line.strip())
			if m1:
				item = {}
				item['src'] = m1[0]
				continue
			m2 = re.findall('^dst:(.*)',line.strip())
			if m2:
				item['dst'] = m2[0]
				continue
			m3 = re.findall('^pro:(.*)',line.strip())
			if m3:
				item['pro'] = m3[0]
				continue
			m4 = re.findall('^The Network Traffic:(\d+) bytes/s',line.strip())
			if m4:
				item['traffic'] = int(m4[0])
				continue
			m5 = re.findall('^This IP appears only once!',line.strip())
			if m5:
				item['traffic'] = 0
				continue
		else:
			items.append(item)
	f.close()
	return items

def segment_resolve(file_full_path):
	"""resolve the segment file"""
	try:
		f = open(file_full_path,'r')
	except FileNotFoundError as err:
		print('No Found File:%s',file_full_path,err)
		return -1
	items = []
	for line in f.readlines():
		if line.strip():
			m1 = re.findall('^(.*) (.*)',line.strip())
			if m1:
				item = {}
				item['net']  = m1[0][0]
				item['mask'] = m1[0][1]
				items.append(item)
	f.close()
	return items

def router_resolve(file_full_path):
	"""resolve the router file"""
	try:
		f = open(file_full_path,'r')
	except FileNotFoundError as err:
		print('No Found File:%s %s',file_full_path,err)
	items = []
	for line in f.readlines():
		if line.strip():
			m1 = re.findall('^(.*)',line.strip());
			if m1:
				item = {}
				item['router'] = m1[0].split(' ')
				items.append(item)
	f.close()
	return items

def router_connection_resolve(file_full_path):
	"""resolve the router connection file"""
	try:
		f = open(file_full_path,'r')
	except FileNotFoundError as err:
		print('No Found File:%s %s',file_full_path,err)
		return -1
	items = []
	for line in f.readlines():
		if line.strip():
			m1 = re.findall('^(.*) (.*)',line.strip())
			if m1:
				item = {}
				item['router1'] = m1[0][0]
				item['router2'] = m1[0][1]
				items.append(item)
	f.close()
	return items		