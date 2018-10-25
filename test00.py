import re
def router_resolve(file_full_path):
	"""resolve the router file"""
	try:
		f = open(file_full_path,'r')
	except:
		print('No Found File:%s',file_full_path)
	items = []
	for line in f.readlines():
		if line.strip():
			m1 = re.findall('^(.*)',line.strip());
			if m1:
				item = m1[0].split(' ')
				for ip in item:
					items.append(ip)
	f.close()
	return items

path = '/home/lw/dataf917/datafusion/192.168.0.133/router.txt'
items = router_resolve(path)
print(items)


