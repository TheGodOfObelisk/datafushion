#-*- coding: UTF-8 -*- 
import re,os,sys
#编辑于2018年10月25日
osweights = {
    'Microsoft Server 2008':10,
    'Windows Server 2008':10,
    'Windows 2000':9,
    'Windows XP SP3':8,
    'Windows 7':7,
    'Windows 8':6,
    'Windows 10':5,
    'Linux':4,
}

def active_dp(file_full_path):
    try:
        f = open(file_full_path, 'r')
    except:
        print('Unexpected error:can not open ' + str(file_full_path))
        return -1
    items = []
    for line in f.readlines():
        if line.strip():
            m1 = re.findall('^Num:.*', line.strip())
            if m1:
                continue
            m2 = re.findall('^Ip:(.*)$', line.strip())
            if m2:
                item = {}
                item['ip'] = m2[0]
                continue
            m3 = re.findall('^addressFamily:(.*)', line.strip())
            if m3:
                item['addrfamily'] = m3[0]
                continue
            m4 = re.findall('^os:(.*)', line.strip())
            if m4:
                if m4[0] != 'NULL':
                    item['os'] = m4[0]
                else:
                    item['os'] = ''
                continue
            m5 = re.findall('^deviceType:(.*)', line.strip())
            if m5:
                if m5[0] != 'NULL':
                    item['devtype'] = m5[0]
                else:
                    item['devtype'] = ''
                continue
            m6 = re.findall('^mac:(.*)', line.strip())
            if m6:
                item['mac'] = m6[0]
                continue
            # extract the port form data
            m_s = re.findall('^start', line.strip())
            if m_s:
                portform = []
                continue
            m = re.findall('^\d+.*', line.strip())
            if m:
                fitem = {}
                list_item = str.split(line.strip(), '\t')
                if len(list_item) != 4:
                    continue
                else:
                    fitem['port'] = int(list_item[0])
                    fitem['protocol'] = list_item[1]
                    if list_item[2] == 'open':
                        fitem['status'] = 1
                    else:
                        fitem['status'] = 0
                    fitem['service'] = list_item[3]
                    try:
                        portform.append(fitem)
                    except:
                        print('error:can not get info of port')
                continue
            m_e = re.findall('^end', line.strip())
            if m_e:
                try:
                    item['portform'] = portform
                except:
                    print('error:can not store info of port')
                continue
            m7 = re.findall('^openNum:(.*)', line.strip())
            if m7:
                item['opennum'] = int(m7[0])
                continue
            m8 = re.findall('^serviceNum:(.*)', line.strip())
            if m8:
                item['sernum'] = int(m8[0])
        else:
            if item['os'] == '':
                weight = 2
            else:
                weight = 3
                match = re.findall(
                    'Microsoft Server 2008|Windows Server 2008|Windows 2000|Windows XP SP3|Windows 7|Windows 8|Windows 10|Linux',
                    item['os'], re.IGNORECASE)
                for i in match:
                    i = i.title()
                for key in osweights:
                    if key in match:
                        if weight < osweights[key]:
                            weight = osweights[key]
            item['osweight'] = weight
            items.append(item)
    f.close()
    return items

def passive_dp(file_full_path):
    try:
        f = open(file_full_path, 'r')
    except:
        print('Unexpected error:can not open ' + str(file_full_path))
        return -1
    items = []
    for line in f.readlines():
        if line.strip():
            m1 = re.findall('^IP:(.*)', line.strip())
            if m1:
                item = {}
                item['ip'] = m1[0]
                continue
            m2 = re.findall('^Service Type\((\d+)\):(.*)', line.strip())
            if m2:
                item['snum'] = int(m2[0][0])
                item['slist'] = str.split(m2[0][1], ' ')
                continue
            m3 = re.findall('^The Network Traffic:(\d+) bytes/s', line.strip())
            if m3:
                item['traffic'] = int(m3[0])
                continue
            m4 = re.findall('^The Frequency:(\d+) packets/s', line.strip())
            if m4:
                item['frequency'] = int(m4[0])
                continue
            m5 = re.findall('^This IP pairs appears only once!', line.strip())
            if m5:
                item['traffic'] = 0
                item['frequency'] = 0
                continue
        else:
            items.append(item)
    f.close()
    return items

def router_dp(file_full_path):
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
