CandidateIP = []
objitem = {}
objitem['ip'] = '192.168.1.21'
# objitem['netmask'] = '255.255.255.0'
# CandidateIP.append(objitem)
# objitem['ip'] = '192.168.1.25'
# objitem['netmask'] = '255.255.255.128'
# CandidateIP.append(objitem['ip'])

CandidateIP.append(objitem['ip'])
CandidateIP.append(objitem['ip'])
CandidateIP.append(objitem['ip'])
CandidateIP.append(objitem['ip'])

# print(objitem)
print(CandidateIP)

for ip in CandidateIP:
    print(ip)