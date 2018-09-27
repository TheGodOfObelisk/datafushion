import json
with open("result.json","r") as load_f:
	load_dict = json.load(load_f)
	for item in load_dict['tasks']:
		if item['type'] == "activeDetection":#to avoid dulipcation
			s_index = item['hosts'][0].find(':')
			ip_new = item['hosts'][0][0:s_index]
			print(ip_new)