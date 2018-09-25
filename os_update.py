import re

def split_str(str):
	"""Split the ';' string"""
	semicolonlist = str.split(';')
	for slist in semicolonlist:
		m = re.match('\sor\s',slist)
		if m == None:
			print('sssssss String :',slist)
			oslist.append(slist)
		else:
			print('SSSSSSS String :',slist.lstrip(' or '))
			oslist.append(slist.lstrip(' or '))


def split_substr(str):
	"""Split the ', or ' string"""
	#print('2The os sting is:',str)
	m = re.search('\,\sor\s',str)
	if m == None:
		split_grandstr(str)
	else:
		orlist = str.split(', or ')
		for olist in orlist:
			split_grandstr(olist)

def split_grandstr(str):
	"""Split the ', ' string"""
	#print('3The os string is:',str)
	m = re.search('\,\s',str)
	if m == None:
		split_subgrandstr(str)
	else:
		list = str.split(', ')
		for l in list:
			split_subgrandstr(l)
			
def split_subgrandstr(str):
	"""Split the ' or ' string"""
	#print('4The os string is:',str)
	m = re.search('\sor\s',str)
	if m==None:
		#print('string:',str)
		oslist.append(str)
	else:
		list = str.split(' or ')
		for li in list:
			#print('string:',li)
			oslist.append(li)
	


str1 = '2N Helios IP VoIP doorbell'
str2 = '3Com 4200G or Huawei Quidway S5600 switch'
str3 = '3Com 4210, or Huawei Quidway S3928P-EI or S5624F switch (VRP 3.10)'
str = 'Broadband router (Allied Data CopperJet, Belkin F5D7632-4, Intracom Jetspeed 500i, or Iskratel Sinope568 or Proteus932); or Adva Optical FSP 150CC-825 router'
str5 = 'Allied Telesis AT-8000S; Dell PowerConnect 2824, 3448, 5316M, or 5324; Linksys SFE2000P, SRW2024, SRW2048, or SRW224G4; or TP-LINK TL-SL3428 switch'


def os_str_transfer(str):
	global oslist   #store the os string respectively
	oslist = [] 
	if re.search('\;',str) == None:
		#print('no ;')
		split_substr(str)
	else:
		#print('yes ;')
		split_str(str)
	return oslist

#print(str)
#for L in List:
#	print('Operating System:',L)

