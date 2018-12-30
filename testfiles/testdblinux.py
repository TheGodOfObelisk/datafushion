import cx_Oracle
import sys
import json
import logging
conn =cx_Oracle.connect('PROJECT/PROJECT@192.168.1.50:1521/ORCL')

cursor_target = conn.cursor()
TIP = '192.168.1.157'
TSUBNET='192.168.1.0/24'

db_username_target = "PROJECT"
logging.basicConfig(filename = 'testlog.log', filemode = "a", level = logging.DEBUG, format = '%(asctime)s - %(levelname)s - %(message)s')
hid_arr = []
b_arr = []
try:
	cursor_target.execute("""
		select IP,HDEVICE from {username}.HOST
		""".format(username = db_username_target))
	res = cursor_target.fetchall()
	print(res)
	for item in res:
		hid_arr.append(item[0])
		b_arr.append(item[1])
	print(hid_arr)
	print(b_arr)
	#logging.debug(str(res))
except:
	print("Error:fail to fetch")
        error_info = sys.exc_info()
        if len(error_info) > 1:
			print(str(error_info[0]) + ' ' + str(error_info[1]))

conn.commit()

cursor_target.close()
conn.close()

a = None
#if a != None:
if a != None and "v" in a:
	print('ok')
else:
	print('no')


sys.exit(0)#just test

