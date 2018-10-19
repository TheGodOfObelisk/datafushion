import cx_Oracle
import sys
import uuid
import json
conn =cx_Oracle.connect('PROJECT/PROJECT@192.168.1.30:1521/orcl2')

cursor_target = conn.cursor()
TIP = '192.168.1.157'
TSUBNET='192.168.1.0/24'

db_username_target = "PROJECT"


try:
	cursor_target.execute("""
                        select * from {username}.HOST
			""".format(username=db_username_target))
	res = cursor_target.fetchall()
	print(res)
except:
	print("Error:fail to fetch")
        error_info = sys.exc_info()
        if len(error_info) > 1:
		print(str(error_info[0]) + ' ' + str(error_info[1]))

conn.commit()

cursor_target.close()
conn.close()


sys.exit(0)#just test

