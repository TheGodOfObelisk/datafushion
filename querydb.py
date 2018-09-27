import cx_Oracle
import sys
import uuid
import json
conn =cx_Oracle.connect('study/study@192.168.1.50:1521/ORCL')

cursor_target = conn.cursor()
TIP = '192.168.1.157'
TSUBNET='192.168.1.0/24'

db_username_target = "STUDY"

try:
    cursor_target.execute("""select * from {username}.INJECTION""".format(username=db_username_target))
    result = cursor_target.fetchall()
    print(result)
except:
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
conn.commit()

cursor_target.close()
conn.close()


sys.exit(0)#just test