import cx_Oracle
import sys
import uuid
import datetime
conn =cx_Oracle.connect('study/study@192.168.1.52:1521/ORCL')

cursor = conn.cursor()
TIP = '192.168.1.157'
TSUBNET='192.168.1.0/24'

try:
    cursor.execute("""
    	select ID from STUDY.SEGMENT
        """)
    result = cursor.fetchall()
    print(result)
    print(len(result))
except:
    print('error when updating')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)

conn.commit()
cursor.close()
conn.close()

now_time = datetime.datetime.now()
now_time1 = datetime.datetime.strftime(now_time,'%Y/%m/%d %H:%M:%S')
print(now_time)
print(now_time1)

sys.exit(0)#just test
