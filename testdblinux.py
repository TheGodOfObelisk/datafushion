import cx_Oracle
import sys
import uuid
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


sys.exit(0)#just test


declare
						t_count number(10);
						begin
							select count(*) into t_count from {username}.SITE where NAME=:name;
							if t_count=0 then
								insert into {username}.SITE(ID,UPDATED,STATUS,NAME,DETAIL,ADDRESS,NET,TYPE) values(:id,'1','online',:name,NULL,NULL,:subnet,'2');
							else
								update {username}.SITE set NET=:subnet,UPDATED=1,STATUS='online';
							end if;
						end;
						""".format(username=db_username_target),id=str(uuid.uuid1()),name=site_name,subnet=subnet_addr)