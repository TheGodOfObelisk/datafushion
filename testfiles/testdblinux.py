import cx_Oracle
import sys
import uuid
import json
conn =cx_Oracle.connect('study/study@192.168.1.50:1521/ORCL')

cursor_target = conn.cursor()
TIP = '192.168.1.157'
TSUBNET='192.168.1.0/24'

db_username_target = "STUDY"

with open("result.json","r") as load_f:
    load_dict = json.load(load_f)
    for item in load_dict['tasks']:
        if item['type'] == "activeDetection":#to avoid dulipcation
            s_index = item['hosts'][0].find(':')
            ip_new = item['hosts'][0][0:s_index]
            print(ip_new)
            try:
                cursor_target.execute("""
                select ID from {username}.HOST where IP=:ip
                """.format(username=db_username_target),ip=ip_new)
                result = cursor_target.fetchall()
                host_id = result[0][0]
                if len(result) > 1:
                    print("Error: more than one record noticing the same ip")
                elif len(result) == 0:
                    print("Error: the new agent ip hasn't been inserted into the HOST table")
            except:
                print("Error:fail to fetch ID from HOST")
                error_info = sys.exc_info()
                if len(error_info) > 1:
                    print(str(error_info[0]) + ' ' + str(error_info[1]))
            try:
                cursor_target.execute("""
                declare t_count number(10);
                begin
                    select count(*) into t_count from {username}.INJECTION where TARGET_ID=:h_id;
                    if t_count=0 then
                        insert into {username}.INJECTION(ID,UPDATED,TARGET_ID,PERIOD) values(:in_id,'1',:h_id,'start');
                    else
                        update {username}.INJECTION set UPDATED=1,PERIOD='start';
                    end if;
                end;
                """.format(username=db_username_target),in_id=str(uuid.uuid1()),h_id=host_id)
            except:
                print("Error:fail to update the INJECTION table")
                error_info = sys.exc_info()
                if len(error_info) > 1:
                    print(str(error_info[0]) + ' ' + str(error_info[1]))
            try:
                cursor_target.execute("""
                        select ID from {username}.INJECTION where TARGET_ID=:ho_id
                        """.format(username=db_username_target),ho_id=host_id)
                result = cursor_target.fetchall()
                if len(result) > 1:
                    print("Error:more than one record noticing the same host in INJECTION table")
                injection_id = result[0][0]
            except:
                print("Error:fail to fetch ID from the INJECTION table")
                error_info = sys.exc_info()
                if len(error_info) > 1:
                    print(str(error_info[0]) + ' ' + str(error_info[1]))

            try:
                print("host_id: ", host_id)
                print("injection_id: ", injection_id)
                cursor_target.execute("""
                        update {username}.INJECTION set UPDATED=1,PERIOD='done' where ID=:in_id
                        """.format(username=db_username_target),in_id=injection_id)
            except:
                print("Error:fail to update the INJECTION table")
                error_info = sys.exc_info()
                if len(error_info) > 1:
                    print(str(error_info[0]) + ' ' + str(error_info[1]))

conn.commit()

cursor_target.close()
conn.close()


sys.exit(0)#just test

