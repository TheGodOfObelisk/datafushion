import os,sys,re,json
import cx_Oracle
import dpfun
import socket
#9.15 的修改： 主机表的insert语句的添加了NULL给netmask，VALUES的末尾
#get arguments
comnand_arguments = sys.argv
if not (len(comnand_arguments)==3):
    print('error:incorrect argument')
    sys.exit(1)
root_dir = comnand_arguments[1]
dbconfigs = comnand_arguments[2]
#get the directory of file
ip_dirs = dpfun.get_result_list(root_dir)
if ip_dirs == -1:
    sys.exit(1)
if not (len(ip_dirs)>0):
    print('无探测结果')
    sys.exit(0)
#connect to the database
try:
    conn = cx_Oracle.connect(dbconfigs)
except:
    print('Exception:can not connect to the database')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' '+str(error_info[1]))
    sys.exit(1)
cursor = conn.cursor()
#get username
m_user = re.findall('^(.*)/(.*)@(.*):(.*)/(.*)$',dbconfigs.strip())
try:
    db_username = m_user[0][0].upper()
except:
    print('Exception:can not get database username')
    sys.exit(1)
#start of my editing
#preprocess
#先处理第一轮探测的子节点信息，从config.json中读取
with open("config.json","r") as load_f:
    load_dict = json.load(load_f)
    print(load_dict)
    host = load_dict['tasks'][0]['hosts'][0]
    print(host)
    s_index = host.find(':')
    host_ip = host[0:s_index]
    print(host_ip)
    try:
        cursor.execute("""
            declare
                isAgent "{username}"."Host"."isAgent"%TYPE;
            begin
                select "isAgent" into isAgent from "{username}"."Host" where "IP"=:ip;
                    case isAgent
                        when 0 then
                            update "{username}"."Host" set "isAgent"=1,"isNew"=0,"HisDel"=0;
                        when 1 then
                            update "{username}"."Host" set "isNew"=0,"HisDel"=0;
                        when 2 then
                            update "{username}"."Host" set "isAgent"=1,"isNew"=0,"HisDel"=0;
                    end case;
            exception
                    when NO_DATA_FOUND then
                        insert into "{username}"."Host" values(:ip,0,0,0,NULL,0,NULL,NULL,0,NULL,
                                            0,0,1,0,0,0,0,0,0,NULL);
            end;
        """.format(username=db_username),ip=host_ip)

    except:
        print("Error:can not initialize database")
        error_info = sys.exc_info()
        if len(error_info) > 1:
            print(str(error_info[0]) + ' ' + str(error_info[1]))
#再处理中心节点自身的信息（自身不参与选举），它所属的子网不加到agents表中（既不参选也不影响参选）
def get_host_ip():
    """
    查询本机ip地址
    :return: ip
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    return ip
localip = ""
if __name__ == '__main__':
    localip = get_host_ip()
try:
    cursor.execute("""
                declare
                    isAgent "{username}"."Host"."isAgent"%TYPE;
                begin
                    select "isAgent" into isAgent from "{username}"."Host" where "IP"=:ip;
                        case isAgent
                            when 0 then
                                update "{username}"."Host" set "isAgent"=2,"isNew"=0,"HisDel"=0;
                            when 1 then
                                update "{username}"."Host" set "isAgent"=2,"isNew"=0,"HisDel"=0;
                            when 2 then
                                update "{username}"."Host" set "isNew"=0,"HisDel"=0;
                        end case;
                exception
                        when NO_DATA_FOUND then
                            insert into "{username}"."Host" values(:ip,0,0,0,NULL,0,NULL,NULL,0,NULL,
                                                0,0,1,0,0,0,0,0,0,NULL);
                end;
            """.format(username=db_username), ip=localip)
except:
    print("Error:can not reinitialize database")
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
#end of my editing

#process
for ip_dir in ip_dirs:
    print('处理来自 ' + os.path.basename(ip_dir) + ' 的探测结果')
    try:
        file_list = os.listdir(ip_dir)
    except:
        print('error:occured in process '+ ip_dir,end=' ')
        error_info = sys.exc_info()
        if len(error_info) > 1:
            print(str(error_info[0]) + ' ' + str(error_info[1]))
        continue
    if not (len(file_list)>0):
        print(os.path.basename(ip_dir) + ' 中无探测结果')
        continue
    for file in file_list:
        file_full_path = os.path.join(ip_dir,file)
        if os.path.isfile(file_full_path):
            if file == 'active.txt':
                items = dpfun.active_dp(file_full_path)
                if items == -1:
                    continue
                # db operation
                try:
                    for item in items:
                        cursor.execute("""
                            declare
                                isDel "{username}"."Host"."HisDel"%TYPE;
                            begin
                                select "HisDel" into isDel from "{username}"."Host" where IP =:ip;
                                    case isDel
                                        when 0 then
                                            update "{username}"."Host" set
                                            "HaddressFamily"=:addrfamily,"Hos"=:os,"Hdevice"=:devtype,"Hmac"=:mac,
                                            "osWeight"=:osWeight,"HopenPortNum"=:opennum where "IP"=:ip;
                                        when 1 then
                                            update "{username}"."Host" set
                                            "HserviceNum"=:serviceNum,"Htraffic"=:traffic,"Hfrequency"=:frequency,"Hos"=:os,"HopenPortNum"=:opennum,
                                            "Hdevice"=:devtype,"Hmac"=:mac,"Hweight"=:weight,"HaddressFamily"=:addrfamily,"HisDel"=:isDel,
                                            "serviceWeight"=:serviceweight,"trafficWeight"=:trafficweight,
                                            "frequencyWeight"=:frequencyweight,"portNumWeight"=:portNumweight,
                                            "osWeight"=:osWeight,"servicePriority"=:servicePriority where "IP"=:ip;
                                    end case;
                            exception
                                    when NO_DATA_FOUND then
                                        insert into "{username}"."Host" values(:ip,:serviceNum,:traffic,:frequency,:os,:opennum,:devtype,:mac,:weight,:addrfamily,
                                        :isDel,:isNew,:isAgent,:serviceweight,:trafficweight,:frequencyweight,:portNumweight,:osWeight,:servicePriority,NULL);
                            end;
                        """.format(username=db_username),ip=item['ip'], serviceNum=0, traffic=0, frequency=0, os=item['os'],
                                       opennum=item['opennum'], devtype=item['devtype'], mac=item['mac'],
                                       weight=0, addrfamily=item['addrfamily'],isDel=0, isNew=1, isAgent=0,
                                       serviceweight=0, trafficweight=0, frequencyweight=0,
                                       portNumweight=0, osWeight=item['osweight'], servicePriority=0)

                        # cursor.execute("""
                        ##               delete from "%s"."Host" where "IP" = :ip and "isNew" = 0 and "isAgent" = 0
                        #             """ % db_username, ip=item["ip"])
                        # cursor.execute("""merge into "%s"."Host" h using dual on((select count(*) from "%s"."Host" where IP=:ip)>0)
                        #             when matched then update set
                        #             h."HaddressFamily"=:addrfamily,h."Hos"=:os,h."Hdevice"=:devtype,h."Hmac"=:mac,
                        #             h."osWeight"=:osWeight,h."HopenPortNum"=:opennum where h."IP"=:ip
                        #             when not matched then
                        #             insert values(:ip,:serviceNum,:traffic,:frequency,:os,:opennum,:devtype,:mac,:weight,:addrfamily,
                        #             :isDel,:isNew,:isAgent,:serviceweight,:trafficweight,:frequencyweight,:portNumweight,:osWeight,:servicePriority)
                        #             """ % (db_username, db_username),
                        #                ip=item['ip'], serviceNum=0, traffic=0, frequency=0, os=item['os'],
                        #                opennum=item['opennum'], devtype=item['devtype'], mac=item['mac'],
                        #                weight=0, addrfamily=item['addrfamily'], isDel=0, isNew=1, isAgent=0,
                        #                serviceweight=0, trafficweight=0, frequencyweight=0,
                        #                portNumweight=0, osWeight=item['osweight'], servicePriority=0)
                        if len(item['portform']) > 0:
                            cursor.execute("""delete from "%s"."Port" where IP =:ip""" % db_username, ip=item['ip'])
                            for p in item['portform']:
                                cursor.execute(
                                    """insert into "%s"."Port" ("Pid","IP","Pport","Pstatus","Pservice","PisDel") values(AutoId.nextval,:ip,:port,:status,:service,:isDel)""" % db_username,
                                    ip=item['ip'], port=p['port'], status=p['status'], service=p['service'], isDel=0)
                    conn.commit()
                except:
                    print("Error:can not store active data")
                    error_info = sys.exc_info()
                    if len(error_info) > 1:
                        print(str(error_info[0]) + ' ' + str(error_info[1]))
            elif file == 'passive.txt':  # Passive detection file
                items = dpfun.passive_dp(file_full_path)
                if items == -1:
                    continue
                # db operation
                try:
                    for item in items:
                        service_exist = {
                            'telnet': 0,
                            'snmp': 0,
                            'icmp': 0,
                            'dns': 0,
                            'http': 0,
                            'ftp': 0,
                            'tftp': 0,
                            'ntp': 0,
                            'pop3': 0,
                            'smtp': 0,
                        }
                        for skey in service_exist:
                            if skey in item['slist']:
                                service_exist[skey] = 1
                                item['slist'].remove(skey)
                        sothers = ','.join(item['slist'])
                        if len(sothers) > 255:
                            sothers = sothers[0:255]
                        cursor.execute("""
                                declare
                                    isDel "{username}"."Host"."HisDel"%TYPE;
                                begin
                                    select "HisDel" into isDel from "{username}"."Host" where IP =:ip;
                                    case isDel
                                        when 0 then
                                            update "{username}"."Host" set 
                                            "HserviceNum"=:serviceNum,"Htraffic"=:traffic,"Hfrequency"=:frequency where "IP"=:ip;
                                        when 1 then
                                            update "{username}"."Host" set
                                            "HserviceNum"=:serviceNum,"Htraffic"=:traffic,"Hfrequency"=:frequency,"Hos"=:os,"HopenPortNum"=:opennum,
                                            "Hdevice"=:devtype,"Hmac"=:mac,"Hweight"=:weight,"HaddressFamily"=:addrfamily,"HisDel"=:isDel,
                                            "serviceWeight"=:serviceweight,"trafficWeight"=:trafficweight,
                                            "frequencyWeight"=:frequencyweight,"portNumWeight"=:portNumweight,
                                            "osWeight"=:osWeight,"servicePriority"=:servicePriority where "IP"=:ip;
                                    end case;
                                exception
                                    when NO_DATA_FOUND then
                                        insert into "{username}"."Host" values(:ip,:serviceNum,:traffic,:frequency,:os,:opennum,:devtype,:mac,:weight,:addrfamily,
                                        :isDel,:isNew,:isAgent,:serviceweight,:trafficweight,:frequencyweight,:portNumweight,:osWeight,:servicePriority,NULL);
                                end;
                                """.format(username=db_username),ip=item['ip'], serviceNum=item['snum'], traffic=item['traffic'],
                                        frequency=item['frequency'], os='',opennum=0, devtype='',
                                        mac='', weight=0, addrfamily='', isDel=0, isNew=1,isAgent=0,
                                      serviceweight=0, trafficweight=0, frequencyweight=0,
                                        portNumweight=0, osWeight=0, servicePriority=0)
                        # cursor.execute("""
                        ##         delete from "%s"."Host" where "IP" = :ip and "isNew" = 0 and "isAgent" = 0
                        #                 """ % db_username,ip = item["ip"])
                        # cursor.execute("""merge into "%s"."Host" h using dual on((select count(*) from "%s"."Host" where IP=:ip)>0)
                        #             when matched then update set
                        #             h."HserviceNum"=:serviceNum,h."Htraffic"=:traffic,h."Hfrequency"=:frequency where h."IP"=:ip
                        #             when not matched then
                        #             insert values(:ip,:serviceNum,:traffic,:frequency,:os,:opennum,:devtype,:mac,:weight,:addrfamily,
                        #             :isDel,:isNew,:isAgent,:serviceweight,:trafficweight,:frequencyweight,:portNumweight,:osWeight,:servicePriority)
                        #             """ % (db_username, db_username),
                        #                ip=item['ip'], serviceNum=item['snum'], traffic=item['traffic'],
                        #                frequency=item['frequency'], os='',opennum=0, devtype='',
                        #                mac='', weight=0, addrfamily='', isDel=0, isNew=1,isAgent=0,
                        #                serviceweight=0, trafficweight=0, frequencyweight=0,
                        #                portNumweight=0, osWeight=0, servicePriority=0)
                        # Service form
                        cursor.execute("""merge into "%s"."Service" t using dual on((select count(*) from "%s"."Service" where IP=:IP)>0)
                                    when matched then 
                                    update set t."Stelnet"=:Stelnet,t."Ssnmp"=:Ssnmp,t."Sicmp"=:Sicmp,t."Sdns"=:Sdns,t."Shttp"=:Shttp,
                                    t."Sftp"=:Sftp,t."Stftp"=:Stftp,t."Sntp"=:Sntp,t."Spop3"=:Spop3,t."Ssmtp"=:Ssmtp,t."Sothers"=:Sothers,
                                    t."SisDel"=:SisDel where t."IP"=:IP
                                    when not matched then
                                    insert values(AutoId_service.nextval,:IP,:Stelnet,:Ssnmp,:Sicmp,:Sdns,:Shttp,:Sftp,:Stftp,:Sntp,:Spop3,:Ssmtp,:Sothers,:SisDel)""" % (db_username, db_username),
                                       IP=item['ip'], Stelnet=service_exist['telnet'], Ssnmp=service_exist['snmp'],
                                       Sicmp=service_exist['icmp'],Sdns=service_exist['dns'], Shttp=service_exist['http'],
                                       Sftp=service_exist['ftp'], Stftp=service_exist['tftp'],Sntp=service_exist['ntp'],
                                       Spop3=service_exist['pop3'],Ssmtp=service_exist['smtp'], Sothers=sothers, SisDel = 0)
                    conn.commit()  # 提交事务
                except:
                    print("Error:can not store passive data")
                    error_info = sys.exc_info()
                    if len(error_info) > 1:
                        print(str(error_info[0]) + ' ' + str(error_info[1]))

# 数据库操作：包括计算权值和决策两部分
# 权值计算：（涉及更新各个子权值，排序决定的子权值在赋值之前应当全部置零）
# 1.开放端口数：排序决定
# 2.业务种类：排序决定
# 3.通信量：排序决定
# 4.通信频次：排序决定
# 5.业务优先级：由最高的那个决定
# 属性值	分值
# TELNET	10
# SNMP	9
# ICMP	8
# DNS	    7
# HTTP	6
# FTP	    5
# TFTP	4
# NTP	    3
# POP3	2
# SMTP	1
# 6..总权值计算及更新
# 属性	比例	最高分值
# 业务优先级	0.3	10
# 业务种类	0.1	10
# 通信量	0.2	10
# 通信频次	0.2	10
# 操作系统	0.1	10
# 开放端口数	0.1	10
# 其中：操作系统：一一映射（模式匹配）数据融合阶段已完成
# 决策：
# 1.按总权值排序取主机信息
# 2.isAgent字段已为1或者2的主机不参与决策
# 3.总权值并列第一的主机只取第一个（暂定）
# 4.优先在新发现的节点中选取（isnew字段为1）
# 5.收尾工作（把所有的isnew字段置为0，所有的HisDel字段置为1，并将选取出来的新节点的isAgent字段置为1，把同一个子网内已经有其他agent的主机的isAgent字段置为2）

#0.重置权值阶段
print("0.重置权值阶段")
try:
    cursor.execute("""
        update "%s"."Host" set "serviceWeight"= 0,"trafficWeight"= 0,"frequencyWeight"= 0,
        "portNumWeight"= 0,"servicePriority"= 0,"Hweight"= 0
        """ % db_username)
except:
    print('error when updating')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)

#1.计算开放端口数子权值
print('1.计算开放端口子权值阶段')
try:
    cursor.execute("""
        select "IP" as "tIP","HopenPortNum" as "tHopenPortNum" from "%s"."Host"
        where "isAgent"= 0 and "HisDel"= 0 ORDER BY "HopenPortNum" DESC 
        """ % db_username)
except:
    print('error when selecting')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)
result = cursor.fetchall()
portNumArr = []
iWeight = 10
for host in result:
    portNumItem = {}
    portNumItem['ip'] = host[0]
    portNumItem['openPortNum'] = host[1]
    portNumItem['portNumWeight'] = iWeight
    portNumArr.append(portNumItem)
    iWeight -= 1
    if iWeight < 1:
        break
for host in portNumArr:
    try:
        cursor.execute("""
                  update "%s"."Host" set "portNumWeight"=:portNumWeight where "IP"=:hostIp        
                  """ % db_username,portNumWeight=host["portNumWeight"],hostIp=host["ip"])
    except:
        print('error when updating')
        error_info = sys.exc_info()
        if len(error_info) > 1:
            print(str(error_info[0]) + ' ' + str(error_info[1]))
        sys.exit(1)

#2.计算业务种类数子权值
print('2.计算服务种类个数子权值阶段')
try:
    cursor.execute("""
                select "IP" as "tIP","HserviceNum" as "tHserviceNum" from "%s"."Host" where "isAgent"= 0 and "HisDel"= 0 ORDER BY "HserviceNum" DESC 
                """ % db_username)
except:
    print('error when selecting')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)
result = cursor.fetchall()
serviceNumArr = []
iServiceWeight = 10
for host in result:
    serviceNumItem = {}
    serviceNumItem['ip'] = host[0]
    serviceNumItem['HserviceNum'] = host[1]
    serviceNumItem['serviceWeight'] = iServiceWeight
    serviceNumArr.append(serviceNumItem)
    iServiceWeight -= 1
    if iServiceWeight < 1:
        break
for host in serviceNumArr:
    try:
        cursor.execute("""
                    update "%s"."Host" set "serviceWeight"=:serviceWeight where "IP"=:hostIp
                    """%db_username,serviceWeight=host["serviceWeight"],hostIp=host["ip"])
    except:
        print('error when updating')
        error_info = sys.exc_info()
        if len(error_info) > 1:
            print(str(error_info[0]) + ' ' + str(error_info[1]))
        sys.exit(1)

#3.计算通信量子权值
print('3.计算通信量子权值字段')
try:
    cursor.execute("""
               select "IP" as "tIP","Htraffic" as "tHtraffic" from "%s"."Host" where "isAgent"= 0 and "HisDel"= 0 ORDER BY "Htraffic" DESC  
                """ % db_username)
except:
    print('error when selecting')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)
result = cursor.fetchall()
trafficArr = []
iTrafficWeight = 10
for host in result:
    trafficItem = {}
    trafficItem['ip'] = host[0]
    trafficItem['Htraffic'] = host[1]
    trafficItem['trafficWeight'] = iTrafficWeight
    trafficArr.append(trafficItem)
    iTrafficWeight -= 1
    if iTrafficWeight < 1:
        break
for host in trafficArr:
    try:
        cursor.execute("""
                update "%s"."Host" set "trafficWeight"=:trafficWeight where "IP"=:hostIp
                """%db_username,trafficWeight = host["trafficWeight"],hostIp = host["ip"])
    except:
        print('error when updating')
        error_info = sys.exc_info()
        if len(error_info) > 1:
            print(str(error_info[0]) + ' ' + str(error_info[1]))
        sys.exit(1)

#4.计算通信频次子权值
print('4.计算通信频次子权值阶段')
sql_t = ""
try:
    cursor.execute("""
            select "IP" as "tIP","Hfrequency" as "tHfrequency" from "%s"."Host" where "isAgent"= 0  and "HisDel"= 0 ORDER BY "Hfrequency" DESC 
                """ % db_username)
except:
    print('error when selecting')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)
result = cursor.fetchall()
frequencyArr = []
iFrequencyWeight = 10
for host in result:
    frequencyItem = {}
    frequencyItem["ip"] = host[0]
    frequencyItem["Hfrequency"] = host[1]
    frequencyItem["frequencyWeight"] = iFrequencyWeight
    frequencyArr.append(frequencyItem)
    iFrequencyWeight -= 1
    if iFrequencyWeight < 1:
        break
for host in frequencyArr:
    try:
        cursor.execute("""
            update "%s"."Host" set "frequencyWeight"=:frequencyWeight where "IP"=:hostIp
                """ % db_username,frequencyWeight = host["frequencyWeight"],hostIp = host["ip"])
    except:
        print('error when updating')
        error_info = sys.exc_info()
        if len(error_info) > 1:
            print(str(error_info[0]) + ' ' + str(error_info[1]))
        sys.exit(1)

#5.计算业务优先级权值
print('5.计算业务优先级阶段')
try:
    cursor.execute("""
          select "%s"."Host"."IP" as "tIP",
          "Stelnet" as "tStelnet", "Ssnmp" as "tSsnmp","Sicmp" as "tSicmp", "Sdns" as "tSdns","Shttp" as "tShttp",
          "Sftp" as "tSftp","Stftp" as "tStftp","Sntp" as "tSntp", "Spop3" as "tSpop3","Ssmtp" as "tSsmtp" 
          from "%s"."Host","%s"."Service" 
          where "isAgent"= 0 and "%s"."Host"."IP" = "%s"."Service"."IP" and "%s"."Host"."HisDel"= 0   
                """ % (db_username,db_username,db_username,db_username,db_username,db_username))
except:
    print('error when selecting')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)
result = cursor.fetchall()
servicePriorityArr = []
for host in result:
    #host[0]: ip ; host[1]: telnet; host[2]: snmp; host[3]: icmp; host[4]: dns
    #host[5]: http; host[6]: ftp; host[7]: tftp; host[8]: ntp; host[9]: pop3;
    #host[10]: smtp;
    servicePriorityItem = {}
    if host[1]:#telnet
        servicePriorityItem["ip"] = host[0]
        servicePriorityItem["servicePriority"] = 10
        servicePriorityArr.append(servicePriorityItem)
        continue
    if host[2]:#snmp
        servicePriorityItem["ip"] = host[0]
        servicePriorityItem["servicePriority"] = 9
        servicePriorityArr.append(servicePriorityItem)
        continue
    if host[3]:#icmp
        servicePriorityItem["ip"] = host[0]
        servicePriorityItem["servicePriority"] = 8
        servicePriorityArr.append(servicePriorityItem)
        continue
    if host[4]:#dns
        servicePriorityItem["ip"] = host[0]
        servicePriorityItem["servicePriority"] = 7
        servicePriorityArr.append(servicePriorityItem)
        continue
    if host[5]:#http
        servicePriorityItem["ip"] = host[0]
        servicePriorityItem["servicePriority"] = 6
        servicePriorityArr.append(servicePriorityItem)
        continue
    if host[6]:#ftp
        servicePriorityItem["ip"] = host[0]
        servicePriorityItem["servicePriority"] = 5
        servicePriorityArr.append(servicePriorityItem)
        continue
    if host[7]:#tftp
        servicePriorityItem["ip"] = host[0]
        servicePriorityItem["servicePriority"] = 4
        servicePriorityArr.append(servicePriorityItem)
        continue
    if host[8]:#ntp
        servicePriorityItem["ip"] = host[0]
        servicePriorityItem["servicePriority"] = 3
        servicePriorityArr.append(servicePriorityItem)
        continue
    if host[9]:#pop3
        servicePriorityItem["ip"] = host[0]
        servicePriorityItem["servicePriority"] = 2
        servicePriorityArr.append(servicePriorityItem)
        continue
    if host[10]:#smtp
        servicePriorityItem["ip"] = host[0]
        servicePriorityItem["servicePriority"] = 1
        servicePriorityArr.append(servicePriorityItem)
        continue
#如果都不是，不用管，默认的权重就是0
for host in servicePriorityArr:
    try:
        cursor.execute("""
            update "%s"."Host" set "servicePriority"= :servicePriority where "IP"= :hostIp
                """ % db_username,servicePriority = host["servicePriority"],hostIp = host["ip"])
    except:
        print('error when updating')
        error_info = sys.exc_info()
        if len(error_info) > 1:
            print(str(error_info[0]) + ' ' + str(error_info[1]))
        sys.exit(1)

#6.计算总权值并更新
print('6.计算总权值及更新阶段')
try:
    cursor.execute("""
        select "IP" as "tIP","serviceWeight" as "tserviceWeight","trafficWeight" as "ttrafficWeight","frequencyWeight" as "tfrequencyWeight",
        "portNumWeight" as "tportNumWeight","servicePriority" as "tservicePriority","osWeight" as "tosweight" from "%s"."Host" where "isAgent"=0 and "HisDel"= 0
            """ % db_username)
except:
    print('error when selecting')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)
result = cursor.fetchall()
targetWeightArr = []
for host in result:
    targetWeightItem = {}
    #host[0]: ip; host[1]: tserviceWeight; host[2]: ttrafficWeight; host[3]: tfrequencyWeight
    #host[4]: tportNumWeight; host[5]: tservicePriority; host[6]: tosweight
    #计算得到的总权值四舍五入
    tmp_weight = round(0.1 * host[1] + 0.2 * host[2] + 0.2 * host[3] + 0.1 * host[4] + 0.3 * host[5] + 0.1 * host[6])
    targetWeightItem["ip"] = host[0]
    targetWeightItem["Hweight"] = tmp_weight
    targetWeightArr.append(targetWeightItem)
for host in targetWeightArr:
    try:
        cursor.execute("""
            update "%s"."Host" set "Hweight"= :Hweight where "IP"= :hostIp
                """ % db_username,Hweight = host["Hweight"],hostIp = host["ip"])
    except:
        print('error when updating')
        error_info = sys.exc_info()
        if len(error_info) > 1:
            print(str(error_info[0]) + ' ' + str(error_info[1]))
        sys.exit(1)
#决策阶段0（提取具有参选资格的节点并获取它们的网络号并在数据库中更新，为正式选举阶段作准备）
print('***********决策阶段0（准备工作）*************')
#考虑所有isAgent为0且HisDel为0的节点，且Subnet为空，已经获取过子网地址的就不要再去获取了，减少通信的压力
try:
    cursor.execute("""
        select "IP" as "tIP" from "%s"."Host" where "isAgent"=0 and "HisDel"=0 and "Subnet" is null 
    """ % db_username)
except:
    print('error when selecting')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)
result = cursor.fetchall()
CandidateIP = []#候选的IP（可能成为新的agent的ip）
if result:
    for host in result:
        c_ip = host[0]#host[0]为ip地址字符串
        CandidateIP.append(c_ip)
#此时CandidateIP中存放的是所有待选ip，准备获取它们的网络号
#下面将CandidateIP中的内容写入json文件中（candidateIP.json）
result = {}
c_ip_list = []
if CandidateIP:
    for ip in CandidateIP:
        c_ip_list.append(ip)
    result["hosts"] = c_ip_list
else:
    try:
        with open("candidateIP.json","w") as f:
            print('没有符合要求的待选IP，全部决策过程结束（不要调用后面的东西了）,json文件为空')
    except:
        print('error when overwriting')
        error_info = sys.exc_info()
        if len(error_info) > 1:
            print(str(error_info[0]) + ' ' + str(error_info[1]))
        sys.exit(1)
try:
    with open("candidateIP.json","w") as f:
        json.dump(result,f)
        print('本轮所有的可能的待选ip存储完成')
except:
    print('error when  saving result')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)
print('**************第一部分结束***************')
conn.commit()
cursor.close()
conn.close()
sys.exit(0)#just test
