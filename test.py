import cx_Oracle
import socket
import json
import sys

#test of calculate subnet
import re
from socket import inet_aton, inet_ntoa
from struct import unpack, pack
netmask = '255.255.255.128'
testip = '192.168.1.196'


def _check_ip(ip_add):
    """
    common func
    """
    p = re.compile(r'^(([01]?[\d]{1,2})|(2[0-4][\d])|(25[0-5]))' \
                   r'(\.(([01]?[\d]{1,2})|(2[0-4][\d])|(25[0-5]))){3}(\/(\d+))?$')

    return p.search(str(ip_add)) is not None


def calcSubnet(ip_add, mask):
    """
    Return the sub net of the network
    eisoopylib.calcSubnet("192.168.0.1", "255.255.255.0")
    192.168.0.0
    etc.
    """
    if _check_ip(ip_add) and _check_ip (mask):
        ip_num, = unpack("!I", inet_aton(ip_add))
        mask_num, = unpack("!I", inet_aton(mask))
        subnet_num = ip_num & mask_num
        return inet_ntoa (pack ("!I", subnet_num))
    else:
        return False

res = calcSubnet(testip, netmask)
if res:
    print(res)
else:
    print('error occurred during calculating subnet address')


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

conn =cx_Oracle.connect('test/test@192.168.1.52:1521/ORCL')
print(localip)
cursor = conn.cursor()

un = "TEST"

try:
    cursor.execute("""
        update "TEST"."Host" set "isAgent"=2 where "isAgent"=0 and "Subnet" in(
        select "Net" from "TEST"."Agent"
        )
        """)
except:
    print('error when updating')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)



# AgentIP = []
# FinalAgentIP = []
# SubnetTmp = []
# sb = "36.110.171.1/24"
# SubnetTmp.append(sb)
# iptt = "36.110.171.43"
# AgentIP.append(iptt)
# print(AgentIP)
# for item in AgentIP:
#     print(item)
# if AgentIP:
#     print('筛去同一网段的')
#     for item in AgentIP:
#         try:
#             cursor.execute("""
#             select "Subnet" from "TEST"."Host" where "IP"=:ip
#             """ ,ip=item)
#         except:
#             print('error when selecting')
#             error_info = sys.exc_info()
#             if len(error_info) > 1:
#                 print(str(error_info[0]) + ' ' + str(error_info[1]))
#             sys.exit(1)
#         result = cursor.fetchall()
#         print(result)
#         print(result[0][0])#ETC: result [('36.110.171.0/24',)] result[0] ('36.110.171.0/24') 36.110.171.0/24
#         if result[0][0] not in SubnetTmp:
#             SubnetTmp.append(result[0][0])
#             FinalAgentIP.append(item)
#
# print(SubnetTmp)
# print(FinalAgentIP)

# with open("config.json","r") as load_f:
#     load_dict = json.load(load_f)
#     print(load_dict)
#     host = load_dict['tasks'][0]['hosts'][0]
#     print(host)
#     s_index = host.find(':')
#     host_ip = host[0:s_index]
#     print(host_ip)
#     try:
#         cursor.execute("""
#             declare
#                 isAgent "{username}"."Host"."isAgent"%TYPE;
#             begin
#                 select "isAgent" into isAgent from "{username}"."Host" where "IP"=:ip;
#                     case isAgent
#                         when 0 then
#                             update "{username}"."Host" set "isAgent"=1,"isNew"=0,"HisDel"=0;
#                         when 1 then
#                             update "{username}"."Host" set "isNew"=0,"HisDel"=0;
#                     end case;
#             exception
#                     when NO_DATA_FOUND then
#                         insert into "{username}"."Host" values(:ip,0,0,0,NULL,0,NULL,NULL,0,NULL,
#                                             0,0,1,0,0,0,0,0,0);
#             end;
#         """.format(username=un),ip=host_ip)
#     except:
#         print("Error:can not initialize database")
#         error_info = sys.exc_info()
#         if len(error_info) > 1:
#             print(str(error_info[0]) + ' ' + str(error_info[1]))

# localname = socket.gethostname()
# ip = socket.gethostbyname(localname)
# print(ip)



# try:
#     cursor.execute("""
#                 declare
#                     isAgent "{username}"."Host"."isAgent"%TYPE;
#                 begin
#                     select "isAgent" into isAgent from "{username}"."Host" where "IP"=:ip;
#                         case isAgent
#                             when 0 then
#                                 update "{username}"."Host" set "isAgent"=1,"isNew"=0,"HisDel"=0;
#                             when 1 then
#                                 update "{username}"."Host" set "isNew"=0,"HisDel"=0;
#                         end case;
#                 exception
#                         when NO_DATA_FOUND then
#                             insert into "{username}"."Host" values(:ip,0,0,0,NULL,0,NULL,NULL,0,NULL,
#                                                 0,0,1,0,0,0,0,0,0,NULL);
#                 end;
#             """.format(username=un), ip=localip)
# except:
#     print("Error:can not reinitialize database")
#     error_info = sys.exc_info()
#     if len(error_info) > 1:
#         print(str(error_info[0]) + ' ' + str(error_info[1]))


# try:
#     cursor.execute("""
#         select "IP" as "tIP" from "TEST"."Host"
#     """)
# except:
#     print('error')
#     error_info = sys.exc_info()
#     if len(error_info) > 1:
#         print(str(error_info[0]) + ' ' + str(error_info[1]))
# result = cursor.fetchall()
# test_array = []
# if result:
#     for host in result:
#         print(host[0])
#         test_array.append(host[0])
# print(test_array)


# print('***********决策阶段0（准备工作）*************')
# #考虑所有isAgent为0且HisDel为0的节点
# try:
#     cursor.execute("""
#         select "IP" as "tIP" from "TEST"."Host"
#     """)
# except:
#     print('error when selecting')
#     error_info = sys.exc_info()
#     if len(error_info) > 1:
#         print(str(error_info[0]) + ' ' + str(error_info[1]))
#     sys.exit(1)
# result = cursor.fetchall()
# CandidateIP = []#候选的IP（可能成为新的agent的ip）
# if result:
#     for host in result:
#         c_ip = host[0]#host[0]为ip地址字符串
#         CandidateIP.append(c_ip)
#此时CandidateIP中存放的是所有待选ip，准备获取它们的网络号
#下面将CandidateIP中的内容写入json文件中（candidateIP.json）
# result = {}
# c_ip_list = []
# if CandidateIP:
#     for ip in CandidateIP:
#         c_ip_list.append(ip)
#     result["hosts"] = c_ip_list
# print(result)
# try:
#     with open("candidateIP.json","w") as f:
#         json.dump(result,f)
#         print("待选ip存储完成")
# except:
#     print('error when saving result')
#     error_info = sys.exc_info()
#     if len(error_info) > 1:
#         print(str(error_info[0]) + ' ' + str(error_info[1]))
#     sys.exit(1)

conn.commit()



# cursor.execute("""
#     select distinct "IP" from "STUDY"."Host"
# """)
# result = cursor.fetchall()
# test = "192.168.1.1"
# if test in result:
#     print("yes!")
# for host in result:
#     if test == host[0]:
#         print("yes!")
#     print(host)
# print(result)
# cursor.execute("""
# declare
# 		isDel "STUDY"."Host"."HisDel"%TYPE;
# begin
# 		select "HisDel" into isDel from "STUDY"."Host" where IP = 'DSADSA';
# 		case isDel
# 			when 0 then
# 				update "STUDY"."Host" set "HaddressFamily"= 'xxxx' where "IP"='74.125.204.138';
# 			when 1 then
# 				update "STUDY"."Host" set "HaddressFamily"= 'xxx' where "IP"='74.125.204.138';
# 		end case;
# exception
# 		when NO_DATA_FOUND then
# 			INSERT into "STUDY"."Host" VALUES('192.168.0.1',0,0,0,'X',0,'xx','xxx',0,'xxxx',0,0,0,0,0,0,0,0,0);
# end;
# """)
# cursor.execute("""
#                             declare
#                                 isDel "{username}"."Host"."HisDel"%TYPE;
#                             begin
#                                 select "HisDel" into isDel from "{username}"."Host" where IP =:ip;
#                                     case isDel
#                                         when 0 then
#                                             update "{username}"."Host" set
#                                             "HaddressFamily"=:addrfamily,"Hos"=:os,"Hdevice"=:devtype,"Hmac"=:mac,
#                                             "osWeight"=:osWeight,"HopenPortNum"=:opennum where "IP"=:ip;
#                                         when 1 then
#                                             update "{username}"."Host" set
#                                             "HserviceNum"=:serviceNum,"Htraffic"=:traffic,"Hfrequency"=:frequency,"Hos"=:os,"HopenPortNum"=:opennum,
#                                             "Hdevice"=:devtype,"Hmac"=:mac,"Hweight"=:weight,"HaddressFamily"=:addrfamily,"HisDel"=:isDel,
#                                             "isAgent" =:isAgent,"serviceWeight"=:serviceweight,"trafficWeight"=:trafficweight,
#                                             "frequencyWeight"=:frequencyweight,"portNumWeight"=:portNumweight,
#                                             "osWeight"=:osWeight,"servicePriority"=:servicePriority where "IP"=:ip;
#                                     end case;
#                             exception
#                                     when NO_DATA_FOUND then
#                                         insert into "{username}"."Host" values(:ip,:serviceNum,:traffic,:frequency,:os,:opennum,:devtype,:mac,:weight,:addrfamily,
#                                         :isDel,:isNew,:isAgent,:serviceweight,:trafficweight,:frequencyweight,:portNumweight,:osWeight,:servicePriority);
#                             end;
#                         """.format(username='STUDY'),ip='192.168.0.2', serviceNum=0, traffic=0, frequency=0, os='WINDOWS',
#                                        opennum=0, devtype='X', mac='XX',
#                                        weight=0, addrfamily='XXX',isDel=0, isNew=1, isAgent=0,
#                                        serviceweight=0, trafficweight=0, frequencyweight=0,
#                                        portNumweight=0, osWeight=1, servicePriority=0)
# print("""
#                             declare
#                                 isDel "{username}"."Host"."HisDel"%TYPE;
#                             begin
#                                 select "HisDel" into isDel from "{username}"."Host" where IP ={ip};
#                                     case isDel
#                                         when 0 then
#                                             update "{username}"."Host" set
#                                             "HaddressFamily"={addrfamily},"Hos"={os},"Hdevice"={devtype},"Hmac"={mac},
#                                             "osWeight"={osWeight},"HopenPortNum"={opennum} where "IP"={ip};
#                                         when 1 then
#                                             update "{username}"."Host" set
#                                             "HserviceNum"={serviceNum},"Htraffic"={traffic},"Hfrequency"={frequency},"Hos"={os},"HopenPortNum"={opennum},
#                                             "Hdevice"={devtype},"Hmac"={mac},"Hweight"={weight},"HaddressFamily"={addrfamily},"HisDel"={isDel},
#                                             "isAgent" ={isAgent},"serviceWeight"={serviceweight},"trafficWeight"={trafficweight},
#                                             "frequencyWeight"={frequencyweight},"portNumWeight"={portNumweight},
#                                             "osWeight"={osWeight},"servicePriority"={servicePriority} where "IP"={ip};
#                                     end case;
#                             exception
#                                     when NO_DATA_FOUND then
#                                         insert into "{username}"."Host" values({ip},{serviceNum},{traffic},{frequency},{os},{opennum},{devtype},{mac},{weight},
#                                         {addrfamily},{isDel},{isNew},{isAgent},{serviceweight},{trafficweight},{frequencyweight},{portNumweight},{osWeight},{servicePriority});
#                             end;
#                         """.format(username='STUDY',ip='192.168.0.2', serviceNum=0, traffic=0, frequency=0, os='WINDOWS',
#                                        opennum=0, devtype='X', mac='XX',
#                                        weight=0, addrfamily='XXX',isDel=0, isNew=1, isAgent=0,
#                                        serviceweight=0, trafficweight=0, frequencyweight=0,
#                                        portNumweight=0, osWeight=1, servicePriority=0))

