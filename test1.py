import cx_Oracle
import socket
# import json
import sys

#test of calculate subnet
import re
from socket import inet_aton, inet_ntoa
from struct import unpack, pack
#如何获取ip与掩码对
netmask = '255.255.255.128'
testip = '192.168.1.196'

def dec2bi(dec):
    result = ''
    if dec:
        result = dec2bi(dec // 2)
        return result + str(dec % 2)
    else:
        return result
print(dec2bi(255))

def mask2prefix(mask):
    return

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
                declare
                    isAgent "{username}"."Host"."isAgent"%TYPE;
                begin
                    select "isAgent" into isAgent from "{username}"."Host" where "IP"=:ip;
                        case isAgent
                            when 0 then
                                update "{username}"."Host" set "isAgent"=1,"isNew"=0,"HisDel"=0;
                            when 1 then
                                update "{username}"."Host" set "isNew"=0,"HisDel"=0;
                        end case;
                exception
                        when NO_DATA_FOUND then
                            insert into "{username}"."Host" values(:ip,0,0,0,NULL,0,NULL,NULL,0,NULL,
                                                0,0,1,0,0,0,0,0,0,NULL);
                end;
            """.format(username=un), ip=localip)
except:
    print("Error:can not reinitialize database")
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
conn.commit()
