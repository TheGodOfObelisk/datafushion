#继续main.py部分的功能，完成全部决策
import os,sys,re,json
import cx_Oracle
from socket import inet_aton, inet_ntoa
from struct import unpack, pack

def _check_ip(ip_add):#检验ip地址字符串是否合法
    """
    common func
    """
    p = re.compile(r'^(([01]?[\d]{1,2})|(2[0-4][\d])|(25[0-5]))' \
                   r'(\.(([01]?[\d]{1,2})|(2[0-4][\d])|(25[0-5]))){3}(\/(\d+))?$')

    return p.search(str(ip_add)) is not None


def calcSubnet(ip_add, mask):#根据ip地址和子网掩码计算子网地址（不带网络前缀的形式），如192.168.1.128
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

def NumberOf1(n):#计算某个10进制数转换为2进制数之后，其中1的个数
    if n< 0:
        n = n&0xffffffff
    count = 0
    while n:
        count += 1
        n = (n-1)&n
    return count

def mask2prefix(mask):#输入为字符串（子网掩码），输出为整数（网络前缀），错误处理欠缺
    prefix = 0
    res = mask.split('.',3)
    for item in res:
        prefix += NumberOf1(int(item))
    return prefix



#第一个参数，含子网的json文件
#第二个参数，数据库连接信息
comnand_arguments = sys.argv
if not (len(comnand_arguments)==3):
    print('error:incorrect argument')
    sys.exit(1)
filename = comnand_arguments[1]
dbconfigs = comnand_arguments[2]

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

#读出带掩码的json文件中信息
#暂时认为输入的是json文件，如果不是的话再改
#json格式，示例：
#{'hosts': [{'ip': '192.168.1.52', 'mask': '255.255.255.0'}, {'ip': '192.168.1.123', 'mask': '255.255.255.128'}, {'ip': '192.168.1.157', 'mask': '255.255.255.0'}]}
with open(filename,"r") as load_f:
    load_dict = json.load(load_f)
    print(load_dict)

ip_mask = []#存放ip和mask对
for item in load_dict['hosts']:
    print(item)
    ip_mask.append(item)
print(ip_mask)
#这里ip_mask和load_dict['hosts']等同，不管输入是什么形式，都把它转化为ip_mask的这种形式，方便后续处理
prefix = 0
for item in ip_mask:
    #计算该节点所属的子网地址（带网络前缀的形式），如192.168.1.128/25
    prefix = mask2prefix(item["mask"])
    tmp_sub = calcSubnet(item["ip"],item["mask"])
    if tmp_sub == False:
        print("error: incorrect format of ip or netmask, ignore it")
        continue
    subnet = tmp_sub + '/' + str(prefix)
    #算出子网，下一步准备写数据库（只更新它们的子网字段）
    try:
        cursor.execute("""
        update "{username}"."Host" set "Subnet"=:sb where "IP"=:ip
        """.format(username=db_username),sb=subnet,ip=item["ip"])
    except:
        print("Error:can not update a specified ip's subnet")
        error_info = sys.exc_info()
        if len(error_info) > 1:
            print(str(error_info[0]) + ' ' + str(error_info[1]))
    print(subnet)

# Host 表增加Subnet字段 ××××
# 检验选举出的ip是否有效
# 已确定在同一个子网内的节点，仅部署1个agent
# 可能在同一个子网内的节点，仅部署1个agent

# 下面修改后的部分未经测试
try:
    cursor.execute("""
        select distinct "Net" from "%s"."Agent"
        """ %db_username)
except:
    print('error when selecting')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)
result_netfields = cursor.fetchall()# result_netfields中存放已经被选举为agent的主机所属的网段
print('已经有agent的子网：')
print(result_netfields)

#决策阶段1（选举）
print('***********决策阶段1（选举）*************')

hasNewHosts = 0#标志决策结果是否为新节点
#首先选取同时满足isAgent=0和isNew=1的节点
try:
    cursor.execute("""
        select "IP" as "tIP","Hweight" as "tHweight", "Subnet" as "tSubnet"  from "%s"."Host" where "isAgent"= 0 and "isNew"= 1 and "HisDel"= 0 ORDER BY "Hweight" DESC  
            """ % db_username)
except:
    print('error when selecting')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)
result = cursor.fetchall()
AgentIP = []
NewNetFields = [] #确定的新agent的网段存在这里，方便最后更新Agent表
HighestWeight = 0#标志最高权重
HasThisNetField = 0;
if result:
    for host in result:
        objItem = {}
        #host[0]代表主机IP，host[1]代表主机权重
        #host[2]代表主机所属子网地址
        objItem["ip"] = host[0]
        objItem["Hweight"] = host[1]
        NetField = host[2]
        for item in result_netfields:# 检查此ip所属子网是否已经有选举出来的agent
            if NetField == item:
                # 一个子网最多有一个agent
                HasThisNetField = 1
                break
            elif HasThisNetField == 1:
                HasThisNetField = 0
        if HasThisNetField  == 1:
            continue
        if not AgentIP:#能走到这里的不仅是新节点而且属于新子网
            AgentIP.append(objItem["ip"])
            HighestWeight = objItem["Hweight"]
            NewNetFields.append(NetField)
        elif HighestWeight == objItem["Hweight"]:# AgentIP已经有内容，并与已有内容并列第一的
            AgentIP.append(objItem["ip"])
            NewNetFields.append(NetField)
        else:
            break
    if AgentIP:
        print('在新节点中决策出子节点')
        hasNewHosts = 1
    else:
        print('新节点中没有满足要求的子节点')
        hasNewHosts = 0#需要进入旧节点中决策。。
#倘若无新节点或者新节点中没有满足要求的子节点
if not result or not AgentIP:
    print('在旧节点中决策')
    try:
        cursor.execute("""
            select "IP" as "tIP", "Hweight" as "tHweight", "Subnet" as "tSubnet" from "%s"."Host" where "isAgent" = 0 and "isNew" = 0 and "HisDel" = 0 ORDER BY "Hweight" DESC           
            """ % db_username)
    except:
        print('error when selecting')
        error_info = sys.exc_info()
        if len(error_info) > 1:
            print(str(error_info[0]) + ' ' + str(error_info[1]))
        sys.exit(1)
    result = cursor.fetchall()
    HasThisNetField = 0#reinitialization
    if result:
        for host in result:
            objItem = {}
            #host[0]代表主机IP，host[1]代表主机权重
            #host[2]代表主机所属子网地址
            objItem["ip"] = host[0]
            objItem["Hweight"] = host[1]
            NetField = host[2]
            for item in result_netfields:# 检查此ip所属子网是否已经有选举出来的agent
                if NetField == item:
                    HasThisNetField = 1
                    break
                elif HasThisNetField == 1:
                    HasThisNetField = 0
            if HasThisNetField == 1:
                continue
            if not AgentIP:
                AgentIP.append(objItem["ip"])
                HighestWeight = objItem["Hweight"]
                NewNetFields.append(NetField)
            elif HighestWeight == objItem["Hweight"]:
                AgentIP.append(objItem["ip"])
                NewNetFields.append(NetField)
            else:
                break
        if AgentIP:
            print('在旧节点中决策出子节点')
            hasNewHosts = 0
        else:
            print('旧节点中没有满足需要的子节点，决策失败')
            hasNewHosts = 0

#注意，这里的AgentIP如果有内容的话，可能有多个属于同一个网段的，要去除重复的
FinalAgentIP = []#用于存放最终筛选剩下的
SubnetTmp = []#辅助数组
if AgentIP:
    print('筛去同一网段的')
    for item in AgentIP:
        try:
            cursor.execute("""
            select "Subnet" from "%s"."Host" where "IP"=:ip
            """ % db_username,ip=item)
        except:
            print('error when selecting')
            error_info = sys.exc_info()
            if len(error_info) > 1:
                print(str(error_info[0]) + ' ' + str(error_info[1]))
            sys.exit(1)
        result = cursor.fetchall()
        if result:
            if result[0][0] not in SubnetTmp:#ETC: result [('36.110.171.0/24',)] result[0] ('36.110.171.0/24') 36.110.171.0/24
                SubnetTmp.append(result[0][0])
                FinalAgentIP.append(item)

print('最终选出来的是：')
print(FinalAgentIP)
#上面的内容尚未作详细测试
#更新部分要增加Agents表的更新
#决策阶段2（更新）
print('***********决策阶段2（更新）*************')
if FinalAgentIP:#如果决策不出来一切都免谈
    print('将所有节点的isNew字段置为0，HisDel字段置为1')
    try:
        cursor.execute("""
            update "%s"."Host" set "isNew"= 0,"HisDel"= 1
            """ % db_username)
    except:
        print('error when updating')
        error_info = sys.exc_info()
        if len(error_info) > 1:
            print(str(error_info[0]) + ' ' + str(error_info[1]))
        sys.exit(1)

#这个语句还没测
print('更新Agent表添加子网')
if SubnetTmp:
    for net in SubnetTmp:
        try:
            cursor.execute("""
            insert into "{username}"."Agent" values(:sb)
            """.format(username=db_username),sb=net)
        except:
            print('error when inserting')
            error_info = sys.exc_info()
            if len(error_info) > 1:
                print(str(error_info[0]) + ' ' + str(error_info[1]))
            sys.exit(1)

#将所有的在已经有agent的网段内的主机的isAgent置为2，且在这之前，它们的isAgent字段值为0
#这个语句还没测，恐怕不行
try:
    cursor.execute("""
        update "{username}"."Host" set "isAgent"=2 where "isAgent"=0 and "Subnet" in(
        select "Net" from "{username}"."Agent"
        )""".format(username=db_username))
except:
    print('error when updating')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)

#把真正选上了的isAgent置为1
for ip in FinalAgentIP:
    try:
        cursor.execute("""
        update "%s"."Host" set "isAgent"=1 where "IP"=:newIndividualAgentIP 
        """ % db_username,newIndividualAgentIP = ip)
    except:
        print('error when updating')
        error_info = sys.exc_info()
        if len(error_info) > 1:
            print(str(error_info[0]) + ' ' + str(error_info[1]))
        sys.exit(1)

print('****************决策结束*****************')



# 根据子网内容设置主动探测参数
# 保存决策结果
#下面的未经测试
result = {}
task_list = []
if FinalAgentIP:
    ahost = []
    phost = []
    activearg = ""
    for ip in AgentIP:
        ahost.append(ip + ":" + "8082")
        phost.append(ip + ":" + "8081")
        try:
            cursor.execute("""
            select "Subnet" from "%s"."Host" where "IP"=:tip
            """ % db_username, tip=ip)
        except:
            print('error when selecting')
            error_info = sys.exc_info()
            if len(error_info) > 1:
                print(str(error_info[0]) + ' ' + str(error_info[1]))
            sys.exit(1)
        res = cursor.fetchall()
        activearg = res[0][0]#主动探测参数
    if activearg == "":
        print('error: incorrect active argument or no appropriate subnet content')
        sys.exit(1)
    task1 = {
        "type":"activeDetection",
        #"taskArguments":"192.168.0.1/24",
    }
    task1["taskArguments"]=activearg
    task2 = {
        "type": "passiveDetection",
        "taskArguments": "-G 600",
    }
    task1["hosts"] = ahost
    task2["hosts"] = phost
    task_list.append(task1)
    task_list.append(task2)
result["tasks"] = task_list
result["hasNewHosts"] = hasNewHosts
try:
    with open("result.json","w") as f:
        json.dump(result,f)
        print("结果存储完成")
except:
    print('error when saving result')
    error_info = sys.exc_info()
    if len(error_info) > 1:
        print(str(error_info[0]) + ' ' + str(error_info[1]))
    sys.exit(1)


conn.commit()
cursor.close()
conn.close()

