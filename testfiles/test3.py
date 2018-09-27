def dec2bi(dec):
    result = ''
    if dec:
        result = dec2bi(dec // 2)
        return result + str(dec % 2)
    else:
        return result
# print(dec2bi(255))

test_mask  = "255.255.255.192"
# res = test_mask.split('.',3)
# print(res)
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

res = mask2prefix(test_mask)
print(res)
# res = NumberOf1(255)
# print(res)