import re
def exchange_maskint(mask_int):
	bin_arr = ['0' for i in range(32)]
	for i in range(mask_int):
		bin_arr[i] = '1'
	tmpmask = [''.join(bin_arr[i * 8:i * 8 + 8]) for i in range(4)]
	tmpmask = [str(int(tmpstr, 2)) for tmpstr in tmpmask]
	return '.'.join(tmpmask)

subnet = '192.168.0.0/28'
prefix = (subnet.split('/',1))[1]
print(prefix)
print(exchange_maskint(int(prefix)))


args = "hello ['das'] av"
str = args.split()
command = str[0]
print(command)

test_args = "['192.168.1.133','192.168.1.134','192.168.1.135']"
reg = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
for item in test_args:
	print(item)
res = re.findall(reg, test_args)
print(res)