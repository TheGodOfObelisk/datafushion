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