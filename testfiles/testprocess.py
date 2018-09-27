# print('hello world')
# import json
# data = [{'a':1,'b':2}]
# json = json.dumps(data)
# print json

import sys
import time
print "the script name is ", sys.argv[0]
i =0
while i < 5:
    time.sleep(1)
    print(i)
    i += 1
