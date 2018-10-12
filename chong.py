# -*- coding: utf-8 -*-
"""
Created on Fri Oct 12 20:37:34 2018

@author: acely
"""
import urllib2
import urllib
from bs4 import BeautifulSoup
import sys
reload(sys)
sys.setdefaultencoding('utf8')
html = urllib2.urlopen("https://dealer.autohome.com.cn/frame/spec/32014/110000/110100/0.html?isPage=1&amp;source=www.baidu.com").read()
soup = BeautifulSoup(html,"html5lib")
res = soup.findAll('span',attrs = {"class":"nbg"})
print res