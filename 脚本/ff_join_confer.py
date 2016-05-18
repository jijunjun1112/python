#coding:utf-8
from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains #引入ActionChains鼠标操作类
from selenium.webdriver.common.keys import Keys #引入keys类操作
import time
from Browser_webrtc import *

conf_id=sys.argv[1]
ff_name=sys.argv[2]
conf_url="https://meetings.ipvideotalk.com/"+conf_id

def main():
	browser_webrtc=Browser_webrtc(conf_url) 
	browser_webrtc.openBrowser()
	browser_webrtc.login(ff_name)

if __name__ == '__main__':
	main()

