#coding:utf-8
from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains 
from selenium.webdriver.common.keys import Keys 
import time
from Browser_ipvt import *


def main():
	browser_ipvt=Browser_ipvt('http://account.ipvideotalk.com/login/') 
	browser_ipvt.openBrowser()
	browser_ipvt.login()
	browser_ipvt.scheduleconfer()
	browser_gvc.quitBrowser()


if __name__ == '__main__':
	main()

