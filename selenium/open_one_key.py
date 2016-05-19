#coding:utf-8
from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains #引入ActionChains鼠标操作类
from selenium.webdriver.common.keys import Keys #引入keys类操作
import time
from Browser_gvc import *

    
def main():

    browser_gvc=Browser_gvc('http://192.168.126.105/') 
    browser_gvc.openBrowser()
    browser_gvc.login()
    browser_gvc.judgeConferStatus()
    browser_gvc.closeCurrentConfer()
    browser_gvc.OpenConfer()
    browser_gvc.judgeConferStatus()
    browser_gvc.quitBrowser()


if __name__ == '__main__': 
    main()
