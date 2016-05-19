#coding:utf-8
from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains 
from selenium.webdriver.common.keys import Keys 
import time
from Browser_gvc import *


def main():
	browser_gvc=Browser_gvc('http://192.168.126.105/')
	browser_gvc.openBrowser()
	browser_gvc.login()


if __name__ == '__main__':
	main()

