#coding:utf-8
from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains #引入ActionChains鼠标操作类
from selenium.webdriver.common.keys import Keys #引入keys类操作
import time
import sys

class Browser_webrtc(object):
	"""This is user class."""
	url=""
	browser=""
	conf_url=""

	def __init__(self, url):
		self.url = url

	def showClassName(self):
		print self.__class__.__name__

	def showClassDoc(self):
		print self.__class__.__doc__

	def quitBrowser(self):
		self.browser.quit()
		print "Now quit the browser"

	def openBrowser(self):
		self.browser= webdriver.Firefox()
		self.browser.get(self.url)
		self.browser.maximize_window() 
		time.sleep(1) 
		print "Open gvc client web!"
	

	def login(self,name):
		self.browser.find_element_by_name("userName").send_keys(name)
		self.browser.find_element_by_name("email").send_keys(name+"@test.com")
		self.browser.find_element_by_id("joinButton").click()
		time.sleep(1)
		print "Has already login in as admin!"

def main():
	browser_webrtc=Browser_webrtc('https://meetings.ipvideotalk.com/165464995') 
	browser_webrtc.openBrowser()
	browser_webrtc.login("ff1")

	# browser_webrtc.quitBrowser()

if __name__ == '__main__':
	main()

