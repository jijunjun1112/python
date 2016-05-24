#coding:utf-8
from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains #引入ActionChains鼠标操作类
from selenium.webdriver.common.keys import Keys #引入keys类操作
import time
import sys

class Browser_ipvt(object):
	"""This is user class."""
	url=""
	browser=""
	conf_url=""

	def scheduleconfer(self):
		self.browser.find_element_by_id("scheduleMeeting").click()
		time.sleep(1)
		self.browser.find_element_by_id("meetingTheme").send_keys("sunny")
		self.browser.find_element_by_id("proAccount").send_keys("8200433")
		self.browser.find_element_by_xpath(".//*[@class='btn btn-blue meetingSubmit']").click()

		time.sleep(1)

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
	

	def login(self):
		self.browser.find_element_by_id("uerName").send_keys("jijunjun1112")
		self.browser.find_element_by_id("password").send_keys("Jun13676830606")
		self.browser.find_element_by_xpath(".//*[@id='loginForm']/div[4]/button").click()
		time.sleep(1)
		print "Has already login in as jijunjun1112!"



def main():
	browser_ipvt=Browser_ipvt('http://account.ipvideotalk.com/login/') 
	browser_ipvt.openBrowser()
	browser_ipvt.login()
	browser_ipvt.scheduleconfer()

	browser_ipvt.quitBrowser()

if __name__ == '__main__':
	main()

