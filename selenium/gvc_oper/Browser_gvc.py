#coding:utf-8
from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains #引入ActionChains鼠标操作类
from selenium.webdriver.common.keys import Keys #引入keys类操作
import time
import sys

class Browser_gvc(object):
	"""This is user class."""
	url=""
	browser=""
	conf_url=""

	def applyDNS(self): 
		self.browser.find_element_by_id('advset_menu').click()
		time.sleep(1)
		self.browser.find_element_by_xpath(".//*[@id='account2_general']").click()
		time.sleep(2)

		frame = self.browser.find_element_by_xpath('.//*[@id="iframediv"]')
		self.browser.switch_to_frame(frame)
		self.browser.find_element_by_xpath('.//*[@id="enableiptalkpro"]').click()
		time.sleep(1)
		self.browser.find_element_by_id('a_save').click() 
		time.sleep(2)
		self.browser.switch_to_default_content()
		self.browser.find_element_by_id('apply').click()
		time.sleep(10)

		frame = self.browser.find_element_by_xpath('.//*[@id="iframediv"]')
		self.browser.switch_to_frame(frame)
		self.browser.find_element_by_xpath('.//*[@id="enableiptalkpro"]').click()
		time.sleep(1)
		self.browser.find_element_by_id('a_save').click() 
		time.sleep(2)
		self.browser.switch_to_default_content()
		self.browser.find_element_by_id('apply').click()
		time.sleep(10)
		print "apply dns!"

	def correctDNS(self,dns4):
		self.browser.find_element_by_id('advset_menu').click() 
		self.browser.find_element_by_class_name('m_advavset_net').click()
		time.sleep(2)
		frame = self.browser.find_element_by_xpath('.//*[@id="iframediv"]')
		self.browser.switch_to_frame(frame)
		self.browser.find_element_by_id('prednsser4').clear()
		self.browser.find_element_by_id("prednsser4").send_keys(dns4)
		self.browser.find_element_by_id('a_save').click() 
		time.sleep(2)
		self.browser.switch_to_default_content()
		print "correct dns!"



	def OpenConfer(self):
		self.browser.find_element_by_id('call_call').click()
		time.sleep(1)
		frame = self.browser.find_element_by_xpath('.//*[@id="callframediv"]')
		self.browser.switch_to_frame(frame) 
		self.browser.find_element_by_id('acct2name').click()
		time.sleep(1)
		self.browser.find_element_by_id('dialnow').click()
		print "Now openning a new conference!"
		time.sleep(10)
		self.browser.switch_to_default_content()
		

	def closeCurrentConfer(self):
		if self.browser.find_element_by_id('incomingcall').is_displayed():
			frame = self.browser.find_element_by_xpath('.//*[@id="incomingcall"]')
			self.browser.switch_to_frame(frame)
			self.browser.find_element_by_id('close').click()  
			time.sleep(2)
			self.browser.switch_to_default_content()
			print "The current conference has closed!"
		else:
			print "There is no conference in the process!"


	def judgeConferStatus(self):
		if self.browser.find_element_by_id('incomingcall').is_displayed():
			frame = self.browser.find_element_by_xpath('.//*[@id="incomingcall"]')
			self.browser.switch_to_frame(frame)
			isshow=self.browser.find_element_by_id('details').get_attribute("isshow")
			if str(isshow)=="1":
				print "There is one conference in the process!"
				self.browser.find_element_by_id('details').click()
				print self.browser.find_element_by_id('ipvconfurl').text
			else: 
				print "The current conference is failed!" 
			self.browser.switch_to_default_content()
		else:
			print "There is no conference in the process!"
		

 
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
		self.browser.find_element_by_id('username').send_keys(u'admin')
		self.browser.find_element_by_class_name('password').send_keys(u'admin')
		self.browser.find_element_by_id('loginbtn').click() 
		time.sleep(1)
		print "Has already login in as admin!"



def main():
	browser_gvc=Browser_gvc('http://192.168.126.105/') 
	browser_gvc.openBrowser()
	browser_gvc.login()
	browser_gvc.judgeConferStatus()
	browser_gvc.closeCurrentConfer()
	# browser_gvc.OpenConfer()
	# browser_gvc.judgeConferStatus()
	browser_gvc.correctDNS(120)
	browser_gvc.applyDNS()
	browser_gvc.quitBrowser()

if __name__ == '__main__':
	main()

