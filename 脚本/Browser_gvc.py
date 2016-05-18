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

	def openPresent(self):
		if self.browser.find_element_by_id('incomingcall').is_displayed():
			frame = self.browser.find_element_by_xpath('.//*[@id="incomingcall"]')
			self.browser.switch_to_frame(frame)


			for x in xrange(1,1000):

				self.browser.find_element_by_id('confcontrol').click()
				time.sleep(1)
				self.browser.find_element_by_id('present').click()
				time.sleep(0.5)
				self.browser.find_element_by_id('presentlist').click()
				time.sleep(1)
				self.browser.find_element_by_xpath(".//*[@id='presentlist']/div/ul/li[2]").click() #choose pc, open presentation
				self.browser.find_element_by_id("presentsave").click()
				print "Open presentation!"

				time.sleep(5) #after 180s, close presentation	 

				self.browser.find_element_by_id('present').click()
				time.sleep(0.5)
				self.browser.find_element_by_id('presentlist').click()
				time.sleep(1)
				self.browser.find_element_by_xpath(".//*[@id='presentlist']/div/ul/li[3]").click() #choose close, close presentation
				self.browser.find_element_by_id("presentsave").click()
				print "Close presentation!"

				time.sleep(5)

			self.browser.switch_to_default_content()
		else:
			print "There is no conference in the process!"

	def openScheduledConfer(self):
		self.browser.find_element_by_id('apps_menu').click()
		time.sleep(2)
		self.browser.find_element_by_xpath(".//*[@id='apps_li']/li[2]/span").click()
		time.sleep(1)

		frame = self.browser.find_element_by_xpath('.//*[@id="iframediv"]')
		self.browser.switch_to_frame(frame)
		# print self.browser.find_element_by_id('itemsdiv').is_displayed()
		if(self.browser.find_element_by_id('itemsdiv').is_displayed()==False):
			print "There is no scheduled conference!"
		else:
			print "There is sheduled conference!"
			element=self.browser.find_element_by_class_name('datechild')
			ActionChains(self.browser).move_to_element(element).perform() 
			time.sleep(1)
			self.browser.find_element_by_id('startbtn').click() 
			print "Now openning this sheduled conference!"
			time.sleep(6)
		self.browser.switch_to_default_content()

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
		print "Now close Current conference!"
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
		print "Now judge the conference status!"
		if self.browser.find_element_by_id('incomingcall').is_displayed():
			frame = self.browser.find_element_by_xpath('.//*[@id="incomingcall"]')
			self.browser.switch_to_frame(frame)

			# judge some element here .....

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
		print "Now login in as admin!"
		time.sleep(5)



def main():
	browser_gvc=Browser_gvc('http://192.168.126.105/') 
	browser_gvc.openBrowser()
	browser_gvc.login()
	# browser_gvc.judgeConferStatus()
	# browser_gvc.closeCurrentConfer()
	# browser_gvc.OpenConfer()

	browser_gvc.correctDNS("120")
	browser_gvc.applyDNS()
	browser_gvc.quitBrowser()

if __name__ == '__main__':
	main()

