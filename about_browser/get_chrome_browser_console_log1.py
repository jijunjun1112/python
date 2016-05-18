import os
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities    
chromedriver="C:\Users\Administrator\Desktop\chromedriver.exe"
os.environ["webdriver.chrome.driver"]=chromedriver
# enable browser logging
d = DesiredCapabilities.CHROME 
d['loggingPrefs'] = { 'browser':'ALL' }
driver=webdriver.Chrome(executable_path=chromedriver,desired_capabilities=d)


# test specific code in python selenium


# printing the chrome browser specific logs on console
for entry in driver.get_log('browser'):
    for key,val in entry.items() :
        if key == "message" :
            print val 