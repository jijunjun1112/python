from selenium import webdriver

browser = webdriver.Firefox() # Get local session of firefox
browser.get("http://www.baidu.com") # Load page
#assert "yahoo!!" in browser.title




#browser.close()