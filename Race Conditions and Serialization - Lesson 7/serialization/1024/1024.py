#1-first we want to leak the source code since it is not given to us
##then we note that the css is loaded with absolute file name in url (always a scary thing we can ../../../etc/passwd)
##we can use that to read source code files
##that is a path traversal vulnerability
#2- there is a serialize so we need to understand how to exploit it
## there is a class with a destruct function (usually wakeup e destruct are functions automatically called)
## we can craft the serialized object by hand or we can write php with an online runner and then serialize it

#This is the unserialized class (the one with the destruct) with variables set for the exploit:

O:7:"Ranking":3:{s:7:"ranking";s:28:"<?php echo getenv('FLAG');?>";s:7:"changed";b:1;s:4:"path";s:18:"./games/hello3.php";}

#To reach the written file we have to jsut navigate to it. We can check the presence of the created file with the exploit used for the dump by color=../games/hello3.php
#http://1024.training.jinblack.it/games/hello3.php
#http://1024.training.jinblack.it/?color=../games/hello3.php


#Steps:
#
#
#
#