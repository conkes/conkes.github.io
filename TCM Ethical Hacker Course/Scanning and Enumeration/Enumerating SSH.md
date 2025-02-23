As we see in our output file nmap.txt, we also have an exposed SSH port. As anything further than attempting to see if it will connect is no longer scanning and enumeration, we will only go so far here.

First, attempting to ssh
`ssh 192.168.152.136`
returns error 
`Unable to negotiate with 192.168.152.136 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1
`
Adding this to the attempt with the following CMD in bash

`ssh 192.168.152.136 -oKexAlgorithms=+diffie-hellman-group1-sha1 -c aes-128 cbc`

will bypass this error and allow us to put in a password. However this is no longer scanning so the module ends here. Understanding how to get this info off of the banner returns is the goal.