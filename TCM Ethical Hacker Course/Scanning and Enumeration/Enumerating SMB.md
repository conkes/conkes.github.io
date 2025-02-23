From our NMAP scans, we found an open port at 139, meaning that we have an exposed SMB share. To further research any Metasploit exploits against this, we can use:

`msfconsole`

`search smb`
`auxilary/scanner/smb/smb_version`

In Metasploit, we see 3 main types of modules. We have auxiliary, exploit, and post. in this case, auxiliary is synonymous for scanning, which is what we want.

`set RHOSTS 192.168.152.136`
`set RPORT 139`

version type `Unix Samba 2.2.1a`

To login to the share anonymously:
`smbclient -L(list shares) \\\\192.168.152.136\\`

we see 2 shares, being ADMIN$ and IPC$
to attempt to connect to these shares, we can edit the original smbclient command with the following:

`smbclient \\\\192.168.152.136\\ADMIN$ or IPC$`
you can use 2 \\ if you'd like, but its standard to use 4 and then 2 after the IP.

We are allowed into the IPC share with anonymous access, however we do not have permissions to list directories, making this a dead end.