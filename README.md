ldaping_enum
======================

Description
-----------
Uses [LDAP Ping](https://msdn.microsoft.com/en-us/library/cc223811.aspx) search requests to enumerate usernames a la [KrbGuess](https://web.archive.org/web/20200805185350/https://www.cqure.net/wp/tools/password-recovery/krbguess/), guessing usernames based on an input dictionary.


Installation
------------
Requires asn1-ber.v1

	go get gopkg.in/asn1-ber.v1
	./make.sh


Usage
-----

	Usage: ./ldaping -d FQDN -s DC USERNAME_FILE
	  -b int
	    	Buffer of username guesses held in memory (default 1000)
	  -d FQDN
	    	FQDN to search against
	  -f File
	    	File containing domain controllers, one per line
	  -o file
	    	Output file to write found users (default "found_users.txt")
	  -s hostname
	    	IP or hostname of domain controller to query
	  -t threads
	    	Number of guessing threads (default 10)


Example
-------

`./ldaping_enum -d contoso.com -s dc1.contoso.com usernames.txt`

Credit
-------
Originally created by Scott Bernstein
