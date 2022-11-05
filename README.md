# INF226 Assignment 2 

**How to run:**
Open terminal: python app.py
Open browser: http://localhost:5000 




**Refactoring code:**

- Removed unnessesary code like get coffee etc.
- Replaced dictionary of users with a database for user information.
- Using SQLAlchemy for database holding login and registration data.
- Encrypting all passwords as they are being created.

TODO: make secure random key (secret key)

why flaskwtf ?

Flaskwtf handles CSRF tokens for you.

Flaskwtf has support for Recaptcha.

Flaskwtf has efficient, secure and very well tested field validators. E.g. password fields, username fields etc.

Flaskwtf checks for a proper refererer header as an extra security measure against CSRF.

Flask wtf has native jinja support



Answers to questions:

# Questions:

**Threat model – who might attack the application?** 

Probably noone wants to attack this application, but if we imagine that this app was a popular platform for communication,
the there could potentially be someone interested in accessing messages/messaging of other users. 

**What can an attacker do?**

An attacker can try to hack username/password and authenticate themself as someone else.
Or they could try to break into the database and gain access to user-data.

**What damage could be done (in terms of confidentiality, integrity, availability)?**

If the database of the application was hacked, it would completely compromise its integrity.
The attacker could tamper with the data and then noone would know what to expect.
Also if an attacker could circumvent authentication/authorization procedures, confidential data could be obtained and spread to anyone.
Confidentiality would be shattered.
It would also severely damage integrity as noone could know if a message really was sent or recieved by the intended user.
Another (less catastrophical) attack could be a denial of service attack. Where for instance the server gets flooded with requests (bots) and shuts down.
This would damage availability as noone would be able to use the app/service.

**Are there limits to what an attacker can do?**

The limit is largely determined by the application design, implementation and security measures.
Good tracability can help detect unnatural behaviour and mitigate potential danger / reduce damages.

**Are there limits to what we can sensibly protect against?**

A system can become very secure with a good design but still experience security issues.
Because many systems operated by people. They will always be prone to the social engineering aspect.
For instance login-information accidentally gets leaked to someone it shouldn't. (and then abused).
The best you can do is to instill good practices, but it will probably never completely eliminate all security concerns.

**What are the main attack vectors for the application?**



**What should we do (or what have you done) to protect against attacks?**

**What is the access control model?**

**How can you know that you security is good enough? (traceability)**



more coming...




Sources:

https://github.com/arpanneupane19/Python-Flask-Authentication-Tutorial

more coming...