# INF226 Assignment 2 
---------------------
Status: Incomplete
---------------------
The app does not yet work as intended because of issues creating userdata-table in database file.
I tried using SQLAlchemy when initiating the SQLite database. 
My intension was to store id, username and a hashed password when submitting the registration form.
Because of this issue the app is essentially useless, because registrations don't get stored and thus login fails.

**Fix: (new)** 
- needs specific version of flask_SQLAlchemy:
      pip install flask-sqlalchemy==2.5.1

**How to run:**
- Open terminal: python app.py
- Open browser: http://localhost:5000 

**Refactoring code:**

- Secret key randomized using secrets.token_urlsafe()
    This key shouldn't be in clear text.

- Removed unnessesay files in the code base like hello.py
- Removed unnessesary code like get coffee etc.
    Removing any files/code that the application don't use is a good idea
    for improving visability and eliminate potential security holes.

- Replace dictionary of users with a database for user information.
    Instead of storing user information in clear text in a dictionary it is safer
    and more practical to have such information stored in a database.

- Using SQLAlchemy creating database table for userdata (id/username/password)
    Considering it didn't work, I should have considered trying something else.
    But if it did work, it would be a great way of handling the database.
    Making use of SQLAlchemy ORM for secure queries.

- Encrypting all passwords as they are being created.
    Imported Bcrypt from flask_bcrypt to encrypt passwords.

- Using wtforms for Registration and Login.
    wtforms have methods for validating username and password inputs/submissions.

- Using flask_wtf.
    Flask_wtf handles CSRF tokens.


# Answers to questions (2b):

**Threat model – who might attack the application?** 

Probably noone wants to attack this application, but if we imagine that this app was a popular platform for communication,
the there could potentially be someone interested in accessing messages/messaging of other users. 

**What can an attacker do?**

An attacker can try to hack username/password and authenticate themself as someone else.
Or they could try to break into the database and gain access to user-data/ tamper with data.

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

! App is still extremely vulnerable and prone to SQL-injection (severe weakness)
The application could still be vulnerable to XSS-attacks (cross site scripting).
Bots attacks could still be an issue.

**What should we do (or what have you done) to protect against attacks?**

I have done:
Set up authentication by username and password.
Utilized flask_wtf FlaskForm and wtforms validation methods registration and login forms.
Used bcrypt for encrypting passwords.
Storing id/username/hashed password in separate database (userdata.db)

Should do:
Fix the app (in the sense that it doesnt work with creating table in the userdata.db)
Create message system with properly controlled and sanitized user inputs.
Use recaptcha for login/registration requests to stop bot flooding attacks. 

**What is the access control model?**

Access control is in place by users creating a unique username and a personal password to identify themselves. 
This username and password must be entered to get access to the apps service/functionality
and should grant each user access only to information specific to them.

**How can you know that you security is good enough? (traceability)**

It is hard to know if security is good enough. In this app user activity is traced by session cookies which allows the server side
to see (metadata such as IP adress etc) who and when a user was connected to the server.
It would be hard to tell if someones identity was being stolen or impersonated.
But good tracability greatly helps discovering and pinpointing the source of these issues.



# Sources:

Original template: https://git.app.uib.no/inf226/22h/login-server

Book: Security for software engineers

Book: Secure by design

https://github.com/arpanneupane19/Python-Flask-Authentication-Tutorial

https://flask.palletsprojects.com/en/2.2.x/api/#sessions

