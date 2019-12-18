# report2
it is comparison of manual vs automatic security testing of http://testhtml5.vulnweb.com/  

# Environment Details  
This is an HTML5 application that is vulnerable by design. This is not a real collection of tweets. This application was created so that you can test your Acunetix, other tools, or your manual penetration testing skills. The application code is prone to attacks such as Cross-site Scripting (XSS) and XML External Entity (XXE). Links presented on this site have no affiliation to the site and are here only as samples.  

# Features of the Environment  
1. JavaScript Framework : AngularJS1.0.6  
2. Web Framework : Bootstrap2.3.1  
3. Web Server : Nginx1.4.1  
4. JavaScript Libraries : jQuery1.9.1  
5. Reverse Proxy : Nginx1.4.1  
6. IP [176.28.50.165]  
7. HTML5, HTTPServer[nginx/1.4.1]  
8. Host : testhtml5.vulnweb.com  

# Pentesting For Following Bugs  
## a) XSS (Cross-Site Scripting)  
#### Description:  
Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. Flaws that allow these attacks to succeed are quite widespread and occur anywhere a web application uses input from a user within the output it generates without validating or encoding it.  

### Manaual Test  
Steps to reproduce:  
1. Login in the website  
2. submit the payload **<script>alert()</script>** in the **username** parameter  on login page  

POC:-  

![man_xss](https://github.com/ashu1665/report2/blob/master/html5_man_xss.png)    

### Automatic Test  
Steps to reproduce:  
1. Run the command:-  python3 vuln_scan.py http://testhtml5.vulnweb.com/ "username=admin"  
2. Choose the 1 option as XSS  

POC:-  
![xss](https://github.com/ashu1665/report2/blob/master/html5_xss.png)    

## b) XXE(XML External Entity)

#### Description:-

An XML External Entity attack is a type of attack against an application that parses XML input. This attack occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser. This attack may lead to the disclosure of confidential data, denial of service, server side request forgery, port scanning from the perspective of the machine where the parser is located, and other system impacts.

### Manaual Test

1. Capture the request to request to http://testhtml5.vulnweb.com/forgotpw and send to repeater  
2. Send the POST request with xxe payload  

POC:-  
![xxe](https://github.com/ashu1665/report2/blob/master/html5_xxe_man.png)  


### Automatic Test  

Steps to Reproduce  
1. Run the command:-  python3 vuln_scan.py http://testhtml5.vulnweb.com/ "username=admin"  
2. Choose the 3 option as XXE  

POC:-  
![xxe3](https://github.com/ashu1665/report2/blob/master/html5_xxe.png)  


## c) CORS(Cross-origin resource sharing)  
#### Description:-  

Cross-origin resource sharing (CORS) is a browser mechanism which enables controlled access to resources located outside of a given domain. It extends and adds flexibility to the same-origin policy (SOP). However, it also provides potential for cross-domain based attacks, if a website's CORS policy is poorly configured and implemented.  

## Manaual Test  

Steps to reproduce  
1. Login into the website  
2. Visit the url  and intercept http://testhtml5.vulnweb.com/ the request using burp and send it to repeater  
3. Change the origin header to http://bing.com  

POC:-
![cors](https://github.com/ashu1665/report2/blob/master/html5_man_cors.png)  


## Automatic Test  

Steps to reproduce  
1. Run the command:-  python3 vuln_scan.py http://testhtml5.vulnweb.com/ "username=admin"  
2. Choose the 5 option as CORS  

POC:-  
![CORS](https://github.com/ashu1665/report2/blob/master/html5_cors.png)  


## d) Sensitive Data Leak  
#### Description  

A possible sensitive file has been found. This file is not directly linked from the website. This check looks for common sensitive resources like password files, configuration files, log files, include files, statistics data, database dumps. Each one of these files could help an attacker to learn more about his target.
Manual Test

**Not Found**    

### Automatic test  

Steps to reproduce  
1. Run the command:-  python3 vuln_scan.py http://testhtml5.vulnweb.com/ "username=admin"  
2. Choose the 8 option as Sensitive Data Leak   

POC:-  
![sensitive](https://github.com/ashu1665/report2/blob/master/html5_sensitive_data.png)  


## e) Missing Security Headers  
#### Description:-  

HTTP security headers are a fundamental part of website security. Upon implementation, they protect you against the types of attacks that your site is most likely to come across. These headers protect against XSS, code injection, clickjacking, etc.  

### Manaual Test  

Steps to reproduce    
1. Visit https://securityheaders.com/ and in search box enter http://testhtml5.vulnweb.com/  

POC:-  
![missing_header](https://github.com/ashu1665/report2/blob/master/html5_man_missing_header.png)  


### Automatic test  

Steps to reproduce  
1. Run the command:-  python3 vuln_scan.py http://testhtml5.vulnweb.com/ "username=admin"  
2. Choose the 6 option as Missing security headers     

POC:-  
![missing/-header_1](https://github.com/ashu1665/report2/blob/master/html5_sensitive_data.png)  


## f) Host Header Injection  

#### Description:-  
Most web servers are configured to pass the unrecognized host header to the first virtual host in the list. Therefore, it’s possible to send requests with arbitrary host headers to the first virtual host.  
Another way to pass arbitrary Host headers is to use the X-Forwarded-Host header. In some configurations this header will rewrite the value of the Host header.  

### Manaual Test  
**Not Found**  

### Automatic Test  
Steps to reproduce  
1. Run the command:-  python3 vuln_scan.py http://testhtml5.vulnweb.com/ "username=admin"  
2. Choose the 9 option as Host Header Injection  

POC:-
[!host_header](https://github.com/ashu1665/report2/blob/master/html5_host_header.png)  




# Comparison Between Manual and Automatic Pentest  
## Number of bug types Found in Manual Test  

1. **XSS**  
2. **XXE**  
3. **CORS**  
4. **Missing Security Headers**    

Total **4 bug types found using Manual test out of 9** tested for  

## Number of bug types Found in Automatic test  

1. **XSS**
2. **Host Header Injection**  
3. **XXE**  
4. **CORS**  
5. **Missing Security Headers**  
6. **Sensitive Data Leak**  



Total 6 bug types Found using Automatic test out of 9 tested for






