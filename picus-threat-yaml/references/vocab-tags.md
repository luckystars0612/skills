# Threat tags — complete list

> Pulled from `GET /v1/threat-library/action-parameters` on the live platform, 2026-10-05.
> Picus **validates these on import** — a value outside the list is rejected. The endpoint
> accepts a `module_name` query parameter but ignores it: the response is byte-identical for
> all 12 modules, so one list serves every module.

Used in the `tags` field. Picus sets these on Web Application, Email, File Download and
Azure actions; they are optional.

**258 values.**

```
.NET Deserialization
AG-CR2
AG-CR3
ASP.NET
ActiveMQ
Affected OS
Alternate Syntax
Angular Sandbox Escape
Apache
Apache CouchDB
Apache Flink
Apache Shiro
Apache Solr
Apache Struts
Apache Tomcat
Application Specific File Inclusion
Application Specific Prototype Pollution
Appwrite
Argument Injection
Authentication Bypass
Azure
Bash
Basic Path Traversal
Basic SQLi
Basic Unvalidated Redirect
Basic XSS
Blind SQL Injection
Boolean Based Blind SQLi
Buffer Overflow
CISA
CISA advisory AA25-141A
CRLF Injection
CSP Bypass
CSRF
CSS Injection
CSV Injection
CTEM
Cachet
Cisco
CliTable
Client Side Template Injection
Code Execution
Code Injection
Collection
Command Injection
Config File Exposure
Credential Access
CyberArk Password Vault
DB2 SQLi
DOM Based XSS
DOMPurify
Defense Evasion
Denial of Service
Deserialization
Discovery
Django
Docker
Docker Dashboard
Dolibarr
Drupal
Elasticsearch
Encoded URI
Entra
Error Based SQLi
Evasion
Event Handler
Execution
Exfiltration
File Inclusion
File Type Evasion
File Upload
Firebird SQLi
FlowCloud
Fortinet FortiGate SSL VPN
GPON Router
Generic
Generic LFI
Gitlab
Google Analytics
Google Tag Manager
Grafana
HAProxy
HP iLO4 Server
HTML Injection
HTML5
HTTP DELETE Method
HTTP PUT Method
HTTP Request Smuggling
Header Anomaly
Header Based SQL
Header Based SQLi
Header Violation
Heap Buffer Overflow
Hibernate Query Language Injection
Hidden Input XSS
Html Injection
Huawei
IBM WebSphere
Impact
JPCERT
JSON Injection
Java Deserialization
Java Jackson - Databind
Javascript URI
Jellyfin
Jenkins
Jetty
Joomla
Kibana
Kubernetes
LDAP Injection
LFI
LimeSurvey
Local File Inclusion
Log File Exposure
MS SQL Injection
MSSQL SQLi
Malware
Metabase
MicroEmulationPlan
Microsoft SSMS
Microsoft Sharepoint
Microsoft Windows
Mining
Mongoose
MooTools
Morfeus
Multiple Action
MyLittleAdmin
MySQL Injection
MySQL SQLi
Nessus
Netsparker
NoSQL Injection
NodeJS
Nostromo
OWASP A01
OWASP A01 2021
OWASP A03
OWASP A04
OWASP A05
OWASP A08
OWASP A09
OWASP A10
Odoo
Open Redirection
OpenVas
Oracle
Oracle Glassfish
Oracle SQLi
Oracle Weblogic
Out-Of-Band XXE
PHP
PHP Deserialization
PHP Object Injection
PHPUnit
Palo Alto GlobalProtect SSL VPN
Parameter Pollution
Path Traversal
Persistence
Phishing as the First Step
Pi-hole
PlaceOS
Popper
Port Scanner
PostgreSQL SQL Injection
PostgreSQL SQLi
Privilege Escalation
Prototype Pollution
ProxyShell
Pulse Secure SSL VPN
Purl
Python
Python Deserialization
Qualys WVS
RCE
RPO
Ransomware
Rce
Red Report 2024
Reflected File Download
Regular Expression Denial of Service
Remote File Inclusion
Request Line Anomaly
Restricted
Reverse Payload
Reverse Shell
Ruby
Ruby on Rails
SAP
SAP NetWeaver
SQL Injection
SQL Injection Probing
SQLite SQLi
SQLmap
SSJS Injection
SSRF
Server Side Code Injection
Server Side Includes Injection
Server Side Request Forgery
Server Side Template Injection
Smuggling
Social Network Team
SonicWall
Spring
Spring Boot Framework
Spring Data REST
Spring Framework
Spring Security
Spring Web Flow
Stack Buffer Overflow
Stealer
Symantec
TAG
Tag
Tenda
ThinkPHP
Time Based Blind SQLi
Timing Code Injection
TrendMicro OfficeScan
URL Encoded Path Traversal
URL Encoded Unvalidated Redirect
URL Scheme
US-CERT
Unauthorized Access
Unicode Encoded
WAF Bypass
Web Cache Poisoning
Webshell
Wordpress
XML Based
XML External Entity
XML Injection
XSS
XSS Evasion
XSSI
XST
XXE
XXE via SAML
Xpath Injection
YUI
Zimbra
ZipSlip
Zyxel
anthropic
c99
credential access
critical-URL
emerging
file upload
gcp
m365
macos
mod_rewrite
mythos
phpMyAdmin
r57
rConfig
```
