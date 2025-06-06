# URL Safety Analyzer

### A Python tool to analyze the safety of URLs by checking for suspicious keywords, WHOIS information, HTTPS status, and DNS records. This script helps identify potentially malicious or unsafe websites based on various criteria.

## Features

Suspicious Keywords: Checks if the URL contains any keywords typically associated with phishing or malicious websites (e.g., "login", "secure", "paypal").

- WHOIS Lookup: Verifies the domain's registration information, including creation date and registrar.

* HTTPS Check: Verifies if the website uses HTTPS to ensure the connection is secure.

* DNS Check: Checks if the domain has valid DNS records, ensuring it is reachable.

## Requirements

### To run this tool, you will need the following Python libraries:

- whois for WHOIS information retrieval

- requests for making HTTP requests

- dnspython for DNS lookups

- urllib.parse (standard library) for parsing the URL
