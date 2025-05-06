import whois
import requests
import dns.resolver
from urllib.parse import urlparse

def check_url(url):
    suspicious_keywords = ["login", "secure", "verify", "account", "update", "confirm", "paypal", "bank", "signin"]
    domain = urlparse(url).netloc
    if any(keyword in domain for keyword in suspicious_keywords):
        print("🔴 Suspicious keywords detected in the domain name.")
        return True
    return False

def check_whois(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path
        domain = domain.replace("www.", "")
        domain_info = whois.whois(domain)

        if domain_info.creation_date:
            print(f"🕓 Domain Created: {domain_info.creation_date}")
        else:
            print("🟡 Domain creation date is not available.")
            return True  # suspicious

        if domain_info.registrar:
            print(f"🏢 Registrar: {domain_info.registrar}")
        else:
            print("🟡 No registrar information found!")
            return True  # suspicious

        return False  # not suspicious

    except whois.parser.PywhoisError as e:
        print(f"🔴 WHOIS Error: WHOIS not found or could not be parsed: {e}")
        return True
    except Exception as e:
        print(f"🔴 WHOIS General Error: {e}")
        return True

def check_https(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200 and "https" in response.url:
            return True
        else:
            print("🔴 Warning: The website does not use HTTPS.")
            return False
    except requests.exceptions.RequestException as e:
        print(f"🔴 Connection error: {e}")
        return False

def check_dns(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path
    try:
        result = dns.resolver.resolve(domain, 'A')
        print(f"🌐 DNS records for {domain}:")
        for rdata in result:
            print(f" - {rdata.address}")
        return False
    except dns.resolver.NoAnswer:
        print("🟡 No DNS records found.")
        return True
    except dns.resolver.NXDOMAIN:
        print("🔴 Domain does not exist!")
        return True
    except Exception as e:
        print(f"🔴 DNS Error: {e}")
        return True

def analyze_url(url):
    print(f"\n🔍 Analyzing URL: {url}")
    suspicious_flag = False

    # Check suspicious keywords
    if check_url(url):
        print("🔴 Suspicious URL detected!")
        suspicious_flag = True

    # WHOIS check
    if check_whois(url):
        suspicious_flag = True

    # HTTPS check
    if not check_https(url):
        suspicious_flag = True

    # DNS check
    if check_dns(url):
        suspicious_flag = True

    # Final verdict
    if not suspicious_flag:
        print("✅ The URL appears to be safe (no major red flags detected).")
    else:
        print("⚠️ The URL may be suspicious based on the analysis.")

# Entry point
if __name__ == "__main__":
    url = input("Enter the URL to analyze: ")
    analyze_url(url)
