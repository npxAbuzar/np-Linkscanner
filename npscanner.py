import re
import urllib.parse

# Suspicious words to check in URL
suspicious_keywords = [
    "login", "secure", "update", "verify", "account", "bank",
    "password", "confirm", "unlock", "click", "paypal", "paypall"
]

# Function to check if URL contains suspicious keywords
def check_keywords(url):
    found = []
    for word in suspicious_keywords:
        if word.lower() in url.lower():
            found.append(word)
    return found

# Function to check if URL uses HTTPS
def check_https(url):
    return url.lower().startswith("https://")

# Function to check if URL has IP address instead of domain
def is_ip_address(url):
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        ip_match = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain)
        return bool(ip_match)
    except:
        return False

# Function to calculate simple risk score
def calculate_risk(keyword_hits, https, ip):
    score = 0
    if keyword_hits:
        score += 2
    if not https:
        score += 1
    if ip:
        score += 2
    return score

# Main Function
def main():
    print("=== NP-LinkScanner | by NPxBh41 ===\n")
    url = input("Enter a URL to scan: ").strip()

    keyword_hits = check_keywords(url)
    https = check_https(url)
    ip = is_ip_address(url)
    score = calculate_risk(keyword_hits, https, ip)

    print("\n[+] Scan Results:")
    if keyword_hits:
        print(f"[!] Suspicious keywords found: {', '.join(keyword_hits)}")
    else:
        print("[✓] No suspicious keywords found.")

    print(f"[{'✓' if https else '!'}] HTTPS: {'Yes' if https else 'No'}")
    print(f"[{'!' if ip else '✓'}] Raw IP Address used: {'Yes' if ip else 'No'}")

    # Risk level
    print("\n[!] Risk Score:", score)
    if score >= 4:
        print("[🔥] Risk Level: HIGH ⚠️")
    elif score >= 2:
        print("[⚠️] Risk Level: MEDIUM")
    else:
        print("[✅] Risk Level: LOW")

if __name__ == "__main__":
    main()
