# Holberton School – Shodan Passive Reconnaissance Report

**Date of Scan:** 2025-08-12  
**Search Engine:** [Shodan](https://www.shodan.io/)  
**Search Query:** `holbertonschool.com`  
**Total Results Found:** 3

---

## 1. IP Ranges / Hosts Found

| IP Address      | Hostnames                                                                                       | Organization                    | Country | City  |
|-----------------|------------------------------------------------------------------------------------------------|----------------------------------|---------|-------|
| 52.47.143.83    | `ec2-52-47-143-83.eu-west-3.compute.amazonaws.com`, `yriry2.holbertonschool.com`               | Amazon Data Services France     | France  | Paris |
| 35.180.27.154   | `ec2-35-180-27-154.eu-west-3.compute.amazonaws.com`                                             | Amazon Data Services France     | France  | Paris |

**IP Ranges:**  
Both IPs are hosted in AWS' `eu-west-3` (Paris) region. Likely range:  
- `52.47.0.0/16` (AWS Paris)  
- `35.180.0.0/16` (AWS Paris)  

---

## 2. Ports & Services

| Port | Count | Protocol | Notes                |
|------|-------|----------|----------------------|
| 443  | 2     | HTTPS    | SSL/TLS present      |
| 80   | 1     | HTTP     | Redirects to main domain |

---

## 3. Technologies & Frameworks Detected

### 3.1 Web Server
- **nginx** (on multiple hosts)
- Version observed: `nginx/1.18.0 (Ubuntu)` (on 35.180.27.154)

### 3.2 Operating System
- **Ubuntu** (on 35.180.27.154)

### 3.3 SSL/TLS
- **Issuer:** Let's Encrypt (Common Name: `E6`)
- **Issued To:** `yriry2.holbertonschool.com`
- **Supported Versions:** TLSv1.2, TLSv1.3

### 3.4 Tags from Shodan
- `cloud`
- `eol-product` (End-of-life software detected on some hosts)

---

## 4. HTTP Banners

**Host:** `52.47.143.83:443`  
```
HTTP/1.1 200 OK
Server: nginx
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 0
X-Content-Type-Options: nosniff
X-Download-Options: noopen
```

**Host:** `35.180.27.154:443`  
```
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0 (Ubuntu)
Location: [http://holbertonschool.com](http://holbertonschool.com)
```

**Host:** `35.180.27.154:80`  
```
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0 (Ubuntu)
Location: [http://holbertonschool.com](http://holbertonschool.com)
```

---

## 5. Observations

- All hosts are AWS EC2 instances in **Paris, France** (Amazon Data Services France).
- SSL certificates are properly configured with modern TLS versions (v1.2, v1.3).
- `eol-product` tag indicates potential outdated software (nginx or Ubuntu version might be at end-of-life).
- Multiple subdomains point to the same AWS infrastructure.

---

## 6. Recommendations

- Investigate and upgrade any **end-of-life software** to maintain security compliance.
- Regularly monitor Shodan for new hosts/subdomains to detect potential exposure.
- Review HTTP headers to improve security (consider enabling `X-XSS-Protection` and stricter `Content-Security-Policy`).

---
