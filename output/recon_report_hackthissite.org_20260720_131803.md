# Reconnaissance Report: hackthissite.org

**Prepared:** 2026-07-20 13:17:58  
**Target:** https://www.hackthissite.org/  
**Scope:** Passive / publicly available information only.

---

## Executive Summary

- Resolves to 5 IPv4 address(es).
- TLS certificate valid, 81 days remaining.
- Security header coverage: 50% (3 recommended header(s) missing).

---

## 1. WHOIS Information

| Field | Value |
|---|---|
| Registrar | Porkbun LLC |
| Domain Name | hackthissite.org |
| Creation Date | 2003-08-10 15:01:25+00:00 |
| Expiration Date | 2026-08-10 15:01:25+00:00 |
| Updated Date | 2025-07-15 23:08:30+00:00 |
| Organization | Not available |
| Country | Not available |
| Status | clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited, clientTransferProhibited https://icann.org/epp#clientTransferProhibited |
| Name Servers | c.ns.buddyns.com, f.ns.buddyns.com, g.ns.buddyns.com, h.ns.buddyns.com, j.ns.buddyns.com |

## 2. DNS Records & IP Geolocation

| Record Type | Value(s) |
|---|---|
| A | 137.74.187.100<br>137.74.187.101<br>137.74.187.102<br>137.74.187.103<br>137.74.187.104 |
| AAAA | None found |
| MX | 10 aspmx.l.google.com.<br>20 alt1.aspmx.l.google.com.<br>20 alt2.aspmx.l.google.com.<br>30 aspmx2.googlemail.com.<br>30 aspmx3.googlemail.com.<br>30 aspmx4.googlemail.com.<br>30 aspmx5.googlemail.com. |
| NS | c.ns.buddyns.com.<br>f.ns.buddyns.com.<br>g.ns.buddyns.com.<br>h.ns.buddyns.com.<br>j.ns.buddyns.com. |
| TXT | "Harica-9mEHYfxOM4FZwd9l0gG"<br>"Harica-PM9RrLqWMFZXTJCoEoK"<br>"t-verify=e3f12c9c23e2e475563590326df31a12"<br>"v=spf1 a mx ip4:137.74.187.96 ip4:137.74.187.97 ip4:137.74.187.98 a:mail.hackthissite.org include:aspmx.googlemail.com include:spf.hackmail.org -all" |
| CNAME | None found |

### Geolocation

- **IP:** 137.74.187.100
- **Location:** Paris, Île-de-France, France
- **ISP / Org:** OVH SAS / Staff HackThisSite
- **AS:** AS16276 OVH SAS

## 3. HTTP Response Headers

- **Final URL:** https://www.hackthissite.org/
- **Status Code:** 200

| Header | Value |
|---|---|
| Access-Control-Allow-Origin | * |
| Cache-Control | no-store, no-cache, must-revalidate, post-check=0, pre-check=0 |
| Connection | Upgrade |
| Content-Encoding | gzip |
| Content-Language | en |
| Content-Length | 6431 |
| Content-Security-Policy | child-src 'self' hackthissite.org *.hackthissite.org htscdn.org *.htscdn.org discord.com; form-action 'self' hackthissite.org *.hackthissite.org htscdn.org *.htscdn.org; upgrade-insecure-requests; report-uri https://hackthissite.report-uri.com/r/d/csp/enforce |
| Content-Type | text/html |
| Date | Mon, 20 Jul 2026 10:18:02 GMT |
| Expires | Thu, 19 Nov 1981 08:52:00 GMT |
| Feature-Policy | fullscreen * |
| NEL | {"report_to":"default","max_age":31536000,"include_subdomains":true,"success_fraction":0.0,"failure_fraction":0.1} |
| Onion-Location | http://hackthisjogneh42n5o7gbzrewxee3vyu6ex37ukyvdw6jm66npakiyd.onion/ |
| Pragma | no-cache |
| Public-Key-Pins-Report-Only | pin-sha256="YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg="; pin-sha256="Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys="; max-age=2592000; includeSubDomains; report-uri="https://hackthissite.report-uri.com/r/d/hpkp/reportOnly" |
| Referrer-Policy | origin-when-cross-origin |
| Report-To | {"group":"default","max_age":31536000,"endpoints":[{"url":"https://hackthissite.report-uri.com/a/d/g"}],"include_subdomains":true} |
| Server | HackThisSite |
| Set-Cookie | HackThisSite=btvilavjue4cf1qblfpmd1m5k5; expires=Tue, 21-Jul-2026 10:18:02 GMT; path=/ |
| Strict-Transport-Security | max-age=31536000; includeSubDomains; preload |
| Upgrade | h2,h2c |
| Vary | Accept-Encoding |
| X-XSS-Protection | 0 |

## 4. SSL/TLS Certificate

| Field | Value |
|---|---|
| Subject (CN) | hackthisjogneh42n5o7gbzrewxee3vyu6ex37ukyvdw6jm66npakiyd.onion |
| Issuer | Hellenic Academic and Research Institutions CA |
| Valid From | 2026-03-25T06:05:48+00:00 |
| Valid Until | 2026-10-10T06:05:47+00:00 |
| Days Remaining | 81 |
| TLS Version | TLSv1.2 |
| Cipher Suite | ECDHE-RSA-AES256-GCM-SHA384 |
| Subject Alt. Names | hackthissite.org, www.hackthissite.org, hackthisjogneh42n5o7gbzrewxee3vyu6ex37ukyvdw6jm66npakiyd.onion |

## 5. robots.txt & sitemap.xml

### robots.txt
- **Found at:** https://www.hackthissite.org/robots.txt
- **Disallowed paths (2):**
  - `/missions/`
  - `/killing/all/humans/`

### sitemap.xml
- Not found.

## 6. Security Observations

**Security header coverage score: 50%**

**Present:**
- Content-Security-Policy
- Strict-Transport-Security
- Referrer-Policy

**Missing / Recommended:**

| Header | Why it matters |
|---|---|
| X-Frame-Options | Prevents clickjacking by controlling whether the page can be framed. |
| X-Content-Type-Options | Prevents MIME-sniffing attacks (should be 'nosniff'). |
| Permissions-Policy | Restricts which browser features/APIs the page may use. |

**Banner exposure:**
- `Server: HackThisSite` -- Reveals server/framework version info useful for attacker fingerprinting.

**Cookie configuration notes:**
- Cookie missing HttpOnly -- readable by JavaScript, raising XSS-theft risk.
- Cookie missing Secure -- may be sent over plain HTTP.
- Cookie missing SameSite -- weaker CSRF protection.

---

## Disclaimer

This report was generated automatically using the Web Recon Automation Framework and reflects publicly available information at the time of collection. It is intended as a starting point for authorized security assessment work, not a complete vulnerability assessment or penetration test. All testing beyond passive information gathering requires explicit written authorization from the target's owner.
