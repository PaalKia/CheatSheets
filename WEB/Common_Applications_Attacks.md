# Content Management Systems (CMS)  
## WordPress – Discovery & Enumeration

### Introduction

- **WordPress** (2003) → open-source CMS, PHP-based, usually Apache + MySQL.  
- **Extremely popular**: ~32.5% of all sites on the internet.  
- **Highly customizable**, SEO-friendly → but vulnerable through **themes/plugins**.  

**Stats**:  
- 50k+ plugins, 4,100+ themes.  
- 317 versions released.  
- 661+ new WP sites built daily.  
- 120+ languages supported.  
- Hacks: **8% weak passwords**, **60% outdated installs**.  
- Vulnerabilities (per WPScan): 54% plugins, 31.5% core, 14.5% themes.  

**Big names using WordPress**: NYT, eBay, Sony, Forbes, Disney, Facebook, Mercedes-Benz.  

### Discovery / Footprinting

#### `robots.txt`
Exemple typique :
```
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://site.local/wp-sitemap.xml
```

- Présence de `/wp-admin` + `/wp-content` = **WordPress détecté**.  
- `/wp-admin` → redirige souvent vers `/wp-login.php`.

### Structure
- **Plugins** → `/wp-content/plugins/`  
- **Themes** → `/wp-content/themes/`  

### Types d’utilisateurs
- **Admin** → gestion complète (users, code).  
- **Editor** → gérer/publier posts (même ceux d’autres).  
- **Author** → gérer/publier ses propres posts.  
- **Contributor** → écrire posts, mais pas publier.  
- **Subscriber** → simple utilisateur (lecture + profil).  

➡️ **Accès admin = souvent RCE possible**.

## Enumeration

### Identifier WordPress
`curl -s http://blog.site.local | grep WordPress`

Exemple retour : `<meta name="generator" content="WordPress 5.8" />`

### Identifier le thème
`curl -s http://blog.site.local/ | grep themes`

Exemple retour : `.../wp-content/themes/business-gravity/...`

### Identifier les plugins
`curl -s http://blog.site.local/ | grep plugins`

Exemple retour :  
- **Contact Form 7** (`ver=5.4.2`)  
- **mail-masta** (`ver=1.0.0`)  
- **wpDiscuz** (`ver=7.0.4`)
  
## User Enumeration

- Login page : `/wp-login.php`  

- **User valide + mauvais mot de passe** →  
  `"The password for username admin is incorrect."`

- **User invalide** →  
  `"The username someone is not registered on this site."`

➡️ Fuite d’information → **username enumeration**.  

Exemple : `admin` confirmé.

## Automated Enumeration – WPScan

### Installation
`sudo gem install wpscan`

### Aide
`wpscan -h`

### Exemple scan
`sudo wpscan --url http://blog.site.local --enumerate --api-token TOKEN`

### Résultats typiques
- **Server** → Apache/2.4.41 (Ubuntu).  
- **XML-RPC enabled** → brute-force possible.  
- **readme.html exposé**.  
- **Upload dir listing enabled**.  
- **WordPress version 5.8** (vulnérable REST API, XSS).  
- **Theme Transport Gravity** (child de Business Gravity).  
- **Plugins détectés** : mail-masta (LFI, SQLi), wpDiscuz, Contact Form 7.  
- **Users** : `admin`, `john`.

## Moving On
Avec ces infos, nous pouvons maintenant :  
- Planifier l’exploitation (RCE via plugins, brute-force, LFI/SQLi).  
- Explorer la surface d’attaque restante.  
- Démontrer comment **un simple WordPress mal configuré** mène à **compromission totale**.

---


