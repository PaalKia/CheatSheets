
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

