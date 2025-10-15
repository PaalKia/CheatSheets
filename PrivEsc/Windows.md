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





