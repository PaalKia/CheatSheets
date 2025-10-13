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













