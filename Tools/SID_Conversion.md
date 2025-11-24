# SID Conversion

## Format SID
```
S-1-5-21-DOMAIN_IDENTIFIER-RID
```

## Hex → SID

```python
def hex_to_sid(hex_str):
    if hex_str.startswith('0x'):
        hex_str = hex_str[2:]
    
    data = bytes.fromhex(hex_str)
    revision = data[0]
    sub_count = data[1]
    authority = int.from_bytes(data[2:8], 'big')
    
    sid = f"S-{revision}-{authority}"
    for i in range(sub_count):
        offset = 8 + (i * 4)
        sub = int.from_bytes(data[offset:offset+4], 'little')
        sid += f"-{sub}"
    
    return sid

# Usage
hex_sid = "0x0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000"
print(hex_to_sid(hex_sid))
# Output: S-1-5-21-4089266779-1167590040-2748827309-1103
```

## Extraire Domain SID et RID

```python
def get_domain_sid(sid):
    parts = sid.split('-')
    return '-'.join(parts[:-1])

def get_rid(sid):
    return int(sid.split('-')[-1])

# Usage
sid = "S-1-5-21-4089266779-1167590040-2748827309-1103"
print(f"Domain SID: {get_domain_sid(sid)}")
print(f"RID: {get_rid(sid)}")
```

## RIDs Well-Known

| RID | Nom |
|-----|-----|
| 500 | Administrator |
| 501 | Guest |
| 502 | krbtgt |
| 512 | Domain Admins |
| 513 | Domain Users |
| 516 | Domain Controllers |
| 518 | Schema Admins |
| 519 | Enterprise Admins |
