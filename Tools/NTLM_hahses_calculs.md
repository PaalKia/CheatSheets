# NTLM Hash Calculation

## Algorithme
```
Password → UTF-16 Little Endian → MD4 → NTLM Hash
```

## Script Python

```python
import hashlib

def ntlm_hash(password):
    return hashlib.new('md4', password.encode('utf-16le')).hexdigest()

# Usage
password = "MyPassword123!"
print(f"NTLM Hash: {ntlm_hash(password)}")
```

## One-liner

```bash
python3 -c 'import hashlib; print(hashlib.new("md4", "PASSWORD".encode("utf-16le")).hexdigest())'
```

## PowerShell

```powershell
function Get-NTLMHash {
    param([string]$Password)
    $md4 = [System.Security.Cryptography.MD4]::Create()
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Password)
    $hash = $md4.ComputeHash($bytes)
    return ($hash | ForEach-Object { $_.ToString("x2") }) -join ''
}

Get-NTLMHash -Password "admin"
```

## Vérifier un hash

```python
import hashlib

def verify_ntlm(password, known_hash):
    calc_hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
    return calc_hash.lower() == known_hash.lower()

# Usage
if verify_ntlm("admin", "209c6174da490caeb422f3fa5a7ae634"):
    print("✅ Match!")
```

## Cracking

```bash
# Hashcat
hashcat -m 1000 hash.txt rockyou.txt

# John
john --format=NT hash.txt --wordlist=rockyou.txt
```

## Hashes communs

| Password | NTLM Hash |
|----------|-----------|
| (vide) | 31d6cfe0d16ae931b73c59d7e0c089c0 |
| admin | 209c6174da490caeb422f3fa5a7ae634 |
| password | 8846f7eaee8fb117ad06bdd830b7586c |
