# HTTP Verb Tampering 

# Bypassing Basic Authentication

## Principe
Exploiter des méthodes HTTP alternatives (POST, HEAD, OPTIONS, …) pour contourner des protections comme **HTTP Basic Auth**.  
Deux cas possibles :
- **Insecure Server Config** : simple bypass (souvent détecté par scanners).  
- **Insecure Coding** : nécessite des tests manuels.

## Identification

1. Application : File Manager avec ajout de fichiers (`test`, `notes.txt`).  
2. Fonction **Reset** → nécessite authentification (HTTP Basic Auth).  
   - Sans credentials → `401 Unauthorized`.  
3. Ressource protégée : `/admin/reset.php` (et tout `/admin/`).  

## Exploitation

### Étape 1 — Identifier la méthode utilisée
- Requête initiale : `GET /admin/reset.php`  
- Test : modifier en `POST` (Burp → *Change Request Method*).  
- Résultat : toujours `401 Unauthorized`.

➡️ Donc `GET` et `POST` protégés.

### Étape 2 — Lister les méthodes acceptées
- `curl -i -X OPTIONS http://SERVER_IP:PORT/`

Réponse type :
```
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
Allow: POST,OPTIONS,HEAD,GET
```

➡️ Le serveur accepte **HEAD**.

### Étape 3 — Utiliser `HEAD`
- Intercepter la requête `GET /admin/reset.php`  
- Changer méthode → `HEAD /admin/reset.php`  
- Forward dans Burp  

Résultat :
- Pas de prompt Basic Auth  
- Pas de `401`  
- Réponse vide (normal pour HEAD)  
- ✅ Fonction **Reset exécutée** : tous les fichiers supprimés dans le File Manager.

---

# Bypassing Security Filters

## Principe
- Vulnérabilité due à **Insecure Coding** (les devs ne filtrent que certains verbes HTTP).  
- Exemple : un filtre ne vérifie que `$_POST['param']` → un `GET` ou autre méthode peut contourner la protection.  

## Identification
- Application : File Manager.  
- Tentative d’upload avec `test;` → message **Malicious Request Denied!**  
- Donc un filtre back-end bloque les caractères suspects.  
- Idée : changer le verbe HTTP pour échapper au filtre.  

## Exploitation

### Étape 1 — Intercepter et modifier la requête
- Requête initiale (POST) bloquée → "Malicious Request Denied!"  
- Burp → *Change Request Method* → `GET`  

Résultat :  
- Pas de message d’erreur  
- Fichier `test;` créé avec succès ✅


### Étape 2 — Confirmer avec Command Injection
Payload : `file1; touch file2;`  

1. Saisir le nom de fichier dans l’appli  
2. Intercepter la requête  
3. Modifier méthode en `GET`  
   - Paramètre envoyé : `filename=file1%3B+touch+file2%3B`  

Résultat :  
- Deux fichiers créés : `file1` et `file2`  
- ➡️ Command Injection confirmée

## Résumé
- Le filtre back-end ne couvrait que **POST**  
- En envoyant un **GET**, on a bypassé la protection  
- Impact : possibilité d’exploiter une **Command Injection** malgré la présence d’un filtre.

---

# HTTP Verb Tampering - Prevention

## Vulnérabilité
- Cause : **insecure config** ou **insecure coding**
- Risque : certaines méthodes HTTP (HEAD, OPTIONS, etc.) échappent à l’auth ou aux filtres.

## Insecure Configuration

### Apache (vulnérable)
```
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```
➡ Protège **GET** seulement → POST/HEAD/OPTIONS restent ouverts.

### Tomcat (vulnérable)
```
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```
➡ Restriction uniquement sur `GET`.

### ASP.NET (vulnérable)
```
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
            <deny verbs="GET" users="*">
        </deny>
        </allow>
    </authorization>
</system.web>
```
➡ Protège `GET` seulement.

### Fix
- Ne pas restreindre à un seul verbe.  
- Utiliser :  
  - **Apache** → `LimitExcept`  
  - **Tomcat** → `http-method-omission`  
  - **ASP.NET** → `add/remove`  
- Désactiver/deny `HEAD` si inutile.

## Insecure Coding

Exemple vulnérable (PHP) :
```
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
        system("touch " . $_REQUEST['filename']);
    } else {
        echo "Malicious Request Denied!";
    }
}
```

### Problème
- Filtre (`preg_match`) → ne regarde que `$_POST`  
- Exécution (`system`) → prend `$_REQUEST` (donc GET ou POST)  
➡ Les filtres ne couvrent pas tous les cas → injection possible via `GET`.

## Recommandations
- Être **cohérent** : même méthode partout.  
- Tester **tous les paramètres** (GET + POST).  
- Bonnes pratiques :  
  - **PHP** → `$_REQUEST['param']`  
  - **Java** → `request.getParameter('param')`  
  - **C#** → `Request['param']`  

➡ Couvrir toutes les méthodes dans les filtres de sécurité.  


