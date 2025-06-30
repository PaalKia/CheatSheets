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
