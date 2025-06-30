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

---

**À retenir**  
Les vulnérabilités SQLi ne se limitent pas à la clause WHERE ; toute partie d’une requête construite dynamiquement peut être une cible.


