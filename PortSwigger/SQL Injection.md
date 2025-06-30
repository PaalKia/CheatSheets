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

