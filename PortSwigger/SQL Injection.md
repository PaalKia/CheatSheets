# SQL Injection Detection

## Techniques manuelles

- **Tester le simple guillemet `'`**  
  Soumettez un `'` dans chaque champ pour voir si une erreur SQL ou un comportement anormal apparaît.

- **Utiliser une syntaxe SQL spécifique**  
  Injectez des expressions qui devraient soit retourner la même valeur que l’original, soit changer le résultat, et observez les réponses de l’application.

- **Tester des conditions booléennes `OR 1=1` et `OR 1=2`**  
  Ajoutez `OR 1=1` (toujours vrai) puis `OR 1=2` (toujours faux) et comparez les différences de comportement.

- **Payloads de délai temporel**  
  Envoyez une requête qui déclenche un délai (ex : `SLEEP(5)`) et mesurez si la réponse met plus de temps à arriver.

- **Payloads OAST (out-of-band)**  
  Injectez des charges utiles qui génèrent une interaction réseau externe (ex: via Burp Collaborator) et surveillez les interactions déclenchées.

## Outils automatisés

- **Burp Scanner**  
  Permet de détecter rapidement et de façon fiable la majorité des vulnérabilités SQLi.

