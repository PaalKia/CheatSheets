# Command Injection

## Principe

La détection des vulnérabilités basiques d’**OS Command Injection** suit le même processus que leur exploitation :  
on tente d’injecter une commande et on observe si la sortie diffère de l’exécution normale.  

Si le résultat change, la vulnérabilité est confirmée.  
Pour des injections plus complexes, il peut être nécessaire de fuzzing ou de revue de code.  

Ici, on se concentre sur les cas simples où l’entrée utilisateur est directement passée à une fonction système **sans aucune sanitation**.

## Exemple : Host Checker

L’application demande une adresse IP pour tester sa disponibilité.  

- En entrant `127.0.0.1`, la sortie renvoie un `ping` réussi.  
- On peut en déduire que la commande exécutée est :  

`ping -c 1 OUR_INPUT`

Si `OUR_INPUT` n’est pas filtré, on peut injecter d’autres commandes.

## Opérateurs d’injection

Pour chaîner ou détourner l’exécution, plusieurs opérateurs sont possibles :  

| Injection Operator | Injection Character | URL-Encoded | Exécution |
|--------------------|---------------------|-------------|-----------|
| Semicolon          | `;`                 | `%3b`       | Les deux commandes (Linux, PowerShell) |
| New Line           | `\n`                | `%0a`       | Les deux |
| Background         | `&`                 | `%26`       | Les deux (souvent le second output apparaît en premier) |
| Pipe               | `\|`                 | `%7c`       | Seulement la deuxième commande |
| AND                | `&&`                | `%26%26`    | Les deux (seulement si la première réussit) |
| OR                 | `\|\|`                | `%7c%7c`    | La deuxième (seulement si la première échoue) |
| Sub-Shell          | `` ` ` ``           | `%60%60`    | Les deux (Linux uniquement) |
| Sub-Shell          | `$( )`              | `%24%28%29` | Les deux (Linux uniquement) |


## Compatibilité

- Ces opérateurs fonctionnent **quel que soit le langage web (PHP, .NET, NodeJS…) ou l’OS serveur (Linux, Windows, macOS)**.  
- **Exception** : le `;` ne fonctionne pas avec **Windows CMD**, mais reste valide en **PowerShell**.

