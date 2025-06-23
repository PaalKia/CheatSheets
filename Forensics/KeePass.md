### **KeePass**

CVE : [CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784)

**Contexte :**
Cette vulnérabilité affecte KeePass 2.x avant la version 2.54. Elle permet à un attaquant d'extraire le mot de passe maître en clair à partir d'un dump mémoire, même si l'espace de travail est verrouillé ou plus en cours d'exécution.

**Fonctionnement de l'exploit :**
KeePass utilise une boîte de texte personnalisée (SecureTextBoxEx) pour la saisie du mot de passe. Chaque caractère tapé laisse une trace résiduelle en mémoire. Un attaquant peut analyser un dump mémoire (processus KeePass, fichier d'échange pagefile.sys, fichier d'hibernation hiberfil.sys ou dump complet de la RAM) pour reconstruire le mot de passe, à l'exception du premier caractère.

**Outil et fonctionnement :**
Le PoC "KeePass Master Password Dumper" de vdohney permet d'extraire le mot de passe maître en analysant les traces résiduelles en mémoire. https://github.com/vdohney/keepass-password-dumper

