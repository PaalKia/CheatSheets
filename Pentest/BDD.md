# Accès à MySQL - 1er pas

### Connaître la version de l’OS

**Commande :**
```sql
SELECT @@version_compile_os;
```

### Vérifier les chemins autorisés pour lire/écrire des fichiers

**Commande :**
```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```
Indique le dossier où MySQL autorise les lectures/écritures de fichiers (LOAD DATA, SELECT INTO OUTFILE…).

### Voir la version de MySQL

**Commande :**
```sql
SELECT @@version;
```
Affiche la version exacte du serveur MySQL.

### Vérifier droits user courant
```sql
SHOW GRANTS;
```
