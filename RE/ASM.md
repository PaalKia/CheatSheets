# Architecture

# Langage Assembly

## Concepts de Base

### Définition
- **Assembly** = langage de bas niveau lisible par l'humain
- Traduit en **code machine** (binaire) compréhensible par le processeur
- Aussi appelé "code machine symbolique"

### Exemple de Traduction
```
Assembly:    add rax, 1
Shellcode:   4883C001
Binaire:     01001000 10000011 11000000 00000001
```

### Shellcode
- Représentation hexadécimale du code machine
- Peut être reconverti en Assembly
- Chargeable directement en mémoire

## Hiérarchie des Langages

### Langages de Haut Niveau
- **Exemples**: C++, Java, Python
- Code unique pour tous les processeurs
- Nécessitent compilation ou interprétation

### Langages de Bas Niveau (Assembly)
- Spécifique à chaque architecture processeur
- Instructions directes pour le CPU
- Traduit en code machine (1 et 0)

## Étapes de Compilation

```
Python → C → Assembly → Shellcode → Binaire
```

### Exemple "Hello World!"

**Python:**
```python
print("Hello World!")
```

**C (équivalent):**
```c
write(1, "Hello World!", 12);
_exit(0);
```

**Assembly (syscall Linux):**
```nasm
mov rax, 1      ; syscall write
mov rdi, 1      ; stdout
mov rsi, message ; texte
mov rdx, 12     ; longueur
syscall

mov rax, 60     ; syscall exit
mov rdi, 0
syscall
```

**Shellcode (hex):**
```
48 c7 c0 01
48 c7 c7 01
48 8b 34 25
48 c7 c2 0c
0f 05
...
```

**Binaire:**
```
01001000 11000111 11000000 00000001
01001000 11000111 11000111 00000001
...
```

## Types de Langages

### Compilés
- **Exemples**: C, C++, Rust
- Conversion directe en code machine
- Plus rapides (pas d'intermédiaire)

### Interprétés
- **Exemples**: Python, PHP, Bash, JavaScript
- Utilisent des bibliothèques pré-compilées (C/C++)
- Interprétés pendant l'exécution

### Multi-plateforme
- **Exemple**: Java
- Code → Bytecode Java → Code machine (JVM)
- Plus lent mais portable

## Intérêt pour le Pentesting

### Exploitation Binaire
- **Essentiel** pour attaquer des programmes compilés
- Nécessaire pour:
  - Buffer overflows
  - ROP chains
  - Heap exploitation
  - Désassemblage et débogage

### Compétences Requises
- Comprendre les instructions Assembly
- Suivre le flux d'exécution en mémoire
- Écrire des exploits personnalisés
- Injecter du shellcode

### Architectures
- **x86/x64 Intel**: Standard pour PC modernes
- **ARM**: Smartphones, MacBook M1/M2
- Les bases Assembly sont transférables entre architectures

---

# Architecture des Ordinateurs

## Architecture Von Neumann (1945)

### Principe
- Base de tous les ordinateurs modernes
- Concept de "Ordinateur à Usage Général" (Turing/Babbage)
- Exécute du code machine pour des algorithmes spécifiques

### Composants Principaux
```
┌─────────────────────────────────────┐
│              CPU                    │
│  ┌───────┬───────┬──────────┐      │
│  │  CU   │  ALU  │ Registres│      │
│  └───────┴───────┴──────────┘      │
└─────────────────────────────────────┘
         ↕              ↕
    ┌────────┐    ┌──────────┐
    │ Mémoire│    │   I/O    │
    │Cache+RAM│   │Clavier   │
    └────────┘    │Écran     │
                  │Stockage  │
                  └──────────┘
```

## CPU - Processeur Central

### 3 Composants Essentiels

| Composant | Fonction |
|-----------|----------|
| **CU** (Control Unit) | Contrôle l'exécution |
| **ALU** (Arithmetic Logic Unit) | Calculs arithmétiques/logiques |
| **Registres** | Stockage ultra-rapide |

## Mémoire (Primary Memory)

### Cache Memory

**Caractéristiques:**
- Située **dans le CPU**
- Extrêmement rapide (vitesse du CPU)
- Très limitée en taille
- Coûteuse à fabriquer

**Niveaux de Cache:**

| Niveau | Taille | Vitesse | Localisation |
|--------|--------|---------|--------------|
| **L1** | Ko | Ultra-rapide | Dans chaque cœur CPU |
| **L2** | Mo | Très rapide | Partagé entre cœurs |
| **L3** | Mo | Rapide | Optionnel, plus grand que L2 |

**Performance:**
- L1 : ~1 cycle d'horloge
- L2 : quelques cycles
- RAM : ~200 cycles

### RAM (Random Access Memory)

**Caractéristiques:**
- Taille: Go → To
- Plus lente que le cache
- Volatile (données temporaires)
- Éloignée du CPU

**Adressage:**
```
32-bit: 0x00000000 → 0xFFFFFFFF (max 4 Go)
64-bit: 0x0000000000000000 → 0xFFFFFFFFFFFFFFFF (max 18.5 exaoctets)
```

## Segments Mémoire RAM

```
Adresses Hautes
┌──────────────┐
│    STACK     │ ← LIFO, taille fixe
├──────────────┤
│      ↓       │
│              │
│      ↑       │
├──────────────┤
│     HEAP     │ ← Hiérarchique, dynamique
├──────────────┤
│     DATA     │ ← Variables (.data + .bss)
├──────────────┤
│     TEXT     │ ← Instructions Assembly
└──────────────┘
Adresses Basses
```

### Détails des Segments

| Segment | Description | Caractéristiques |
|---------|-------------|------------------|
| **Stack** | Pile LIFO | Taille fixe, push/pop uniquement, rapide |
| **Heap** | Tas dynamique | Allocation flexible, plus lent, plus grand |
| **Data** | Variables | `.data` (initialisées) + `.bss` (non initialisées) |
| **Text** | Code | Instructions Assembly chargées ici |

### Mémoire Virtuelle
- Chaque application a sa **propre** mémoire virtuelle
- Chaque app → son Stack/Heap/Data/Text isolé

## I/O et Stockage (Secondary Memory)

### Périphériques I/O
- Clavier
- Écran
- Stockage (HDD/SSD)

### Bus Interfaces
- "Autoroutes" pour transférer données/adresses
- Capacité: multiples de 4 bits → 128 bits
- Exemples: SATA, USB

### Types de Stockage

| Type | Technologie | Vitesse |
|------|-------------|---------|
| **HDD** | Magnétique | Lent |
| **SSD** | Circuit non-volatile (style RAM) | Plus rapide |

**Caractéristiques:**
- Stockage **permanent** (non-volatile)
- Le plus éloigné du CPU = le plus lent
- Taille: To et plus

## Hiérarchie de Vitesse

```
RAPIDE → LENT
```

| Composant | Vitesse | Taille | Cycles |
|-----------|---------|--------|--------|
| **Registres** | ⚡⚡⚡⚡⚡ | octets | ~1 |
| **L1 Cache** | ⚡⚡⚡⚡ | Ko | ~3-5 |
| **L2 Cache** | ⚡⚡⚡ | Mo | ~10-20 |
| **L3 Cache** | ⚡⚡ | Mo | ~40-75 |
| **RAM** | ⚡ | Go-To | ~200 |
| **Stockage** | 🐌 | To+ | Milliers |

### Règle Générale
```
Plus c'est LOIN du CPU → Plus c'est LENT
Plus c'est GROS → Plus c'est LENT
```

## Points Clés pour Assembly

### Pourquoi C'est Important
1. Assembly travaille principalement avec **CPU + Mémoire**
2. Comprendre où vont/viennent les données
3. Connaître le coût (vitesse) de chaque instruction
4. Essentiel pour exploitation binaire:
   - Stack overflows → comprendre Stack
   - ROP/Heap exploits → comprendre profondément l'architecture

### Flux de Données Typique
```
Stockage → RAM (segments) → Cache → Registres → ALU
                                              ↓
                                          Résultat
```

## Résumé

**Architecture Von Neumann = CPU + Mémoire + I/O**

**CPU:**
- CU: Contrôle
- ALU: Calculs
- Registres: Données immédiates

**Mémoire:**
- Cache (L1/L2/L3): Ko-Mo, ultra-rapide
- RAM: Go-To, 4 segments (Stack/Heap/Data/Text)

**Stockage:**
- HDD/SSD: To+, permanent, le plus lent

**Vitesse:** Registres > Cache > RAM > Stockage

**Exploitation:** Comprendre cette architecture = fondamental pour pwn binaire

---

# Architecture CPU

## Composants du CPU

### Structure
```
┌────────────────────────────────┐
│            CPU                 │
│  ┌──────────┬──────────────┐  │
│  │    CU    │     ALU      │  │
│  │ Contrôle │  Arithmétique│  │
│  │ + Données│  + Logique   │  │
│  └──────────┴──────────────┘  │
└────────────────────────────────┘
```

| Composant | Fonction |
|-----------|----------|
| **CU** (Control Unit) | Déplace et contrôle les données |
| **ALU** (Arithmetic Logic Unit) | Calculs arithmétiques et logiques |

## ISA - Instruction Set Architecture

### Définition
- Détermine **comment** le CPU traite les instructions
- Chaque processeur = ISA différente

### Deux Approches Principales

| Type | Principe | Caractéristiques |
|------|----------|------------------|
| **RISC** | Instructions simples | Plus de cycles, cycles courts, moins d'énergie |
| **CISC** | Instructions complexes | Moins de cycles, cycles longs, plus d'énergie |

## Vitesse d'Horloge (Clock Speed)

### Clock Cycle
- **1 cycle** = traitement d'une instruction basique
- Exécuté par CU ou ALU
- Fréquence: cycles/seconde (Hertz)

**Exemple:**
```
CPU 3.0 GHz = 3 milliards de cycles/seconde (par cœur)
```

### Diagramme Clock Cycle
```
     ┌─┐   ┌─┐   ┌─┐   ┌─┐   ┌─┐   ┌─┐
─────┘ └───┘ └───┘ └───┘ └───┘ └───┘ └───
     T1  T2  T3  T4  T5  T6
```

### Multi-Core
- CPUs modernes = plusieurs cœurs
- Permet **plusieurs cycles simultanés**

## Cycle d'Instruction (Instruction Cycle)

### 4 Étapes

```
    ┌──────────┐
    │  FETCH   │ ← 1. Récupérer l'instruction
    └─────┬────┘
          ↓
    ┌──────────┐
    │  DECODE  │ ← 2. Décoder binaire → instruction
    └─────┬────┘
          ↓
    ┌──────────┐
    │ EXECUTE  │ ← 3. Exécuter (ALU/CU)
    └─────┬────┘
          ↓
    ┌──────────┐
    │  STORE   │ ← 4. Stocker résultat
    └──────────┘
```

### Détails des Étapes

| Étape | Description | Exécuté par |
|-------|-------------|-------------|
| **1. FETCH** | Récupère adresse depuis IAR (Instruction Address Register) | CU |
| **2. DECODE** | Décode binaire pour comprendre l'instruction | CU |
| **3. EXECUTE** | Récupère opérandes et exécute | ALU (arith) / CU |
| **4. STORE** | Stocke résultat dans destination | CU |

## Exemple: `add rax, 1`

```nasm
add rax, 1    ; Assembly
48 83 C0 01   ; Machine code (hex)
```

**Cycle complet:**

1. **FETCH**: Récupère `48 83 C0 01` depuis registre `rip`
2. **DECODE**: Comprend → "ajouter 1 à rax"
3. **EXECUTE**: 
   - CU: lit valeur actuelle de `rax`
   - ALU: calcule `rax + 1`
4. **STORE**: Écrit nouveau résultat dans `rax`


## Traitement Parallèle

### Ancien Design (Séquentiel)
```
T1  T2  T3  T4  T5  T6
[F1][D1][E1]          ← Instruction 1 terminée
            [F2][D2][E2] ← Instruction 2 commence après
```

### Design Moderne (Pipeline)
```
T1  T2  T3  T4  T5  T6
[F1][D1][E1]
    [F2][D2][E2]
        [F3][D3][E3]
```

**Avantages:**
- Multi-thread + Multi-core
- **Plusieurs instructions en parallèle**
- Beaucoup plus rapide

## Architectures Spécifiques

### Code Machine ≠ Universel

**Même code machine = instructions différentes:**

| Processeur | Code Machine | Instruction |
|------------|--------------|-------------|
| Intel x86 64-bit | `4883C001` | `add rax, 1` |
| ARM | `4883C001` | `biceq r8, r0, r8, asr #6` |

### ISA par Processeur

**Intel x86_64:**
```nasm
add rax, 1
```

**ARM:**
```nasm
add r1, r1, 1
```

## Syntaxes Différentes (même ISA)

### x86 Architecture = Plusieurs Syntaxes

**Intel Syntax:**
```nasm
add rax, 1
```

**AT&T Syntax:**
```nasm
addb $0x1,%rax
```

**Différences:**
- Ordre source/destination inversé
- Préfixes différents ($, %)
- **Même code machine final!**

## x86_64

### Architecture Ciblée
- **x86_64** (aussi appelé AMD64)
- Syntaxe: **Intel**
- Raison: majorité des PC/serveurs modernes

### Vérifier l'Architecture (Linux)

```bash
lscpu
```

**Output:**
```
Architecture:                    x86_64
CPU op-mode(s):                  32-bit, 64-bit
Byte Order:                      Little Endian
```

**Ou:**
```bash
uname -m
```

**Output:**
```
x86_64
```

## Points Clés à Retenir

### Processeur
- CU + ALU = CPU
- Chaque processeur = ISA différente
- ISA = ensemble d'instructions spécifiques

### Cycles
- **Clock Cycle**: 1 instruction basique
- **Instruction Cycle**: 4 étapes (Fetch → Decode → Execute → Store)
- Moderne = parallélisation (multi-core/thread)

### Code Machine
- **Non universel**: même hex ≠ même instruction sur CPUs différents
- x86 Intel ≠ ARM
- Même ISA peut avoir syntaxes différentes (Intel vs AT&T)


## Résumé Architecture

```
Code Assembly → ISA spécifique → Code Machine → Exécution CPU

Exemple x86_64 Intel:
add rax, 1 → 48 83 C0 01 → Fetch/Decode/Execute/Store → rax = rax+1
```

**Important:** 
- 1 instruction Assembly ≠ 1 clock cycle
- 1 instruction = 1 instruction cycle = plusieurs clock cycles
- RISC vs CISC = compromis vitesse/complexité/énergie

---

# ISA - Instruction Set Architectures

## Définition ISA

### Qu'est-ce qu'une ISA?
- Spécifie la **syntaxe et sémantique** de l'Assembly
- Intégrée dans la **conception même du processeur**
- Affecte l'ordre d'exécution et la complexité des instructions

## Composants d'une ISA

| Composant | Description | Exemples |
|-----------|-------------|----------|
| **Instructions** | Format: `opcode operand_list` (1-3 opérandes) | `add rax, 1`, `mov rsp, rax`, `push rax` |
| **Registres** | Stockage temporaire (opérandes/adresses/instructions) | `rax`, `rsp`, `rip` |
| **Adresses Mémoire** | Pointeurs vers données/instructions | `0xffffffffaa8a25ff`, `0x44d0`, `$rax` |
| **Types de Données** | Type des données stockées | `byte`, `word`, `double word` |

## Deux Architectures Principales

```
┌────────────────────────────────────────────┐
│              ISA                           │
│  ┌──────────────┬──────────────────────┐  │
│  │     CISC     │        RISC          │  │
│  │ Intel / AMD  │     ARM / Apple      │  │
│  │  PC / Serveurs│  Smartphones / Laptops│ │
│  └──────────────┴──────────────────────┘  │
└────────────────────────────────────────────┘
```

## CISC - Complex Instruction Set Computer

### Principe
- Instructions **complexes**
- Réduit le nombre total d'instructions
- Optimisation au niveau **matériel (CPU)**

### Exemple: `add rax, rbx`

**CISC traite en 1 seul cycle d'instruction:**
```
[Fetch-Decode-Execute-Store] → Terminé!
```

Pas besoin de:
1. Fetch rax
2. Fetch rbx  
3. Add
4. Store
(Chacune prenant son propre cycle)

### Raisons Historiques
1. Exécuter plus d'instructions complexes d'un coup
2. **Mémoire limitée** dans le passé → code plus court préféré

### Caractéristiques

**Avantages:**
- ✅ Moins d'instructions totales
- ✅ Code Assembly plus court
- ✅ Instructions complexes en 1 cycle

**Inconvénients:**
- ❌ CPU plus complexe à concevoir
- ❌ Chaque instruction = **plusieurs clock cycles**
- ❌ **Haute consommation d'énergie**
- ❌ Plus de chaleur
- ❌ Instructions de longueur variable

## RISC - Reduced Instruction Set Computer

### Principe
- Instructions **simples**
- Optimisation au niveau **logiciel (Assembly)**
- CPU conçu pour instructions basiques uniquement

### Exemple: `add r1, r2, r3`

**RISC décompose en plusieurs cycles:**
```
Cycle 1: [Fetch-Decode-Execute-Store] → Fetch r2
Cycle 2: [Fetch-Decode-Execute-Store] → Fetch r3
Cycle 3: [Fetch-Decode-Execute-Store] → Add
Cycle 4: [Fetch-Decode-Execute-Store] → Store in r1
```

### Caractéristiques

**Avantages:**
- ✅ Instructions de **longueur fixe** (32-bit/64-bit)
- ✅ Chaque étape = **1 clock cycle** précis
- ✅ **Très faible consommation** d'énergie
- ✅ Idéal pour batteries (smartphones/laptops)
- ✅ CPU plus simple à concevoir
- ✅ Optimisation logicielle moderne → très rapide

**Inconvénients:**
- ❌ Plus d'instructions totales
- ❌ Code Assembly plus long
- ❌ Mémoire/stockage plus utilisé (moins problématique aujourd'hui)

### Pipeline RISC
```
Clock Cycles: T1  T2  T3  T4  T5  T6
Instruction 1: [F][D][E]
Instruction 2:    [F][D][E]
Instruction 3:       [F][D][E]
```

**F**=Fetch, **D**=Decode, **E**=Execute

- Chaque étape = **1 clock cycle exactement**
- Parallélisation efficace

## CISC vs RISC - Tableau Comparatif

| Critère | CISC | RISC |
|---------|------|------|
| **Complexité** | Instructions complexes | Instructions simples |
| **Longueur Instructions** | Variable (multiples de 8-bit) | Fixe (32/64-bit) |
| **Instructions/Programme** | Peu (code court) | Beaucoup (code long) |
| **Optimisation** | Matérielle (CPU) | Logicielle (Assembly) |
| **Temps d'Exécution** | Variable (multi-cycles) | Fixe (1 cycle) |
| **Instructions Supportées** | Nombreuses (~1500) | Limitées (~200) |
| **Consommation Énergie** | Haute ⚡⚡⚡ | Très basse ⚡ |
| **Exemples** | Intel, AMD | ARM, Apple |
| **Usage** | PC, Serveurs | Smartphones, Laptops modernes |

## Diagramme Clock Cycles

### CISC (Variable)
```
Instruction:  [  Fetch  ][ Decode ][    Execute     ]
Clock Cycles: T1  T2  T3  T4  T5  T6
              └───┴───┴───┴───┴───┘
              Longueur variable
```

### RISC (Fixe)
```
Instr 1: [F][D][E]
Instr 2:    [F][D][E]
Instr 3:       [F][D][E]
Cycles:  T1 T2 T3 T4 T5 T6
         └─┴─┴─┴─┴─┴─┘
         1 cycle par étape
```

## Évolution et Tendances

### Passé
- **Mémoire/stockage limités** → CISC avantagé (code court)
- RISC désavantagé par code long

### Présent/Futur
- Mémoire/stockage abondants et bon marché
- Compilateurs/assembleurs modernes → optimisation logicielle excellente
- RISC devient **plus rapide** que CISC (même pour apps lourdes)
- RISC consomme **beaucoup moins** d'énergie
- **Tendance**: RISC devient dominant

### Aujourd'hui (Pentesting)
- Majorité des cibles = **Intel/AMD (CISC)**
- Priorité = **Apprendre CISC/x86**
- Bases Assembly transférables → ARM plus facile après

## Fun Fact

> **Question**: Peut-on créer un ordinateur à usage général avec un CPU ne supportant qu'**une seule instruction** ?

**Réponse**: Oui! 
- On peut construire des instructions complexes avec seulement `sub` (soustraction)
- Démontre la puissance de la simplicité RISC
- Instructions complexes = combinaisons d'instructions simples

---

# Registres, Adresses et Types de Données

## Registres x86_64

### Définition
- Composants **les plus rapides** (intégrés au CPU)
- Très **limités en taille** (quelques octets)
- Stockage temporaire pour instructions/données

## Types de Registres

### Data Registers (Registres de Données)

**Utilisation:** Stocker arguments d'instructions/syscalls

| Registre | Usage Principal |
|----------|-----------------|
| **rax** | Numéro syscall / Valeur de retour |
| **rbx** | Callee Saved (sauvegardé) |
| **rcx** | 4ème argument / Compteur de boucle |
| **rdx** | 3ème argument |
| **rdi** | 1er argument / Opérande destination |
| **rsi** | 2ème argument / Opérande source |
| **r8** | 5ème argument |
| **r9** | 6ème argument |
| **r10** | Registre secondaire |

### Pointer Registers (Registres Pointeurs)

**Utilisation:** Stocker adresses importantes

| Registre | Usage | Description |
|----------|-------|-------------|
| **rbp** | Base Stack Pointer | Début de la Stack |
| **rsp** | Stack Pointer | Position actuelle dans la Stack (sommet) |
| **rip** | Instruction Pointer | Adresse de la prochaine instruction |

## Sub-Registres (Sous-Registres)

### Structure d'un Registre 64-bit

```
┌─────────────────────────────────────────────────────────────────┐
│                            RAX (64 bits)                          │
│                                                                   │
│                    ┌──────────────────────────────────┐          │
│                    │         EAX (32 bits)            │          │
│                    │                                  │          │
│                    │          ┌───────────────────┐   │          │
│                    │          │   AX (16 bits)    │   │          │
│                    │          │                   │   │          │
│                    │          │    ┌─────────┐    │   │          │
│                    │          │    │AL (8bit)│    │   │          │
└────────────────────┴──────────┴────┴─────────┴────┴───┴──────────┘
 63                 32         16    8         0
```

### Règles de Nommage

| Taille | Octets | Nom | Exemple | Règle |
|--------|--------|-----|---------|-------|
| **64-bit** | 8 | `r` + base | `rax` | Préfixe `r` |
| **32-bit** | 4 | `e` + base | `eax` | Préfixe `e` |
| **16-bit** | 2 | base | `ax` | Nom de base |
| **8-bit** | 1 | base + `l` | `al` | Suffixe `l` |

### Exemples
```
bx  → bl (8-bit), bx (16-bit), ebx (32-bit), rbx (64-bit)
bp  → bpl (8-bit), bp (16-bit), ebp (32-bit), rbp (64-bit)
```

## Tableau Complet des Registres

### Data/Arguments Registers

| Description | 64-bit | 32-bit | 16-bit | 8-bit |
|-------------|--------|--------|--------|-------|
| Syscall Number/Return | **rax** | eax | ax | al |
| Callee Saved | **rbx** | ebx | bx | bl |
| 1st arg - Destination | **rdi** | edi | di | dil |
| 2nd arg - Source | **rsi** | esi | si | sil |
| 3rd arg | **rdx** | edx | dx | dl |
| 4th arg - Loop counter | **rcx** | ecx | cx | cl |
| 5th arg | **r8** | r8d | r8w | r8b |
| 6th arg | **r9** | r9d | r9w | r9b |

### Pointer Registers

| Description | 64-bit | 32-bit | 16-bit | 8-bit |
|-------------|--------|--------|--------|-------|
| Base Stack Pointer | **rbp** | ebp | bp | bpl |
| Current/Top Stack Pointer | **rsp** | esp | sp | spl |
| Instruction Pointer | **rip** | eip | ip | ipl |

> **Note:** `rip` est en "call only" (lecture seule pour la plupart des ops)


## Adresses Mémoire

### Plage d'Adresses (64-bit)
```
0x0000000000000000 → 0xFFFFFFFFFFFFFFFF
```

### Segments de RAM

```
Adresses Hautes (0xFFFF...)
┌──────────────────────┐
│       STACK          │ ← rsp, rbp
├──────────────────────┤
│        HEAP          │
├──────────────────────┤
│        DATA          │
├──────────────────────┤
│        TEXT          │ ← rip (code)
└──────────────────────┘
Adresses Basses (0x0000...)
```

**Permissions:** Chaque région a des permissions R/W/X

## Modes d'Adressage

### Ordre de Vitesse (Rapide → Lent)

| Mode | Description | Exemple | Vitesse |
|------|-------------|---------|---------|
| **Immediate** | Valeur dans l'instruction | `add 2` | ⚡⚡⚡⚡⚡ |
| **Register** | Nom du registre | `add rax` | ⚡⚡⚡⚡ |
| **Direct** | Adresse complète | `call 0xffffffffaa8a25ff` | ⚡⚡⚡ |
| **Indirect** | Pointeur de référence | `call [rax]` ou `call 0x44d000` | ⚡⚡ |
| **Stack** | Adresse au sommet de stack | `add rsp` | ⚡ |

**Règle:** Plus c'est immédiat, plus c'est rapide!

## Endianness (Ordre des Octets)

### Définition
- Ordre de stockage/récupération des octets en mémoire
- **x86/AMD = Little-Endian** (utilisé dans ce module)

### Little-Endian vs Big-Endian

**Adresse à stocker:** `0x0011223344556677`

#### Little-Endian (x86/AMD)
```
Stockage: DROITE → GAUCHE

Adresse:  [0] [1] [2] [3] [4] [5] [6] [7]
Valeur:    77  66  55  44  33  22  11  00
Résultat: 0x7766554433221100 (inversé!)
```

#### Big-Endian (Autres architectures)
```
Stockage: GAUCHE → DROITE

Adresse:  [0] [1] [2] [3] [4] [5] [6] [7]
Valeur:    00  11  22  33  44  55  66  77
Résultat: 0x0011223344556677 (normal)
```

### Exemple Concret: Integer 426

**Binaire:** `00000001 10101010` (2 octets)

| Ordre | Octets | Valeur Décimale |
|-------|--------|-----------------|
| **Normal** | `00000001 10101010` | 426 ✅ |
| **Inversé** | `10101010 00000001` | 43521 ❌ |

**Impact:** L'ordre change complètement la valeur!

## Implications Pratiques Endianness

### Écriture en Assembly (Little-Endian)

**Pour stocker "Hello":**
```
Ordre normal:  H  e  l  l  o
Ordre à push:  o, l, l, e, H  (inversé!)
```

**Pour stocker une adresse:**
```
Adresse:       0x12345678
Ordre à push:  0x78, 0x56, 0x34, 0x12
```

### Avantages Little-Endian
- ✅ Accès aux sub-registres sans parcourir tout le registre
- ✅ Arithmétique dans le bon ordre (droite → gauche)
- ✅ Plus efficace pour certaines opérations

## Types de Données

### Tailles Standard

| Type | Taille | Octets | Exemple |
|------|--------|--------|---------|
| **byte** | 8 bits | 1 | `0xAB` |
| **word** | 16 bits | 2 | `0xABCD` |
| **dword** (double word) | 32 bits | 4 | `0xABCDEF12` |
| **qword** (quad word) | 64 bits | 8 | `0xABCDEF1234567890` |

## Correspondance Registres ↔ Types

### Règle Fondamentale
> **Les deux opérandes doivent avoir la MÊME taille!**

### Tableau de Correspondance

| Sub-Registre | Type de Données | Taille |
|--------------|-----------------|--------|
| **al** | byte | 8 bits |
| **ax** | word | 16 bits |
| **eax** | dword | 32 bits |
| **rax** | qword | 64 bits |

### Exemple d'Erreur
```nasm
❌ mov rax, byte_var    ; ERREUR: rax=8 bytes, byte_var=1 byte
✅ mov al, byte_var     ; OK: al=1 byte, byte_var=1 byte
```

## Points Clés à Retenir

### Registres
1. **Data Registers**: rax, rbx, rcx, rdx, rdi, rsi, r8-r10
2. **Pointer Registers**: rbp, rsp, rip
3. Chaque registre 64-bit → divisible en 32, 16, 8 bits
4. Convention de nommage: r(64) → e(32) → base(16) → l(8)

### Adresses
1. 64-bit: `0x0` → `0xFFFFFFFFFFFFFFFF`
2. Modes: Immediate > Register > Direct > Indirect > Stack
3. Segments RAM: Stack, Heap, Data, Text

### Endianness
1. **x86 = Little-Endian** (droite → gauche)
2. Stocker en ordre **inversé** en Assembly
3. L'ordre des octets change la valeur!

### Types de Données
1. byte (8), word (16), dword (32), qword (64)
2. **Toujours matcher** taille registre ↔ type données
3. al ↔ byte, ax ↔ word, eax ↔ dword, rax ↔ qword

---

# Assembling & Debugging

# Structure des Fichiers Assembly

## Exemple: Hello World!

### Code Complet
```nasm
         global  _start

         section .data
message: db      "Hello HTB Academy!"

         section .text
_start:
         mov     rax, 1
         mov     rdi, 1
         mov     rsi, message
         mov     rdx, 18
         syscall

         mov     rax, 60
         mov     rdi, 0
         syscall
```

**Résultat:** Affiche "Hello HTB Academy!" à l'écran

## Structure Générale

### Vue d'Ensemble
```
┌─────────────────────────────────────────┐
│         global _start                   │ ← Directive
├─────────────────────────────────────────┤
│         section .data                   │ ← Section Data
│ message: db "Hello HTB Academy!"        │   (Variables)
├─────────────────────────────────────────┤
│         section .text                   │ ← Section Text
│ _start:                                 │   (Code)
│         mov rax, 1                      │
│         syscall                         │
└─────────────────────────────────────────┘
```

## Anatomie d'une Ligne

### 3 Éléments par Ligne
```
Label:     Instruction    Operand(s)
  ↓            ↓             ↓
message:      db      "Hello World!"
_start:       mov         rax, 1
              syscall
```

| Élément | Description | Obligatoire |
|---------|-------------|-------------|
| **Label** | Référence pour instructions/directives | Non |
| **Instruction** | Commande à exécuter | Oui |
| **Operand(s)** | Arguments de l'instruction (0-3) | Dépend |

## Trois Sections Principales

### 1️⃣ Directive `global _start`

```nasm
global _start
```

**Fonction:** Indique où commence l'exécution du code

- Pointe vers le label `_start`
- Première ligne du fichier (conventionnellement)
- Machine commence l'exécution à `_start`

### 2️⃣ Section `.data` (Variables)

```nasm
section .data
message: db "Hello HTB Academy!"
length:  equ $-message
```

**Fonction:** Contient toutes les variables

**Caractéristiques:**
- Chargée dans le **segment Data** de la RAM
- Permissions: **Lecture/Écriture** (R/W)
- **Non-exécutable** (protection mémoire)
- Variables chargées **avant** l'exécution de `_start`

### 3️⃣ Section `.text` (Code)

```nasm
section .text
_start:
    mov rax, 1
    syscall
```

**Fonction:** Contient toutes les instructions Assembly

**Caractéristiques:**
- Chargée dans le **segment Text** de la RAM
- Permissions: **Lecture seule** (R-X)
- **Exécutable** mais non-modifiable
- Protection contre buffer overflow
- `_start` = point d'entrée conventionnel

## Définition de Variables

### Instructions de Définition

| Instruction | Type | Description | Exemple |
|-------------|------|-------------|---------|
| **db** | Define Byte | Liste d'octets | `db 0x0A` |
| **dw** | Define Word | Liste de mots (2 bytes) | `dw 0x1234` |
| **dd** | Define Double | Liste de doubles (4 bytes) | `dd 0x12345678` |

### Exemples Pratiques

#### Définir un Byte
```nasm
newline: db 0x0a           ; Caractère nouvelle ligne
```

#### Définir une Liste de Bytes
```nasm
message: db 0x41, 0x42, 0x43, 0x0a   ; "ABC\n"
```

#### Définir une String
```nasm
message: db "Hello World!", 0x0a     ; "Hello World!\n"
```

#### Calculer une Longueur
```nasm
section .data
    message db "Hello World!", 0x0a
    length  equ $-message            ; length = 13
```

## 🔢 Token `$` et Instruction `equ`

### Le Token `$`
```
$ = distance depuis le début de la section courante
```

**Exemple:**
```nasm
section .data
    message db "Hello"    ; Position 0
    length  equ $-message ; $ est à position 5
                          ; length = 5 - 0 = 5
```

### Instruction `equ`

```nasm
constant_name equ expression
```

**Caractéristiques:**
- Définit une **constante** (non modifiable)
- Évalue une expression
- Utilisé principalement pour calculer longueurs

**Exemples:**
```nasm
; Longueur d'une string
message db "Test"
msg_len equ $-message      ; msg_len = 4

; Constante numérique
MAX_SIZE equ 100
```

## Labels

### Définition
```nasm
label_name:
    instruction operands
```

**Usages:**
- Référencer des variables
- Marquer des points dans le code
- Définir des fonctions/boucles
- Point d'entrée (`_start`)

**Exemples:**
```nasm
; Label de variable
message: db "Hello"

; Label de code
_start:
    mov rax, 1

; Label de boucle
loop_start:
    dec rcx
    jnz loop_start
```

## Commentaires

### Syntaxe
```nasm
; Ceci est un commentaire
mov rax, 1    ; Commentaire en fin de ligne
```

**Bonnes Pratiques:**
```nasm
; Initialiser syscall write
mov rax, 1        ; syscall number pour sys_write
mov rdi, 1        ; file descriptor (stdout)
mov rsi, message  ; pointeur vers le message
mov rdx, 18       ; longueur du message
syscall           ; appel système
```

**Avantages:**
- ✅ Explique le but du code
- ✅ Facilite la relecture future
- ✅ Aide au débogage
- ✅ Documentation intégrée

## Protections Mémoire

### Séparation Data/Text

```
┌────────────────────────────────┐
│      Section .data             │
│  Permissions: R/W              │
│  Exécutable: NON ❌            │
│  Usage: Variables              │
├────────────────────────────────┤
│      Section .text             │
│  Permissions: R-X              │
│  Modifiable: NON ❌            │
│  Usage: Code                   │
└────────────────────────────────┘
```

### Pourquoi cette Séparation?

| Protection | Objectif |
|------------|----------|
| Data = Non-exécutable | Empêche exécution de données → Mitigation buffer overflow |
| Text = Non-modifiable | Empêche modification du code → Mitigation exploitation |

**Impact Pratique:**
- ❌ Pas de variables dans `.text`
- ❌ Pas de code dans `.data`
- ✅ Sécurité accrue
- ✅ Exploitation plus difficile

## Template de Base

### Structure Minimale
```nasm
; ============================================
; Programme: [Nom du programme]
; Description: [Description]
; ============================================

         global  _start

         section .data
; --- Variables ---
message: db      "Hello World!", 0x0a
msg_len: equ     $-message

         section .text
_start:
; --- Code principal ---
    mov     rax, 1         ; sys_write
    mov     rdi, 1         ; stdout
    mov     rsi, message   ; buffer
    mov     rdx, msg_len   ; longueur
    syscall

; --- Exit propre ---
    mov     rax, 60        ; sys_exit
    mov     rdi, 0         ; code retour 0
    syscall
```

---

# Assemblage & Désassemblage

## Processus Complet

```
Code Assembly (.s) → nasm → Object File (.o) → ld → Exécutable (ELF)
                   Assemblage            Linkage
```

## Préparation du Code

### Extensions de Fichiers
- `.s` ← Utilisé dans ce module
- `.asm` ← Alternative commune

### Fichier `helloWorld.s`
```nasm
global _start

section .data
    message db "Hello HTB Academy!"
    length equ $-message

section .text
_start:
    mov rax, 1
    mov rdi, 1
    mov rsi, message
    mov rdx, length
    syscall

    mov rax, 60
    mov rdi, 0
    syscall
```

## Étape 1: Assemblage (nasm)

### Commande de Base

```bash
nasm -f elf64 helloWorld.s
```

**Résultat:** `helloWorld.o` (object file)

### Options de Format

| Architecture | Flag | Output |
|--------------|------|--------|
| **64-bit** | `-f elf64` | ELF 64-bit |
| **32-bit** | `-f elf` | ELF 32-bit |

### Qu'est-ce que le Fichier .o?

```
helloWorld.o = Code machine assemblé + Détails variables/sections
```

**Caractéristiques:**
- ✅ Code traduit en machine code
- ✅ Variables et sections détaillées
- ❌ **Pas encore exécutable**
- ⏳ Références et labels non résolus

## Étape 2: Linkage (ld)

### Commande de Base

```bash
ld -o helloWorld helloWorld.o
```

**Résultat:** `helloWorld` (exécutable ELF)

### Options par Architecture

| Architecture | Commande |
|--------------|----------|
| **64-bit** | `ld -o output file.o` |
| **32-bit** | `ld -m elf_i386 -o output file.o` |

### Rôle du Linker

**Résout:**
- ✅ Références → Adresses réelles
- ✅ Labels → Adresses mémoire
- ✅ Liens vers bibliothèques OS
- ✅ Format ELF final

### ELF = Executable and Linkable Format

## Exécution

```bash
./helloWorld
```

**Output:**
```
Hello HTB Academy!
```

---

## Script d'Automatisation

### `assembler.sh` - Version Complète

```bash
#!/bin/bash

fileName="${1%%.*}" # Retire l'extension .s

nasm -f elf64 ${fileName}".s"
ld ${fileName}".o" -o ${fileName}
[ "$2" == "-g" ] && gdb -q ${fileName} || ./${fileName}
```

### Utilisation

```bash
# Rendre exécutable
chmod +x assembler.sh

# Assembler, linker et exécuter
./assembler.sh helloWorld.s

# Assembler, linker et déboguer
./assembler.sh helloWorld.s -g
```

**Fonctionnalités:**
- ✅ Assemble automatiquement
- ✅ Linke automatiquement
- ✅ Exécute ou lance GDB selon l'argument
- ✅ Gère l'extension `.s` automatiquement

## Désassemblage (objdump)

### Commande de Base

```bash
objdump -M intel -d helloWorld
```

### Options Principales

| Option | Description |
|--------|-------------|
| `-M intel` | Syntaxe Intel (vs AT&T) |
| `-d` | Désassemble section `.text` |
| `-D` | Désassemble toutes les sections |
| `-s` | Dump des strings |
| `-j .section` | Cibler une section spécifique |

## Exemples de Désassemblage

### 1️⃣ Désassemblage Complet

```bash
objdump -M intel -d helloWorld
```

**Output:**
```nasm
helloWorld:     file format elf64-x86-64

Disassembly of section .text:

0000000000401000 <_start>:
  401000:	b8 01 00 00 00       	mov    eax,0x1
  401005:	bf 01 00 00 00       	mov    edi,0x1
  40100a:	48 be 00 20 40 00 00 	movabs rsi,0x402000
  401011:	00 00 00
  401014:	ba 12 00 00 00       	mov    edx,0x12
  401019:	0f 05                	syscall
  40101b:	b8 3c 00 00 00       	mov    eax,0x3c
  401020:	bf 00 00 00 00       	mov    edi,0x0
  401025:	0f 05                	syscall
```

**Colonnes:**
1. Adresse mémoire
2. Machine code (hex)
3. Instruction Assembly

### 2️⃣ Code Propre (Sans Hex/Adresses)

```bash
objdump -M intel --no-show-raw-insn --no-addresses -d helloWorld
```

**Output:**
```nasm
helloWorld:     file format elf64-x86-64

Disassembly of section .text:

<_start>:
        mov    eax,0x1
        mov    edi,0x1
        movabs rsi,0x402000
        mov    edx,0x12
        syscall 
        mov    eax,0x3c
        mov    edi,0x0
        syscall
```

**Flags:**
- `--no-show-raw-insn` → Masque machine code
- `--no-addresses` → Masque adresses mémoire

> ⚠️ **Note:** `movabs` = `mov` (identique, juste une notation objdump)

### 3️⃣ Dump Section .data (Variables)

```bash
objdump -sj .data helloWorld
```

**Output:**
```
helloWorld:     file format elf64-x86-64

Contents of section .data:
 402000 48656c6c 6f204854 42204163 6164656d  Hello HTB Academ
 402010 7921                                 y!
```

**Colonnes:**
1. Adresse de départ
2. Bytes en hexadécimal
3. Représentation ASCII

**Flags:**
- `-s` → Dump strings/data
- `-j .data` → Section `.data` uniquement
- Pas besoin de `-M intel` pour les données

## Observations du Désassemblage

### Optimisations de nasm

#### Résolution des Variables
```nasm
# Code Original
mov rsi, message

# Après Assemblage
movabs rsi, 0x402000    # message → adresse résolue
```

#### Résolution des Constantes
```nasm
# Code Original
mov rdx, length         # length equ $-message

# Après Assemblage
mov edx, 0x12          # length → valeur calculée (18 = 0x12)
```

#### Optimisation des Registres
```nasm
# Code Original
mov rax, 1

# Après Assemblage (optimisé)
mov eax, 0x1           # 32-bit au lieu de 64-bit (économie mémoire)
```

**Raison:** nasm utilise sub-registres quand possible pour économiser de la mémoire

## Tips & Tricks

### Astuces nasm
- ✅ Utiliser `equ $-label` pour longueurs dynamiques
- ✅ nasm optimise automatiquement les registres
- ✅ Labels et variables résolus après linkage

### Astuces objdump
- ✅ Toujours utiliser `-M intel` pour syntaxe Intel
- ✅ `-d` pour code, `-s` pour données
- ✅ `movabs` dans output = `mov` (identique)

### Debugging
- ✅ Désassembler pour vérifier le code généré
- ✅ Vérifier section `.data` pour les variables
- ✅ Comparer code original vs assemblé

## Points d'Attention

### Fichier .o
- ❌ **Non exécutable** directement
- ✅ Nécessite linkage avec `ld`
- ✅ Contient références non résolues

### Linkage Obligatoire
- Labels → Adresses réelles
- Bibliothèques OS → Liées
- Format → ELF exécutable

### Architecture
- 🔴 **64-bit:** `-f elf64` (nasm) + défaut (ld)
- 🔵 **32-bit:** `-f elf` (nasm) + `-m elf_i386` (ld)

---

# GNU Debugger (GDB)

## Qu'est-ce que le Debugging?

### Définition
- **Debugging** = Trouver et corriger les bugs (erreurs)
- Processus: Breakpoints → Examiner → Identifier le problème

### Pourquoi en Assembly?
- Code = instructions machine en mémoire
- Breakpoints = adresses mémoire (pas lignes de code)
- Observer comment les registres/mémoire changent

## Installation

### GDB

```bash
sudo apt-get update
sudo apt-get install gdb
```

**Distributions:** Pré-installé sur Parrot OS, PwnBox, et la plupart des distros Linux

## Plugin GEF (Recommandé)

### Qu'est-ce que GEF?

**GEF** = GDB Enhanced Features
- Plugin gratuit et open-source
- Conçu pour **reverse engineering** et **exploitation binaire**
- Excellente documentation
- Interface améliorée et colorée

### Installation

```bash
# Télécharger GEF
wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py

# Activer GEF au démarrage de GDB
echo source ~/.gdbinit-gef.py >> ~/.gdbinit
```

**Documentation:** https://gef.readthedocs.io

## Lancer GDB

### Méthode 1: Directe

```bash
gdb -q ./helloWorld
```

**Output:**
```
...SNIP...
gef➤
```

**Flags:**
- `-q` = Quiet (sans bannière)

### Méthode 2: Avec Script Assembler

```bash
./assembler.sh helloWorld.s -g
```

**Résultat:**
- ✅ Assemble le code
- ✅ Linke le code
- ✅ Lance GDB automatiquement

## Commande `info`

### Vue d'Ensemble

```bash
gef➤ info [target]
```

**Usage:** Affiche informations générales sur le programme

### Aide Intégrée

```bash
gef➤ help info
gef➤ help [commande]
```

## Info Functions

### Commande

```bash
gef➤ info functions
```

### Exemple Output

```
All defined functions:

Non-debugging symbols:
0x0000000000401000  _start
```

**Informations:**
- Adresse mémoire de chaque fonction
- Nom de la fonction
- `_start` = point d'entrée principal

## Info Variables

### Commande

```bash
gef➤ info variables
```

### Exemple Output

```
All defined variables:

Non-debugging symbols:
0x0000000000402000  message
0x0000000000402012  __bss_start
0x0000000000402012  _edata
0x0000000000402018  _end
```

**Informations:**
- `message` = Notre variable personnalisée
- `__bss_start`, `_edata`, `_end` = Variables système (segments mémoire)

## Désassemblage avec `disassemble`

### Commandes

```bash
gef➤ disassemble fonction
gef➤ disas fonction          # Alias court
```

### Exemple: Désassembler `_start`

```bash
gef➤ disas _start
```

**Output:**
```nasm
Dump of assembler code for function _start:
   0x0000000000401000 <+0>:     mov    eax,0x1
   0x0000000000401005 <+5>:     mov    edi,0x1
   0x000000000040100a <+10>:    movabs rsi,0x402000
   0x0000000000401014 <+20>:    mov    edx,0x12
   0x0000000000401019 <+25>:    syscall
   0x000000000040101b <+27>:    mov    eax,0x3c
   0x0000000000401020 <+32>:    mov    edi,0x0
   0x0000000000401025 <+37>:    syscall
End of assembler dump.
```

### Colonnes du Output

| Colonne | Description | Exemple |
|---------|-------------|---------|
| **1** | Adresse mémoire absolue | `0x0000000000401000` |
| **2** | Offset depuis le début de la fonction | `<+0>`, `<+5>`, `<+10>` |
| **3** | Instruction Assembly | `mov eax,0x1` |

## Importance des Adresses Mémoire

### Pourquoi C'est Critique?

```
Adresses mémoire = Points de référence pour:
├─ Examiner variables/opérandes
├─ Placer des breakpoints
└─ Suivre le flux d'exécution
```

### Exemple d'Usage

```bash
# Voir la valeur à une adresse
gef➤ x/s 0x402000           # Examine string à cette adresse

# Placer un breakpoint
gef➤ break *0x0000000000401019   # Break avant syscall
```

## PIE - Position Independent Executable

### Qu'est-ce que PIE?

**PIE** = Exécutable à Position Indépendante

### Adressage $rip-Relatif

```
Adresse affichée:  0x00000000004xxxxx
Adresse réelle:    0xffffffffaa8a25ff

└─ Adresse relative à $rip (Instruction Pointer)
   plutôt qu'adresse absolue en RAM
```

### Pourquoi?

**Avantages:**
- ✅ Sécurité accrue
- ✅ ASLR (Address Space Layout Randomization)
- ✅ Exploitation plus difficile

**Caractéristiques:**
- Adresses dans la Virtual RAM du programme
- Distance relative à `$rip` (Instruction Pointer)
- Peut être désactivé pour réduire risque d'exploitation

### Impact Pratique

```
Sans PIE:  Adresses fixes et prévisibles
Avec PIE:  Adresses changent à chaque exécution
```

## Comparaison Outputs

### disas (GDB) vs objdump

**Similitudes:**
```
Même code Assembly
Même adresses relatives
Même instructions
```

**Différences:**

| Outil | Format | Usage |
|-------|--------|-------|
| **objdump** | Statique (fichier) | Analyse avant exécution |
| **GDB disas** | Dynamique (mémoire) | Analyse pendant exécution |

## Workflow de Debugging

### Étapes Typiques

```
1. Lancer GDB
   └─ gdb -q ./binary

2. Examiner structure
   ├─ info functions
   └─ info variables

3. Désassembler code
   └─ disas _start

4. Identifier points clés
   └─ Noter adresses importantes

5. Placer breakpoints
   └─ break *0x401019

6. Exécuter et examiner
   └─ run, step, examine
```

## Commandes Quick Reference

### Démarrage

```bash
gdb -q ./binary              # Lancer GDB (quiet mode)
./assembler.sh file.s -g     # Assembler + GDB
```

### Information

```bash
info functions               # Liste des fonctions
info variables               # Liste des variables
help [commande]              # Aide sur commande
```

### Désassemblage

```bash
disassemble fonction         # Désassembler fonction
disas fonction               # Alias court
disas _start                 # Désassembler point d'entrée
```

## Tips & Tricks

### GEF
- ✅ Interface colorée et claire
- ✅ Informations automatiques sur registres
- ✅ Contexte visuel amélioré
- ✅ Commandes supplémentaires pour exploitation

### GDB Natif vs GEF

| Fonctionnalité | GDB | GEF |
|----------------|-----|-----|
| Commandes de base | ✅ | ✅ |
| Interface colorée | ❌ | ✅ |
| Context auto | ❌ | ✅ |
| Exploitation helpers | ❌ | ✅ |

### Debugging Assembly
- 🎯 Toujours noter adresses importantes
- 🎯 Comparer avec objdump pour validation
- 🎯 PIE = adresses relatives, pas absolues
- 🎯 Utiliser GEF pour meilleure visibilité

## ⚠️ Points d'Attention

### Adresses Mémoire
```
⚠️ PIE activé = adresses relatifs
⚠️ Adresses changent entre exécutions
⚠️ Utiliser offsets (<+0>, <+5>) pour référence
```

### Variables Système
```
__bss_start, _edata, _end = Variables par défaut
→ Ne pas confondre avec vos variables
```

### Formats d'Adresse
```
0x00000000004xxxxx  → Format PIE (relatif)
0xffffffffaa8a25ff → Format absolu (mémoire réelle)
```

---

# Debugging avec GDB 

## Les 4 Étapes du Debugging

```
┌──────────────────────────────────────────┐
│  1. BREAK   → Placer breakpoints         │
│  2. EXAMINE → Examiner état du programme │
│  3. STEP    → Avancer instruction par    │
│              instruction                  │
│  4. MODIFY  → Modifier valeurs/registres │
└──────────────────────────────────────────┘
```

| Étape | Objectif | Commandes |
|-------|----------|-----------|
| **Break** | Arrêter l'exécution à des points clés | `break`, `b` |
| **Examine** | Inspecter registres/mémoire | `x`, `info`, `registers` |
| **Step** | Progresser dans le code | `si`, `s`, `ni`, `n` |
| **Modify** | Changer valeurs pour tester | `set`, `patch` |

---

## 1️⃣ BREAK - Placer des Breakpoints

### Commandes de Base

```bash
break location     # Placer breakpoint
b location         # Alias court
```

### Types de Breakpoints

#### Par Fonction
```bash
gef➤ b _start
Breakpoint 1 at 0x401000
```

#### Par Adresse Absolue
```bash
gef➤ b *0x40100a
Breakpoint 1 at 0x40100a
```

#### Par Offset
```bash
gef➤ b *_start+10
Breakpoint 1 at 0x40100a
```

> ⚠️ **Important:** L'astérisque `*` indique à GDB de break à l'instruction **stockée** à cette adresse

### Lancer le Programme

```bash
gef➤ run           # Lancer depuis le début
gef➤ r             # Alias court
```

**Output Exemple:**
```
Starting program: ./helloWorld 

Breakpoint 1, 0x0000000000401000 in _start ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rip   : 0x0000000000401000  →  <_start+0> mov eax, 0x1
...SNIP...
───────────────────────────────────────── code:x86:64 ────
 →   0x401000 <_start+0>       mov    eax, 0x1
     0x401005 <_start+5>       mov    edi, 0x1
     0x40100a <_start+10>      movabs rsi, 0x402000
```

---

### Continuer l'Exécution

```bash
gef➤ continue      # Continuer jusqu'au prochain breakpoint
gef➤ c             # Alias court
```

**Différence run vs continue:**

| Commande | Comportement |
|----------|-------------|
| `run` / `r` | Redémarre programme **depuis le début** |
| `continue` / `c` | Continue depuis **position actuelle** |

---

### Gérer les Breakpoints

#### Lister les Breakpoints
```bash
gef➤ info breakpoint
gef➤ info b
```

**Output:**
```
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000000000401000 <_start>
2       breakpoint     keep y   0x000000000040100a <_start+10>
```

#### Désactiver/Activer
```bash
gef➤ disable 1     # Désactiver breakpoint #1
gef➤ enable 1      # Réactiver breakpoint #1
```

#### Supprimer
```bash
gef➤ delete 1      # Supprimer breakpoint #1
gef➤ delete        # Supprimer TOUS les breakpoints
```

---

### Breakpoints Conditionnels

```bash
gef➤ break *0x401000 if $rax == 0x5
```

**Utilisation:** Arrêter uniquement quand une condition est vraie

---

## 2️⃣ EXAMINE - Examiner Données

### Commande `x` (Examine)

#### Syntaxe
```bash
x/FMT ADDRESS
```

#### Format FMT

| Partie | Description | Valeurs Possibles |
|--------|-------------|-------------------|
| **Count** | Nombre de répétitions | `1`, `2`, `4`, `10`, etc. |
| **Format** | Format d'affichage | `x`(hex), `s`(string), `i`(instruction), `d`(decimal) |
| **Size** | Taille mémoire | `b`(byte), `h`(halfword), `w`(word), `g`(giant/8 bytes) |


### Examiner Instructions

#### Commande
```bash
gef➤ x/4ig $rip
```

**Décomposition:**
- `4` = 4 répétitions
- `i` = format instruction
- `g` = taille giant (8 bytes)
- `$rip` = adresse (registre instruction pointer)

**Output:**
```nasm
=> 0x401000 <_start>:      mov    eax,0x1
   0x401005 <_start+5>:    mov    edi,0x1
   0x40100a <_start+10>:   movabs rsi,0x402000
   0x401014 <_start+20>:   mov    edx,0x12
```

### Examiner Strings

#### Commande
```bash
gef➤ x/s 0x402000
```

**Décomposition:**
- Pas de count (défaut = 1)
- `s` = format string
- `0x402000` = adresse de la variable

**Output:**
```
0x402000:	"Hello HTB Academy!"
```

### Examiner en Hexadécimal

#### Commande
```bash
gef➤ x/wx 0x401000
```

**Décomposition:**
- `w` = word (4 bytes)
- `x` = format hexadécimal

**Output:**
```
0x401000 <_start>:	0x000001b8
```

**Interprétation:**
```
Hex:           0x000001b8
Little-Endian: b8 01 00 00
Assembly:      mov eax, 0x1
```

### Examiner Multiple Addresses

#### Hex Dump 4 Words
```bash
gef➤ x/4wx 0x402000
```

**Output:**
```
0x402000:  0x6c6c6548  0x4854206f  0x63412042  0x6d656461
```

**Interprétation:**
```
0x6c6c6548 = "Hell" (little-endian)
0x4854206f = "o HT"
0x63412042 = "B Ac"
0x6d656461 = "adem"
```

### Formats Courants

| Format | Description | Exemple Usage |
|--------|-------------|---------------|
| `x/s` | String | Variables texte |
| `x/i` | Instruction | Code désassemblé |
| `x/x` | Hexadécimal | Données brutes, addresses |
| `x/d` | Décimal | Nombres entiers |
| `x/c` | Caractère | Caractères ASCII |

### Commande GEF `registers`

```bash
gef➤ registers
```

**Output:**
```
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffe310  →  0x0000000000000001
$rbp   : 0x0               
$rsi   : 0x0               
$rdi   : 0x0               
$rip   : 0x0000000000401000  →  <_start+0> mov eax, 0x1
```

**Avantage GEF:** Affichage automatique des registres à chaque breakpoint

## 3️⃣ STEP - Avancer dans le Programme

### Position Actuelle

```
─────────────────────────────────────── code:x86:64 ────
     0x400ffe                  add    BYTE PTR [rax], al
 →   0x401000 <_start+0>       mov    eax, 0x1
     0x401005 <_start+5>       mov    edi, 0x1
```

> ⚠️ **Symbole →** = Position actuelle (instruction **non encore exécutée**)

### `stepi` / `si` - Step Instruction

#### Commande
```bash
gef➤ si            # Step 1 instruction
gef➤ si 3          # Step 3 instructions
```

**Comportement:** Avance **une instruction Assembly** à la fois

**Exemple:**
```bash
gef➤ si
0x0000000000401005 in _start ()
   0x400fff                  add    BYTE PTR [rax+0x1], bh
 →   0x401005 <_start+5>       mov    edi, 0x1
     0x40100a <_start+10>      movabs rsi, 0x402000
```

### `step` / `s` - Step (High-Level)

#### Commande
```bash
gef➤ s             # Step jusqu'à prochaine ligne/fonction
```

**Comportement:**
- Continue jusqu'à **sortie de la fonction actuelle**
- OU jusqu'à **entrée dans une nouvelle fonction**
- En Assembly: souvent sort complètement de `_start`

**Exemple:**
```bash
gef➤ step

Single stepping until exit from function _start,
which has no line number information.
Hello HTB Academy!
[Inferior 1 (process 14732) exited normally]
```

### Comparaison des Commandes Step

| Commande | Niveau | Entre dans fonctions? | Usage |
|----------|--------|----------------------|-------|
| **si** (stepi) | Instruction Assembly | Oui | Debugging bas niveau |
| **s** (step) | Ligne de code | Oui | Debugging haut niveau |
| **ni** (nexti) | Instruction Assembly | Non (skip) | Éviter fonctions |
| **n** (next) | Ligne de code | Non (skip) | Éviter fonctions |

### Astuce: Repeat Last Command

```bash
gef➤ si
[... output ...]
gef➤ [ENTER]      # Répète 'si'
[... output ...]
gef➤ [ENTER]      # Répète encore 'si'
```

**Pratique pour:** Avancer rapidement sans retaper la commande

## 4️⃣ MODIFY - Modifier Valeurs

### Pourquoi Modifier?

```
Tester différentes conditions SANS:
├─ Recompiler le code
├─ Modifier le source
└─ Redémarrer le programme
```

**Applications:**
- 🧪 Tester exploits
- 🐛 Déboguer problèmes
- 🔬 Comprendre comportements

### Commande GEF `patch`

#### Aide
```bash
gef➤ help patch
```

**Syntaxe:**
```bash
patch (qword|dword|word|byte) LOCATION VALUE
patch string LOCATION "string"
```

### Modifier une String

#### Exemple Complet

```bash
# 1. Placer breakpoint avant syscall
gef➤ break *0x401019
Breakpoint 1 at 0x401019

# 2. Lancer programme
gef➤ r

# 3. Patcher la string
gef➤ patch string 0x402000 "Patched!\\x0a"

# 4. Continuer
gef➤ c

Continuing.
Patched!
 Academy!
```

**Résultat:** String partiellement modifiée

**Pourquoi "Academy!" reste?**
- Notre string = 9 bytes (`Patched!\n`)
- Ancienne string = 18 bytes
- On n'a modifié que les 9 premiers bytes!

### Modifier un Registre

#### Commande `set`

```bash
gef➤ set $rdx=0x9
```

**Utilisation:** Ajuster la longueur pour syscall write

#### Exemple Complet

```bash
# 1. Breakpoint
gef➤ break *0x401019
Breakpoint 1 at 0x401019

# 2. Run
gef➤ r

# 3. Patcher string
gef➤ patch string 0x402000 "Patched!\\x0a"

# 4. Ajuster longueur dans $rdx
gef➤ set $rdx=0x9

# 5. Continuer
gef➤ c

Continuing.
Patched!
```

**Résultat:** String complètement modifiée, longueur correcte! 

### Types de Patch

#### Patch Byte
```bash
gef➤ patch byte 0x402000 0x41    # 'A'
```

#### Patch Word (2 bytes)
```bash
gef➤ patch word 0x402000 0x4241  # 'AB'
```

#### Patch Double Word (4 bytes)
```bash
gef➤ patch dword 0x402000 0x44434241  # 'ABCD'
```

#### Patch Quad Word (8 bytes)
```bash
gef➤ patch qword 0x402000 0x4847464544434241  # 'ABCDEFGH'
```

### Modifier Flags

```bash
gef➤ set $eflags = 0x246
```

**Usage:** Forcer conditions (zero flag, carry flag, etc.)

## Tips & Astuces

### GEF Auto-Display

**À chaque breakpoint, GEF affiche automatiquement:**
- ✅ Registres
- ✅ Stack
- ✅ Code (prochaines instructions)
- ✅ Threads
- ✅ Trace

**Gain de temps énorme!**

### Raccourcis Clavier

```bash
[ENTER]            # Répète dernière commande
Ctrl+C             # Interrompt exécution
Ctrl+D             # Quitte GDB
```

### Examination Par Défaut

```bash
gef➤ x/4ig $rip    # Examine en instruction giant
gef➤ x $rip        # Utilise derniers format/size (ig)
```

**Astuce:** Pas besoin de respécifier format si identique au précédent

### Little-Endian Reminder

```bash
gef➤ x/wx 0x401000
0x401000: 0x000001b8
```

**Lecture:**
```
Affiché:  0x000001b8
Stocké:   b8 01 00 00  (inversé!)
```

## ⚠️ Points d'Attention

### run vs continue

```
❌ Utiliser 'r' avec breakpoint actif
   → Redémarre depuis début
   
✅ Utiliser 'c' avec breakpoint actif
   → Continue depuis position actuelle
```

### Taille des Patches

```
⚠️ Patcher string plus courte que l'originale
   → Laisse des restes de l'ancienne string
   
✅ Ajuster aussi la longueur utilisée (ex: $rdx pour write)
```

### Instruction Pointer

```
→ Symbole indique instruction NON ENCORE EXÉCUTÉE
   Sera exécutée au prochain 'si' ou 'c'
```










