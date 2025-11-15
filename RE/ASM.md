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

