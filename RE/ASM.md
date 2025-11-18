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

---

# Instructions de Déplacement de Données

## Instructions Principales

### Vue d'Ensemble

| Instruction | Description | Exemple | Résultat |
|-------------|-------------|---------|----------|
| **mov** | Copier données ou charger valeur immédiate | `mov rax, 1` | `rax = 1` |
| **lea** | Charger adresse pointant vers valeur | `lea rax, [rsp+5]` | `rax = adresse de (rsp+5)` |
| **xchg** | Échanger données entre deux registres | `xchg rax, rbx` | `rax ↔ rbx` |

## Instruction `mov`

### Principe Fondamental

> ⚠️ **mov = COPIE, pas déplacement!**
> 
> La source reste **inchangée** après l'opération

```nasm
mov rax, rbx    ; rax = rbx (rbx reste identique)
```

### Charger Valeurs Immédiates

#### Syntaxe
```nasm
mov destination, valeur_immédiate
```

#### Exemple: Initialisation Fibonacci
```nasm
global  _start

section .text
_start:
    mov rax, 0    ; F0 = 0
    mov rbx, 1    ; F1 = 1
```

**Résultat:**
```
$rax : 0x0
$rbx : 0x1
```

### Optimisation: Taille des Registres

#### Problème d'Efficacité

```nasm
mov rax, 1      ; Inefficace: charge 0x0000000000000001 (8 bytes)
mov al, 1       ; Efficace: charge 0x01 (1 byte)
```

#### Comparaison Shellcode

**Code:**
```nasm
global  _start

section .text
_start:
    mov rax, 0    ; Version inefficace
    mov rbx, 1    ; Version inefficace
    mov bl, 1     ; Version efficace
```

**Désassemblage:**
```
0:  b8 00 00 00 00       mov    eax,0x0      ; 5 bytes
5:  bb 01 00 00 00       mov    ebx,0x1      ; 5 bytes
a:  b3 01                mov    bl,0x1       ; 2 bytes ✅
```

**Observation:**
- `mov rbx, 1` → 5 bytes
- `mov bl, 1` → 2 bytes
- **Plus de 2x plus efficace!**

### Version Optimisée

```nasm
global  _start

section .text
_start:
    mov al, 0     ; F0 = 0 (1 byte)
    mov bl, 1     ; F1 = 1 (1 byte)
```

**Avantages:**
- ✅ Shellcode plus court
- ✅ Plus rapide à exécuter
- ✅ Moins de mémoire utilisée

**Règle d'Or:**
> Toujours utiliser la **plus petite taille de registre** nécessaire!

## Instruction `xchg`

### Syntaxe
```nasm
xchg operand1, operand2
```

### Fonctionnement

```nasm
; Avant
rax = 5
rbx = 10

xchg rax, rbx

; Après
rax = 10
rbx = 5
```

### Exemple Pratique

```nasm
global  _start

section .text
_start:
    mov al, 0     ; rax = 0
    mov bl, 1     ; rbx = 1
    xchg rax, rbx ; Échanger
```

**Avant xchg:**
```
$rax : 0x0
$rbx : 0x1
```

**Après xchg:**
```
$rax : 0x1
$rbx : 0x0
```

## Pointeurs d'Adresses

### Concept des Pointeurs

```
Registre Pointeur → Contient une ADRESSE → Qui pointe vers VALEUR
```

**Exemple:**
```
$rsp : 0x00007fffffffe490  →  0x0000000000000001
       └─ Adresse immédiate     └─ Valeur finale
```

### Registres Pointeurs Principaux

| Registre | Nom | Pointe vers |
|----------|-----|-------------|
| **rsp** | Stack Pointer | Sommet de la stack |
| **rbp** | Base Pointer | Base de la stack |
| **rip** | Instruction Pointer | Prochaine instruction |

## Déplacement de Pointeurs

### Sans Crochets: Copie l'Adresse

```nasm
mov rax, rsp
```

**Effet:**
```
rsp = 0x00007fffffffe490  →  0x1

Après mov rax, rsp:
rax = 0x00007fffffffe490  (copie l'ADRESSE)
```

### Avec Crochets `[]`: Déréférence le Pointeur

```nasm
mov rax, [rsp]
```

**Signification:** `[]` = **"valeur à l'adresse"**

**Effet:**
```
rsp = 0x00007fffffffe490  →  0x1

Après mov rax, [rsp]:
rax = 0x1  (copie la VALEUR pointée)
```

### Exemple Complet: Avec vs Sans Crochets

#### Code
```nasm
global  _start

section .text
_start:
    mov rax, rsp      ; Copie l'adresse
    mov rax, [rsp]    ; Copie la valeur
```

#### Debug Étape 1: `mov rax, rsp`

```bash
gef➤ b _start
gef➤ r
gef➤ si
```

**Résultat:**
```
─────────────────────────────── code:x86:64 ────
 →   0x401000 <_start+0>       mov    rax, rsp
───────────────────────────────── registers ────
$rax   : 0x00007fffffffe490  →  0x0000000000000001
$rsp   : 0x00007fffffffe490  →  0x0000000000000001
```

**rax = adresse (0x00007fffffffe490)**

#### Debug Étape 2: `mov rax, [rsp]`

```bash
gef➤ si
```

**Résultat:**
```
─────────────────────────────── code:x86:64 ────
 →   0x401003 <_start+3>       mov    rax, QWORD PTR [rsp]
───────────────────────────────── registers ────
$rax   : 0x1               
$rsp   : 0x00007fffffffe490  →  0x0000000000000001
```

**rax = valeur (0x1)**

### Offsets avec Pointeurs

#### Syntaxe
```nasm
mov rax, [rsp+10]    ; Valeur à rsp+10
lea rax, [rsp+10]    ; Adresse de rsp+10
```

#### Calcul d'Offset

```
rsp = 0x7fffffffe490

[rsp+10] = valeur à l'adresse (0x7fffffffe490 + 0x10)
         = valeur à 0x7fffffffe4a0
```

## Instruction `lea` (Load Effective Address)

### Définition

**lea** = Charger l'**adresse** d'une valeur (pas la valeur elle-même)

### Différence mov vs lea

| Instruction | Que fait-elle? | Exemple | Résultat |
|-------------|----------------|---------|----------|
| **mov rax, rsp** | Copie adresse | `rsp = 0x490` | `rax = 0x490` |
| **lea rax, [rsp]** | Charge adresse | `rsp = 0x490` | `rax = 0x490` |
| **mov rax, [rsp]** | Copie valeur | `[rsp] = 0x1` | `rax = 0x1` |

**Pour adresses directes:** `mov` et `lea` sont identiques

### Utilité: Offsets

#### mov avec offset → Copie VALEUR
```nasm
mov rax, [rsp+10]    ; rax = valeur à (rsp+10)
```

#### lea avec offset → Charge ADRESSE
```nasm
lea rax, [rsp+10]    ; rax = adresse de (rsp+10)
```

> ⚠️ **Important:** `mov` ne peut PAS charger une adresse avec offset!

### Exemple Complet: lea vs mov

#### Code
```nasm
global  _start

section .text
_start:
    lea rax, [rsp+10]    ; Charge adresse
    mov rax, [rsp+10]    ; Charge valeur
```

#### Debug Étape 1: `lea rax, [rsp+10]`

```bash
gef➤ b _start
gef➤ r
gef➤ si
```

**Résultat:**
```
─────────────────────────────── code:x86:64 ────
 →   0x401003 <_start+0>       lea    rax, [rsp+0xa]
───────────────────────────────── registers ────
$rax   : 0x00007fffffffe49a  →  0x000000007fffffff
$rsp   : 0x00007fffffffe490  →  0x0000000000000001
```

**Calcul:**
```
rsp = 0x7fffffffe490
rax = 0x7fffffffe49a  (= rsp + 0xa = rsp + 10) ✅
```

#### Debug Étape 2: `mov rax, [rsp+10]`

```bash
gef➤ si
```

**Résultat:**
```
─────────────────────────────── code:x86:64 ────
 →   0x401008 <_start+8>       mov    rax, QWORD PTR [rsp+0xa]
───────────────────────────────── registers ────
$rax   : 0x7fffffff        
$rsp   : 0x00007fffffffe490  →  0x0000000000000001
```

**mov charge la valeur stockée à [rsp+10]** ✅

## Tableau Récapitulatif

### mov vs lea - Tous les Cas

| Code | Opération | Résultat | Usage |
|------|-----------|----------|-------|
| `mov rax, 5` | Charge valeur immédiate | `rax = 5` | Constantes |
| `mov rax, rbx` | Copie registre | `rax = rbx` | Transfert données |
| `mov rax, rsp` | Copie adresse | `rax = adresse_de_rsp` | Copie pointeur |
| `mov rax, [rsp]` | Déréférence pointeur | `rax = valeur_à_rsp` | Accès mémoire |
| `mov rax, [rsp+10]` | Déréférence avec offset | `rax = valeur_à_(rsp+10)` | Accès avec décalage |
| `lea rax, [rsp]` | Charge adresse | `rax = adresse_de_rsp` | Même que mov rsp |
| `lea rax, [rsp+10]` | Charge adresse+offset | `rax = adresse_de_(rsp+10)` | **Calcul d'adresse** |

## Cas d'Usage Pratiques

### 1. Variables Simples
```nasm
mov rax, 42         ; Charger constante
mov rbx, rax        ; Copier entre registres
```

### 2. Accès Tableau
```nasm
lea rsi, [array]    ; rsi = pointeur vers array
mov rax, [rsi]      ; rax = premier élément
mov rbx, [rsi+8]    ; rbx = deuxième élément (8 bytes plus loin)
```

### 3. Stack Frame
```nasm
lea rbp, [rsp]      ; Sauvegarder stack pointer
mov rax, [rbp-8]    ; Accès variable locale
```

### 4. Syscall avec String
```nasm
section .data
    msg db "Hello", 0xa

section .text
    lea rsi, [msg]   ; rsi = pointeur vers "Hello"
    mov rdx, 6       ; longueur
    ; ... syscall write
```

## Notes Spéciales: QWORD PTR

### Apparition dans GDB

```nasm
mov rax, [rsp]
```

**Désassemblé devient:**
```nasm
mov rax, QWORD PTR [rsp]
```

**Signification:**
- `QWORD` = Quad Word = 8 bytes = 64 bits
- `PTR` = Pointer (pointeur)
- **nasm ajoute automatiquement** la spécification de taille

### Tailles Possibles

| Préfixe | Taille | Exemple |
|---------|--------|---------|
| `BYTE PTR` | 1 byte | `mov al, BYTE PTR [rsp]` |
| `WORD PTR` | 2 bytes | `mov ax, WORD PTR [rsp]` |
| `DWORD PTR` | 4 bytes | `mov eax, DWORD PTR [rsp]` |
| `QWORD PTR` | 8 bytes | `mov rax, QWORD PTR [rsp]` |

## Règles d'Or

### Efficacité du Code

```
✅ Utiliser le plus petit registre nécessaire
   mov al, 1    (2 bytes shellcode)
   
❌ Éviter les registres trop grands
   mov rax, 1   (5+ bytes shellcode)
```

### Pointeurs

```
Sans crochets [] = Adresse
Avec crochets [] = Valeur à l'adresse
```

### mov vs lea

```
mov = Copie données (valeurs ou adresses simples)
lea = Calcule et charge adresses (avec offsets)
```

## Exercices Pratiques

### Exercice 1: Prédire les Valeurs

```nasm
mov rax, 10
mov rbx, rax
xchg rax, rbx
mov rcx, [rsp]
lea rdx, [rsp+8]
```

**Questions:**
1. Quelle est la valeur de rbx après ligne 2?
2. Que contient rax après ligne 3?
3. rcx contient une adresse ou une valeur?
4. rdx contient quoi?

**Réponses:**
1. `rbx = 10`
2. `rax = 10` (inchangé par xchg car rax = rbx)
3. Valeur (à cause de `[]`)
4. Adresse de (rsp+8)

### Exercice 2: Corriger le Code

**Code Inefficace:**
```nasm
mov rax, 0
mov rbx, 1
mov rcx, 2
```

**Version Optimisée:**
```nasm
mov al, 0
mov bl, 1
mov cl, 2
```

## Quick Reference

### Instructions Essentielles

```nasm
; Valeurs immédiates
mov rax, 42

; Entre registres
mov rax, rbx

; Copier adresse
mov rax, rsp

; Déréférencer
mov rax, [rsp]

; Avec offset (valeur)
mov rax, [rsp+10]

; Avec offset (adresse)
lea rax, [rsp+10]

; Échanger
xchg rax, rbx
```

## Application: Début Fibonacci

### Code Initial

```nasm
global  _start

section .text
_start:
    mov al, 0     ; F0 = 0 (optimisé: 1 byte)
    mov bl, 1     ; F1 = 1 (optimisé: 1 byte)
    ; ... suite du programme
```
---

# Instructions Arithmétiques

## Vue d'Ensemble

### Catégories d'Instructions

```
Instructions Arithmétiques
├─ Unaires (1 opérande)
│  ├─ inc (incrémenter)
│  └─ dec (décrémenter)
│
├─ Binaires (2 opérandes)
│  ├─ add (addition)
│  ├─ sub (soustraction)
│  └─ imul (multiplication)
│
└─ Bitwise (opérations bit par bit)
   ├─ not (inversion)
   ├─ and (ET logique)
   ├─ or (OU logique)
   └─ xor (OU exclusif)
```

**Traitement:** Principalement par l'**ALU** (Arithmetic Logic Unit) du CPU

## 1️⃣ Instructions Unaires

### Définition
**Unaire** = Prend **1 seul opérande**

### Instructions Principales

| Instruction | Description | Exemple | Résultat |
|-------------|-------------|---------|----------|
| **inc** | Incrémenter de 1 | `inc rax` | `rax++` ou `rax += 1` |
| **dec** | Décrémenter de 1 | `dec rax` | `rax--` ou `rax -= 1` |

### `inc` - Incrémentation

#### Syntaxe
```nasm
inc operand
```

#### Exemple: `rax = 1`
```nasm
inc rax        ; rax devient 2
```

**Équivalent en C:**
```c
rax++;
// ou
rax += 1;
```

---

### `dec` - Décrémentation

#### Syntaxe
```nasm
dec operand
```

#### Exemple: `rax = 5`
```nasm
dec rax        ; rax devient 4
```

**Équivalent en C:**
```c
rax--;
// ou
rax -= 1;
```

### Application: Fibonacci

#### Code
```nasm
global  _start

section .text
_start:
    mov al, 0     ; F0 = 0
    mov bl, 0     ; Initialise bl à 0
    inc bl        ; F1 = 1 (incrémente bl)
```

#### Debug avec GDB

**Avant inc:**
```
$rbx   : 0x0
```

**Après inc bl:**
```
$rbx   : 0x1
```

#### Avantage
✅ Plus lisible que `mov bl, 1`  
✅ Utile dans boucles (compteurs)  
✅ Compact (instruction courte)

## 2️⃣ Instructions Binaires

### Définition
**Binaire** = Prend **2 opérandes** (source + destination)

### Règle Fondamentale
> ⚠️ **Résultat toujours stocké dans DESTINATION**  
> Source reste **INCHANGÉE**

### Instructions Principales

| Instruction | Description | Exemple | Résultat |
|-------------|-------------|---------|----------|
| **add** | Addition | `add rax, rbx` | `rax = rax + rbx` |
| **sub** | Soustraction | `sub rax, rbx` | `rax = rax - rbx` |
| **imul** | Multiplication | `imul rax, rbx` | `rax = rax * rbx` |

### `add` - Addition

#### Syntaxe
```nasm
add destination, source
```

#### Comportement
```
destination = destination + source
source = inchangée
```

#### Exemple: `rax = 5`, `rbx = 3`
```nasm
add rax, rbx
```

**Résultat:**
```
rax = 5 + 3 = 8
rbx = 3 (inchangé)
```

**Équivalent C:**
```c
rax = rax + rbx;
// ou
rax += rbx;
```

### Application: Calcul Fibonacci

#### Formule Fibonacci
```
Fn = Fn-1 + Fn-2
```

#### Code Étape par Étape
```nasm
global  _start

section .text
_start:
    mov al, 0     ; F0 = 0 (rax = 0)
    mov bl, 0     ; bl = 0
    inc bl        ; F1 = 1 (rbx = 1)
    add rax, rbx  ; F2 = F0 + F1 = 0 + 1 = 1
```

#### Debug avec GDB

**Avant add:**
```
$rax   : 0x0
$rbx   : 0x1
```

**Après add rax, rbx:**
```
$rax   : 0x1    (0x0 + 0x1 = 0x1) ✅
$rbx   : 0x1    (inchangé) ✅
```

### `sub` - Soustraction

#### Syntaxe
```nasm
sub destination, source
```

#### Comportement
```
destination = destination - source
source = inchangée
```

#### Exemple: `rax = 10`, `rbx = 3`
```nasm
sub rax, rbx
```

**Résultat:**
```
rax = 10 - 3 = 7
rbx = 3 (inchangé)
```

**Équivalent C:**
```c
rax = rax - rbx;
// ou
rax -= rbx;
```

### `imul` - Multiplication

#### Syntaxe
```nasm
imul destination, source
```

#### Comportement
```
destination = destination * source
source = inchangée
```

#### Exemple: `rax = 4`, `rbx = 5`
```nasm
imul rax, rbx
```

**Résultat:**
```
rax = 4 * 5 = 20
rbx = 5 (inchangé)
```

**Équivalent C:**
```c
rax = rax * rbx;
// ou
rax *= rbx;
```

> **Note:** `imul` = Multiplication signée (signed)  
> Il existe aussi `mul` pour multiplication non-signée

## 3️⃣ Instructions Bitwise

### Définition
**Bitwise** = Opérations au **niveau des bits** (0 et 1)

### Vue d'Ensemble

| Instruction | Type | Opération |
|-------------|------|-----------|
| **not** | Unaire | Inversion (0→1, 1→0) |
| **and** | Binaire | ET logique |
| **or** | Binaire | OU logique |
| **xor** | Binaire | OU exclusif |

### `not` - Inversion Bitwise

#### Syntaxe
```nasm
not operand
```

#### Comportement
Inverse **tous les bits**:
- `0` devient `1`
- `1` devient `0`

#### Exemple: `rax = 1` (`00000001` en binaire)
```nasm
not rax
```

**Résultat:**
```
Avant:  00000001  (1)
NOT
Après:  11111110  (254 en 8-bit unsigned)
```

### `and` - ET Logique Bitwise

#### Syntaxe
```nasm
and destination, source
```

#### Table de Vérité AND

| Bit A | Bit B | A AND B |
|-------|-------|---------|
| 0 | 0 | 0 |
| 0 | 1 | 0 |
| 1 | 0 | 0 |
| 1 | 1 | **1** ✅ |

**Règle:** Résultat = 1 **seulement si les deux bits sont 1**

#### Exemple: `rax = 1`, `rbx = 2`
```nasm
and rax, rbx
```

**Calcul:**
```
rax:  00000001  (1)
rbx:  00000010  (2)
AND
      00000000  (0)
```

**Résultat:** `rax = 0`

### `or` - OU Logique Bitwise

#### Syntaxe
```nasm
or destination, source
```

#### Table de Vérité OR

| Bit A | Bit B | A OR B |
|-------|-------|--------|
| 0 | 0 | 0 |
| 0 | 1 | **1** ✅ |
| 1 | 0 | **1** ✅ |
| 1 | 1 | **1** ✅ |

**Règle:** Résultat = 1 **si au moins un bit est 1**

#### Exemple: `rax = 1`, `rbx = 2`
```nasm
or rax, rbx
```

**Calcul:**
```
rax:  00000001  (1)
rbx:  00000010  (2)
OR
      00000011  (3)
```

**Résultat:** `rax = 3`

### `xor` - OU Exclusif Bitwise

#### Syntaxe
```nasm
xor destination, source
```

#### Table de Vérité XOR

| Bit A | Bit B | A XOR B |
|-------|-------|---------|
| 0 | 0 | 0 |
| 0 | 1 | **1** ✅ |
| 1 | 0 | **1** ✅ |
| 1 | 1 | 0 |

**Règle:** Résultat = 1 **si les bits sont différents**

#### Exemple: `rax = 1`, `rbx = 2`
```nasm
xor rax, rbx
```

**Calcul:**
```
rax:  00000001  (1)
rbx:  00000010  (2)
XOR
      00000011  (3)
```

**Résultat:** `rax = 3`

## XOR - L'Astuce Magique

### Mettre un Registre à Zéro

#### Propriété XOR
```
A XOR A = 0
(bits identiques → 0)
```

#### Usage: Zéroïsation Efficace

**Méthode Inefficace:**
```nasm
mov rax, 0        ; 5+ bytes
```

**Méthode Efficace:**
```nasm
xor rax, rax      ; 2-3 bytes ✅
```

**Pourquoi ça marche?**
```
Exemple: rax = 5 (00000101)

  00000101
XOR
  00000101
= 00000000  (0) ✅
```

**Tous les bits identiques → Tous deviennent 0!**

### Application: Fibonacci Optimisé

#### Avant (moins efficace)
```nasm
global  _start

section .text
_start:
    mov al, 0     ; 2 bytes
    mov bl, 0     ; 2 bytes
    inc bl
    add rax, rbx
```

#### Après (optimisé avec XOR)
```nasm
global  _start

section .text
_start:
    xor rax, rax  ; 2-3 bytes ✅ Plus court!
    xor rbx, rbx  ; 2-3 bytes ✅
    inc rbx
    add rax, rbx
```

#### Debug avec GDB

**Après xor rax, rax:**
```
$rax   : 0x0  ✅
```

**Après xor rbx, rbx:**
```
$rbx   : 0x0  ✅
```

**Après inc rbx:**
```
$rbx   : 0x1  ✅
```

**Après add rax, rbx:**
```
$rax   : 0x1  ✅ (0 + 1 = 1)
$rbx   : 0x1  ✅ (inchangé)
```

**Résultat:** Même comportement, code plus court!

## Tableaux Récapitulatifs

### Instructions Unaires

| Instruction | Effet | Avant | Après |
|-------------|-------|-------|-------|
| `inc rax` | `rax + 1` | `rax = 5` | `rax = 6` |
| `dec rax` | `rax - 1` | `rax = 5` | `rax = 4` |

### Instructions Binaires

| Instruction | Effet | Exemple (rax=5, rbx=3) | Résultat |
|-------------|-------|------------------------|----------|
| `add rax, rbx` | `rax = rax + rbx` | `5 + 3` | `rax = 8, rbx = 3` |
| `sub rax, rbx` | `rax = rax - rbx` | `5 - 3` | `rax = 2, rbx = 3` |
| `imul rax, rbx` | `rax = rax * rbx` | `5 * 3` | `rax = 15, rbx = 3` |

### Instructions Bitwise

| Instruction | Exemple (rax=1, rbx=2) | Binaire | Résultat |
|-------------|------------------------|---------|----------|
| `not rax` | `NOT 00000001` | `11111110` | `rax = 254` |
| `and rax, rbx` | `00000001 AND 00000010` | `00000000` | `rax = 0` |
| `or rax, rbx` | `00000001 OR 00000010` | `00000011` | `rax = 3` |
| `xor rax, rbx` | `00000001 XOR 00000010` | `00000011` | `rax = 3` |

### XOR Spécial: Zéroïsation

| Opération | Binaire | Résultat |
|-----------|---------|----------|
| `xor rax, rax` | Tout bit identique | `rax = 0` |
| `xor rbx, rbx` | Tout bit identique | `rbx = 0` |
| `xor rcx, rcx` | Tout bit identique | `rcx = 0` |

## Cas d'Usage Pratiques

### 1. Compteur de Boucle
```nasm
xor rcx, rcx      ; rcx = 0 (compteur)
loop_start:
    inc rcx       ; rcx++
    ; ... code ...
    cmp rcx, 10
    jl loop_start ; Répéter si rcx < 10
```

### 2. Calcul Fibonacci
```nasm
; F0 = 0, F1 = 1
xor rax, rax      ; F0 = 0
xor rbx, rbx
inc rbx           ; F1 = 1

; F2 = F1 + F0
add rax, rbx      ; F2 = 0 + 1 = 1
```

### 3. Masquage avec AND
```nasm
mov rax, 0xFF     ; rax = 11111111
and rax, 0x0F     ; Garder seulement 4 bits de droite
                  ; rax = 00001111
```

### 4. Mise à 1 de Bits avec OR
```nasm
mov rax, 0x00     ; rax = 00000000
or rax, 0x05      ; Mettre bits 0 et 2 à 1
                  ; rax = 00000101
```

## Optimisations Shellcode

### Comparaison Tailles

| Opération | Inefficace | Efficace | Gain |
|-----------|------------|----------|------|
| Zéro | `mov rax, 0` (5 bytes) | `xor rax, rax` (3 bytes) | **40%** |
| Incrément +1 | `add rax, 1` (4 bytes) | `inc rax` (3 bytes) | **25%** |
| Décrément -1 | `sub rax, 1` (4 bytes) | `dec rax` (3 bytes) | **25%** |

**Conseil:** Toujours privilégier les instructions les plus courtes!

## Debug Tips

### Vérifier Opérations Binaires

```bash
gef➤ b _start
gef➤ r

# Avant add
gef➤ info registers rax rbx
gef➤ si

# Après add
gef➤ info registers rax rbx
# Vérifier: rax = ancienne_rax + rbx
```

### Observer Bits avec XOR

```bash
gef➤ x/t $rax      # Afficher en binaire (t = two's complement)
gef➤ si
gef➤ x/t $rax      # Comparer avant/après
```

## ⚠️ Points d'Attention

### Source vs Destination

```
❌ Ne PAS confondre ordre!
   sub rax, rbx  =  rax - rbx
   sub rbx, rax  =  rbx - rax  (différent!)
   
✅ Résultat toujours dans DESTINATION (1er opérande)
```

### Overflow

```
⚠️ Addition/Multiplication peuvent overflow
   add rax, rbx  où rax+rbx > max(rax)
   → Résultat modulé (wrap around)
```

### Signed vs Unsigned

```
imul = Multiplication signée
mul  = Multiplication non-signée
```

## Fibonacci Complet (Jusqu'ici)

### Code Optimisé

```nasm
global  _start

section .text
_start:
    xor rax, rax  ; F0 = 0 (optimisé avec xor)
    xor rbx, rbx
    inc rbx       ; F1 = 1 (incrémentation)
    add rax, rbx  ; F2 = F0 + F1 = 0 + 1 = 1
```

### Résultat GDB

```
Initial:
$rax   : 0x0
$rbx   : 0x0

Après inc:
$rbx   : 0x1

Après add:
$rax   : 0x1  (F2 = 1 ✅)
$rbx   : 0x1  (F1 = 1 ✅)
```

## Pro Tips

### Shellcoding

```
✅ xor rax, rax    (2-3 bytes)
❌ mov rax, 0      (5+ bytes)

✅ inc rax         (3 bytes)
❌ add rax, 1      (4 bytes)
```

### Debugging

```bash
# Comparer avant/après
gef➤ info registers
gef➤ si
gef➤ info registers
```

### Bitwise Power

```nasm
; Masquer
and rax, 0xFF      ; Garder seulement 8 bits bas

; Mettre à 1
or rax, 0x80       ; Mettre bit 7 à 1

; Toggle
xor rax, 0xFF      ; Inverser 8 bits bas
```

---

# Boucles (Loops)

## Instructions de Contrôle de Flux

### Vue d'Ensemble

**Assembly = Line-based** (exécution séquentielle ligne par ligne)

**Mais les programmes réels sont plus complexes!**

```
Programme Simple:     Programme Réel:
Ligne 1              ┌─ Ligne 1
Ligne 2              │  Ligne 2
Ligne 3              │  Ligne 3 ──┐
Ligne 4              │  Ligne 4   │ Loop
Ligne 5              │  Ligne 5   │
                     └─ Ligne 6 ◄─┘
                        Ligne 7
                        Ligne 8 → Branch
```

### Types d'Instructions de Contrôle

```
Instructions de Contrôle
├─ Loops (Boucles)
│  └─ Répéter instructions N fois
│
├─ Branching (Branchements)
│  └─ Sauts conditionnels (if/else)
│
└─ Function Calls (Appels de Fonction)
   └─ Exécuter sous-routines
```

## Structure des Boucles

### Concept

**Boucle** = Ensemble d'instructions qui se répètent `rcx` fois

### Anatomie d'une Boucle

```nasm
mov rcx, N          ; Nombre d'itérations

labelBoucle:
    instruction 1    ; Ces instructions
    instruction 2    ; seront répétées
    instruction 3    ; N fois
    loop labelBoucle ; Décrémente rcx et saute
```

### Fonctionnement de `loop`

```
┌─────────────────────────────────┐
│  loop labelBoucle               │
│         ↓                       │
│  1. dec rcx  (rcx = rcx - 1)   │
│  2. if rcx != 0: jump to label │
│  3. if rcx == 0: continue      │
└─────────────────────────────────┘
```
## Instructions Loop

### Instruction `mov rcx, N`

**Syntaxe:**
```nasm
mov rcx, nombre_iterations
```

**Fonction:** Initialise le compteur de boucle

**Exemple:**
```nasm
mov rcx, 10        ; Boucle 10 fois
```

### Instruction `loop`

**Syntaxe:**
```nasm
loop label
```

**Fonction:**
1. Décrémente `rcx` (rcx--)
2. Si `rcx != 0` → Saute au label
3. Si `rcx == 0` → Continue après la boucle

**Exemple:**
```nasm
loop_start:
    ; instructions
    loop loop_start
```

## Application: Boucle Fibonacci

### Logique de Calcul

#### État Initial
```
Last (rax) = 0
Current (rbx) = 1
```

#### Itération
```
1. Next = Last + Current
   → add rax, rbx (rax = 0 + 1 = 1)

2. Last = Current
3. Current = Next
   → xchg rax, rbx (swap valeurs)

4. Répéter
```

### Exemple Itération Manuelle

```
Début:
Last = 0, Current = 1

Itération 1:
├─ Next = 0 + 1 = 1
├─ Last = 1 (ancien Current)
└─ Current = 1 (Next)
   Résultat: 1, 1

Itération 2:
├─ Next = 1 + 1 = 2
├─ Last = 1
└─ Current = 2
   Résultat: 1, 2

Itération 3:
├─ Next = 1 + 2 = 3
├─ Last = 2
└─ Current = 3
   Résultat: 2, 3

Itération 4:
├─ Next = 2 + 3 = 5
├─ Last = 3
└─ Current = 5
   Résultat: 3, 5
```

**Séquence:** 0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55...

## Debug avec GDB
### Itération 0 (Avant 1ère boucle)

```
───────────────────────────────── registers ────
$rax   : 0x0         (F0 = 0)
$rbx   : 0x1         (F1 = 1)
$rcx   : 0xa         (10 itérations)
```

**État:** Valeurs initiales, 10 itérations à faire

### Itération 1

```bash
gef➤ c                  # Continue
```

```
───────────────────────────────── registers ────
$rax   : 0x1         (F1 = 1)
$rbx   : 0x1         (F2 = 1)
$rcx   : 0x9         (9 itérations restantes)
```

**Calcul:**
- add: `0 + 1 = 1`
- xchg: rax=1, rbx=1
- loop: rcx=9

### Itération 2

```bash
gef➤ c
```

```
───────────────────────────────── registers ────
$rax   : 0x1         (F2 = 1)
$rbx   : 0x2         (F3 = 2)
$rcx   : 0x8
```

**Calcul:**
- add: `1 + 1 = 2`
- xchg: rax=1, rbx=2
- loop: rcx=8

### Itération 3

```bash
gef➤ c
```

```
───────────────────────────────── registers ────
$rax   : 0x2         (F3 = 2)
$rbx   : 0x3         (F4 = 3)
$rcx   : 0x7
```

**Calcul:**
- add: `1 + 2 = 3`

### Itération 4

```bash
gef➤ c
```

```
───────────────────────────────── registers ────
$rax   : 0x3         (F4 = 3)
$rbx   : 0x5         (F5 = 5)
$rcx   : 0x6
```

**Calcul:**
- add: `2 + 3 = 5`

### Itération 5

```bash
gef➤ c
```

```
───────────────────────────────── registers ────
$rax   : 0x5         (F5 = 5)
$rbx   : 0x8         (F6 = 8)
$rcx   : 0x5
```

**Calcul:**
- add: `3 + 5 = 8`

**Séquence jusqu'ici:** 0, 1, 1, 2, 3, 5, 8 ✅

### Itération 10 (Dernière)

```bash
gef➤ c
# ... (continuer jusqu'à dernière itération)
```

```
───────────────────────────────── registers ────
$rax   : 0x22        (34 en décimal)
$rbx   : 0x37        (55 en décimal)
$rcx   : 0x1         (1 itération restante)
```

### Vérification Décimale

```bash
gef➤ p/d $rbx
$3 = 55
```

**Résultat:** F10 = 55 ✅

**Séquence complète:** 0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55

## Tableau des Itérations

| Itération | rax (Fn-1) | rbx (Fn) | rcx | Calcul |
|-----------|------------|----------|-----|--------|
| **0** | 0x0 (0) | 0x1 (1) | 10 | Initial |
| **1** | 0x1 (1) | 0x1 (1) | 9 | 0+1=1 |
| **2** | 0x1 (1) | 0x2 (2) | 8 | 1+1=2 |
| **3** | 0x2 (2) | 0x3 (3) | 7 | 1+2=3 |
| **4** | 0x3 (3) | 0x5 (5) | 6 | 2+3=5 |
| **5** | 0x5 (5) | 0x8 (8) | 5 | 3+5=8 |
| **6** | 0x8 (8) | 0xd (13) | 4 | 5+8=13 |
| **7** | 0xd (13) | 0x15 (21) | 3 | 8+13=21 |
| **8** | 0x15 (21) | 0x22 (34) | 2 | 13+21=34 |
| **9** | 0x22 (34) | 0x37 (55) | 1 | 21+34=55 |
| **10** | 0x37 (55) | 0x59 (89) | 0 | 34+55=89 |

## Diagramme de Flux

### Structure Loop

```
     mov rcx, 10
          ↓
    ┌─────────────┐
    │  loopFib:   │ ◄─────┐
    ├─────────────┤       │
    │ add rax,rbx │       │
    │ xchg rax,rbx│       │
    │ loop loopFib│───────┘
    └─────────────┘
          ↓
    (rcx = 0, sortie)
```

### Flux Détaillé

```
START
  ↓
Initialiser rax=0, rbx=1, rcx=10
  ↓
┌─────────────────┐
│ rcx > 0 ?       │
└────┬───────┬────┘
     │ OUI   │ NON
     ↓       ↓
  ┌─────┐  FIN
  │ add │
  │xchg │
  │loop │
  └──┬──┘
     │
     └──────┘ (boucle)
```

## Concepts Clés

### Le Registre `rcx`

**Rôle:**
```
rcx = Compteur de boucle (Loop Counter)
```

**Automatique:**
- `loop` décrémente automatiquement `rcx`
- Pas besoin de `dec rcx` manuel

**Convention:**
- Toujours utiliser `rcx` pour les boucles
- Préserver `rcx` si appelé depuis fonction

### Pourquoi `xchg` est Crucial

**Sans xchg:**
```nasm
add rax, rbx    ; rax = Next
; Comment mettre ancien Current dans rax?
; Comment mettre Next dans rbx?
; → Besoin d'un registre temporaire!
```

**Avec xchg:**
```nasm
add rax, rbx    ; rax = Next
xchg rax, rbx   ; Swap en 1 instruction! ✅
```

**Avantage:**
- ✅ 1 seule instruction
- ✅ Pas de registre temporaire
- ✅ Code plus court

## Variations de Boucle

### Boucle Simple (Compteur)

```nasm
mov rcx, 5          ; 5 itérations

count_loop:
    inc rax         ; rax++
    loop count_loop

; Résultat: rax = 5
```

### Boucle avec Calcul

```nasm
mov rcx, 10         ; 10 itérations
xor rax, rax        ; rax = 0

sum_loop:
    add rax, rcx    ; Additionner compteur
    loop sum_loop

; Résultat: rax = 10+9+8+...+1 = 55
```

### Boucle Imbriquée

```nasm
mov rcx, 3          ; Boucle externe
outer_loop:
    push rcx        ; Sauvegarder rcx externe
    mov rcx, 5      ; Boucle interne
    
    inner_loop:
        ; Instructions
        loop inner_loop
    
    pop rcx         ; Restaurer rcx externe
    loop outer_loop

; Total: 3 × 5 = 15 itérations
```

## ⚠️ Pièges à Éviter

### Piège 1: Oublier d'Initialiser rcx

```nasm
❌ MAUVAIS:
loopFib:
    add rax, rbx
    loop loopFib    ; rcx non initialisé = boucle aléatoire!

✅ BON:
mov rcx, 10         ; Initialiser AVANT la boucle
loopFib:
    add rax, rbx
    loop loopFib
```

### Piège 2: Modifier rcx dans la Boucle

```nasm
❌ MAUVAIS:
mov rcx, 10
loop_bad:
    inc rcx         ; ERREUR: modifie le compteur!
    loop loop_bad   ; Boucle infinie probable

✅ BON:
mov rcx, 10
loop_good:
    inc rax         ; Utiliser autre registre
    loop loop_good
```

### Piège 3: Boucles Imbriquées Sans Sauvegarder rcx

```nasm
❌ MAUVAIS:
mov rcx, 3
outer:
    mov rcx, 5      ; Écrase rcx externe!
    inner:
        loop inner
    loop outer      ; rcx déjà modifié = bug

✅ BON:
mov rcx, 3
outer:
    push rcx        ; Sauvegarder
    mov rcx, 5
    inner:
        loop inner
    pop rcx         ; Restaurer
    loop outer
```

## Quick Reference

### Instructions Essentielles

```nasm
; Initialiser compteur
mov rcx, N          ; N itérations

; Définir label de boucle
label:
    ; instructions
    loop label      ; Décrémente rcx et boucle
```

### Template Boucle Fibonacci

```nasm
; Initialisation
xor rax, rax        ; F(n-1) = 0
xor rbx, rbx
inc rbx             ; F(n) = 1
mov rcx, N          ; N itérations

; Boucle
loopFib:
    add rax, rbx    ; Next = Last + Current
    xchg rax, rbx   ; Swap
    loop loopFib    ; Répéter
```

### Commandes GDB pour Boucles

```bash
# Break au début de la boucle
gef➤ b loopLabel

# Continue à chaque itération
gef➤ c

# Voir compteur
gef➤ p/d $rcx

# Voir registres
gef➤ info registers rax rbx rcx
```

## Fibonacci Complet (Avec Boucle)

### Code Final

```nasm
global  _start

section .text
_start:
    ; Initialisation
    xor rax, rax    ; F0 = 0
    xor rbx, rbx    
    inc rbx         ; F1 = 1
    mov rcx, 10     ; 10 itérations

    ; Boucle de calcul
loopFib:
    add rax, rbx    ; Fn = Fn-1 + Fn-2
    xchg rax, rbx   ; Swap pour prochaine itération
    loop loopFib    ; Répéter

    ; À ce stade:
    ; rax = F9 = 34
    ; rbx = F10 = 55
```

### Progression du Programme

```
✅ Chapitre 1: mov, lea, xchg → Initialisation
✅ Chapitre 2: add, xor, inc → Calculs de base
✅ Chapitre 3: loop → Automatisation!

Prochaines étapes:
⏳ Chapitre 4: Conditions (cmp, jmp) → Logique
⏳ Chapitre 5: I/O (syscall) → Affichage résultats
⏳ Chapitre 6: Programme complet
```

## Pro Tips

### Expérimentation

```nasm
; Essayer différentes valeurs
mov rcx, 5      ; F5 = 5
mov rcx, 15     ; F15 = 610
mov rcx, 20     ; F20 = 6765
```

**Augmenter rcx pour voir nombres plus grands!**

### Conversion Hex → Décimal

```bash
gef➤ p/d $rbx       # Afficher en décimal
gef➤ p/x $rbx       # Afficher en hex
```

### Observer Toute la Séquence

```bash
# Break avant boucle
gef➤ b _start
gef➤ r

# Break dans boucle
gef➤ b loopFib

# Continue itération par itération
gef➤ c
gef➤ c
gef➤ c
# ...noter les valeurs à chaque fois
```

---

# Branchements Inconditionnels

## Types d'Instructions de Branchement

### Vue d'Ensemble

```
Instructions de Contrôle
├─ Loops (Boucles)
│  └─ loop → Sauts automatiques avec compteur
│
└─ Branching (Branchements)
   ├─ Inconditionnels → Sautent TOUJOURS
   │  └─ jmp
   │
   └─ Conditionnels → Sautent SI condition vraie
      └─ je, jne, jl, jg, etc. (prochain chapitre)
```

## Instruction `jmp` - Jump

### Définition

**jmp** = Saut **inconditionnel** vers un label/adresse

**Inconditionnel** = Saute **TOUJOURS**, peu importe les conditions

### Syntaxe

```nasm
jmp destination
```

**Destination peut être:**
- Un label: `jmp loopFib`
- Une adresse: `jmp 0x401000`
- Un registre: `jmp rax` (adresse dans rax)

### Comportement

```
┌─────────────────────────────┐
│  jmp label                  │
│         ↓                   │
│  1. Saute à 'label'         │
│  2. Continue depuis label   │
│  3. PAS de retour auto      │
└─────────────────────────────┘
```

**Important:**
- ⚠️ Pas de retour automatique (contrairement aux fonctions)
- ⚠️ Exécution continue depuis la destination
- ⚠️ Si utilisé en boucle → Boucle infinie!

## Comparaison: `loop` vs `jmp`

### Différences Fondamentales

| Caractéristique | `loop` | `jmp` |
|-----------------|--------|-------|
| **Type** | Conditionnel (vérifie rcx) | Inconditionnel |
| **Compteur** | Décrémente rcx automatiquement | N'utilise PAS rcx |
| **Condition d'arrêt** | rcx == 0 | Aucune ❌ |
| **Usage** | Boucles avec nombre fixe d'itérations | Sauts toujours nécessaires |
| **Risque** | Se termine automatiquement | Boucle infinie si mal utilisé ⚠️ |

### Comparaison Visuelle

#### Avec `loop`
```nasm
mov rcx, 10
label:
    ; instructions
    loop label      ; rcx--, jump si rcx != 0
                    ; SORT quand rcx = 0 ✅
```

#### Avec `jmp`
```nasm
mov rcx, 10
label:
    ; instructions
    jmp label       ; Jump TOUJOURS
                    ; NE SORT JAMAIS ❌
```

## Problème de `jmp` pour Boucles

### Pourquoi c'est un Problème?

```
jmp loopFib
     ↓
Pas de condition d'arrêt
     ↓
Saute TOUJOURS
     ↓
Boucle INFINIE
     ↓
Programme ne termine JAMAIS
```

### Comparaison Concrète

#### Avec `loop` (Correct)

```nasm
mov rcx, 10
label:
    ; code
    loop label
    
; Programme sort ici après 10 itérations ✅
```

**Résultat:** 10 itérations, puis continue

#### Avec `jmp` (Boucle Infinie)

```nasm
mov rcx, 10         ; rcx inutile
label:
    ; code
    jmp label       ; Saute TOUJOURS
    
; Cette ligne n'est JAMAIS atteinte ❌
```

**Résultat:** Boucle infinie, programme bloqué

## 🎯 Usages Appropriés de `jmp`

### ✅ Quand Utiliser `jmp`

#### 1. Sauts Obligatoires (Toujours Nécessaires)

```nasm
cmp rax, 0
je zero_case
jmp non_zero_case    ; Si pas zéro, TOUJOURS sauter ici

zero_case:
    ; traiter cas zéro
    jmp end

non_zero_case:
    ; traiter cas non-zéro

end:
    ; continuer
```

#### 2. Redirection de Flux

```nasm
; Choix entre plusieurs chemins
cmp rbx, 1
je option1
cmp rbx, 2
je option2
jmp default         ; Si aucun match, aller au défaut

option1:
    ; code option 1
    jmp done

option2:
    ; code option 2
    jmp done

default:
    ; code par défaut

done:
    ; continuer
```

#### 3. Sortie Prématurée

```nasm
loop_start:
    ; vérifications
    cmp rax, limite
    jge sortie       ; Si >= limite, sortir

    ; code de boucle
    inc rcx
    jmp loop_start

sortie:
    ; après boucle
```

### ❌ Quand NE PAS Utiliser `jmp`

#### Boucles Avec Compteur Fixe

```nasm
❌ MAUVAIS:
mov rcx, 10
loop_bad:
    ; code
    jmp loop_bad     ; Boucle infinie!

✅ BON:
mov rcx, 10
loop_good:
    ; code
    loop loop_good   ; Sort après 10 itérations
```

#### Boucles Sans Condition de Sortie

```nasm
❌ MAUVAIS:
label:
    inc rax
    jmp label        ; Pas de sortie = boucle infinie

✅ BON:
label:
    inc rax
    cmp rax, 100
    jl label         ; Sort quand rax >= 100
```

## Points d'Attention

### rcx N'est PAS Utilisé

```
jmp ignore rcx complètement
loop utilise rcx comme compteur

Ne PAS confondre!
```

### Condition de Sortie Obligatoire

```
Pour toute boucle avec jmp:
├─ DOIT avoir condition de sortie
├─ Sinon = boucle infinie
└─ Utiliser branching conditionnel (prochain chapitre)
```
---

# Branchements Conditionnels

## Instructions de Branchement Conditionnel

### Définition

**Jcc** = Jump if Condition Code
- Traité **seulement si** une condition spécifique est remplie
- Basé sur Destination (D) et Source (S)

## Principales Conditions (Jcc)

### Tableau des Instructions

| Instruction | Condition | Description |
|-------------|-----------|-------------|
| **jz** | D = 0 | Destination égale à Zéro |
| **jnz** | D ≠ 0 | Destination Non égale à Zéro |
| **js** | D < 0 | Destination est Négative |
| **jns** | D ≥ 0 | Destination Non Négative (0 ou positif) |
| **jg** | D > S | Destination Greater than Source |
| **jge** | D ≥ S | Destination Greater or Equal Source |
| **jl** | D < S | Destination Less than Source |
| **jle** | D ≤ S | Destination Less or Equal Source |

**Référence complète:** Intel x86_64 manual - Section "Jcc-Jump if Condition Is Met"

## Instructions Conditionnelles Autres

### CMOVcc - Conditional Move

**Exemple:**
```nasm
cmovz rax, rbx    ; mov rax, rbx SI condition = 0
cmovl rax, rbx    ; mov rax, rbx SI condition <
```

### SETcc - Set Byte

**Exemple:**
```nasm
setz rax    ; Met l'octet de rax à 1 si condition remplie, 0 sinon
```
## Registre RFLAGS

### Structure

- **64 bits** comme les autres registres
- Ne contient **PAS de valeurs**, mais des **flag bits**
- Chaque bit = 1 ou 0 selon résultat dernière instruction

### Table Complète RFLAGS

| Bit(s) | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12-13 |
|--------|---|---|---|---|---|---|---|---|---|---|----|----|-------|
| **Label** | CF | 1 | PF | 0 | AF | 0 | ZF | SF | TF | IF | DF | OF | IOPL |
| **Description** | Carry | Rés | Parity | Rés | Aux Carry | Rés | Zero | Sign | Trap | Interrupt | Direction | Overflow | I/O Level |

**Suite:** Bits 14-21 (NT, RF, VM, AC, VIF, VIP, ID) et 22-63 (réservés)

### Sub-Registres

```
RFLAGS (64-bit)
   ↓
EFLAGS (32-bit)
   ↓
FLAGS (16-bit) ← Flags les plus significatifs
```

## Flags Principaux

### Les 4 Flags Importants

| Flag | Bit | Description |
|------|-----|-------------|
| **CF** (Carry Flag) | 0 | Indique si on a un float |
| **PF** (Parity Flag) | 2 | Indique si nombre pair ou impair |
| **ZF** (Zero Flag) | 6 | Indique si nombre est zéro |
| **SF** (Sign Flag) | 7 | Indique si registre est négatif |

**Nomenclature:**
- ZF = 1 → "Zero" (ZR)
- ZF = 0 → "Not Zero" (NZ)
- Exemple: `jnz` = jump avec NZ

## JNZ - Jump if Not Zero

### Équivalence loop

```
loop loopFib = dec rcx + jnz loopFib
```

**Pourquoi loop existe?**
- Fonction très commune
- Réduit taille du code
- Plus efficace que d'utiliser les deux instructions séparément

**Observation:**
- rcx décrémente à chaque fois
- Zero flag OFF (minuscule)
- Parity flag ON (MAJUSCULE) quand rcx impair

> **Note GEF:** Flags en **MAJUSCULES** = ON

**Dernière itération (rcx = 0):**
```
$rax   : 0x37    (55)
$rbx   : 0x59    (89)
$rcx   : 0x0
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
```

**Résultat:**
- rcx = 0
- Zero flag = ON (ZERO en majuscules)
- `jnz` ne saute plus → Programme s'arrête

## CMP - Compare

### Définition

**cmp** = Compare deux opérandes
- Soustrait 2ème opérande du 1er (D1 - S2)
- **Ne stocke PAS le résultat**
- Met à jour les flags dans RFLAGS

| Instruction | Description | Exemple |
|-------------|-------------|---------|
| **cmp** | Met à jour RFLAGS en faisant (first - second) | `cmp rax, rbx` → rax - rbx |


### Règle Important

> **1er opérande (Destination) = DOIT être un registre**  
> 2ème opérande = registre, variable, ou valeur immédiate


### Avantage vs sub

**Avec sub:**
```nasm
sub rax, 10    ; Change rax! (rax = rax - 10)
```

**Avec cmp:**
```nasm
cmp rax, 10    ; NE change PAS rax! Compare seulement
```

**Avantage:** `cmp` ne modifie pas les opérandes

## Application: Fibonacci avec cmp et js

### Objectif

Arrêter quand Fibonacci > 10

### Logique

```nasm
cmp rbx, 10     ; rbx - 10
js loopFib      ; Jump si résultat < 0
```

**Déroulement:**
- rbx = 1 → `1 - 10 = -9` (négatif) → `js` saute ✅
- rbx = 13 → `13 - 10 = 3` (positif) → `js` ne saute pas ❌

### Code Complet

```nasm
global  _start

section .text
_start:
    xor rax, rax    ; initialize rax to 0
    xor rbx, rbx    ; initialize rbx to 0
    inc rbx         ; increment rbx to 1

loopFib:
    add rax, rbx    ; get the next number
    xchg rax, rbx   ; swap values
    cmp rbx, 10     ; do rbx - 10
    js loopFib      ; jump if result is <0
```

**Changements:**
- ❌ Supprimé `mov rcx, 10` (plus besoin de compteur)
- ✅ Ajouté `cmp rbx, 10`
- ✅ Utilisé `js loopFib` (jump si négatif)

---

## 🔍 Debug GDB - cmp et js

### Première Itération

```bash
$ ./assembler.sh fib.s -g
gef➤ b loopFib
gef➤ r
```

**Avant js:**
```
$rax   : 0x1
$rbx   : 0x1
$eflags: [zero CARRY parity ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]

─────────────────────────────────────── code:x86:64 ────
     0x401009 <loopFib+0>      add    rax, rbx
     0x40100c <loopFib+3>      xchg   rbx, rax
     0x40100e <loopFib+5>      cmp    rbx, 0xa
 →   0x401012 <loopFib+9>      js     0x401009 <loopFib>	TAKEN [Reason: S]
```

**Observation:**
- SIGN flag = ON
- `1 - 10 = -9` (négatif)
- GEF affiche: **TAKEN [Reason: S]**

---

### Breakpoint Conditionnel

**Syntaxe:**
```bash
b loopFib if $rbx > 10
b *loopFib+9 if $rbx > 10
b *0x401012 if $rbx > 10
```

**Trouver location:**
```bash
gef➤ disas loopFib
```

---

### Application Breakpoint Conditionnel

```bash
gef➤ del 1
gef➤ disas loopFib
Dump of assembler code for function loopFib:
..SNIP...
0x0000000000401012 <+9>:	js     0x401009

gef➤ b *loopFib+9 if $rbx > 10
Breakpoint 2 at 0x401012
gef➤ c
```

**Résultat:**
```
$rax   : 0x8
$rbx   : 0xd      (13 en décimal)
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]

─────────────────────────────────────── code:x86:64 ────
     0x401009 <loopFib+0>      add    rax, rbx
     0x40100c <loopFib+3>      xchg   rbx, rax
     0x40100e <loopFib+5>      cmp    rbx, 0xa
 →   0x401012 <loopFib+9>      js     0x401009 <loopFib>	NOT taken [Reason: !(S)]
```

**Observation:**
- rbx = 0xd (13)
- `13 - 10 = 3` (positif)
- Sign flag = OFF
- GEF affiche: **NOT TAKEN [Reason: !(S)]**

---

## 🔄 Variations avec cmp

### Exemple: jl au lieu de js

```nasm
cmp rbx, 10
jl loopFib      ; Jump si rbx < 10
```

**Fonctionnement:**
- rbx < 10 → `jl` saute ✅
- rbx ≥ 10 → `jl` ne saute pas ❌

**Résultat:** Même comportement que `js` dans ce cas

---

## 🔖 Alias d'Instructions

### je et jne

**Alias:**
- `je` = `jz` (Jump if Equal = Jump if Zero)
- `jne` = `jnz` (Jump if Not Equal = Jump if Not Zero)

**Pourquoi?**
```nasm
cmp rax, rax    ; rax - rax = 0
                ; Met Zero Flag à 1
je label        ; Saute car Equal → Zero Flag = 1
```

---

### jge et jnl

**Alias:**
- `jge` = `jnl` (Greater or Equal = Not Less)
- Logique: `>=` est la même chose que `!<`

---

## 🎯 Comparaison des 3 Méthodes

### Méthode 1: loop
```nasm
mov rcx, 10
loop loopFib    ; Loop 10 fois
```

### Méthode 2: dec + jnz
```nasm
mov rcx, 10
dec rcx
jnz loopFib     ; Jump 10 fois
```

### Méthode 3: cmp + js
```nasm
cmp rbx, 10
js loopFib      ; Jump tant que rbx < 10
```

**Question du cours:** Quelle méthode est la plus efficace?

---

## 📋 Quick Reference

### Instructions Conditionnelles

```nasm
; Jump if Zero
jz label

; Jump if Not Zero
jnz label

; Jump if Sign (negative)
js label

; Jump if Not Sign (positive or zero)
jns label

; Jump if Greater
jg label

; Jump if Less
jl label
```

---

### Compare

```nasm
cmp destination, source    ; destination - source
                          ; Met à jour RFLAGS
                          ; NE modifie PAS les opérandes
```

---

### GDB - Breakpoints Conditionnels

```bash
# Breakpoint si condition
b label if $reg > value

# Breakpoint à adresse spécifique si condition
b *label+offset if $reg > value
b *0x401012 if $rbx > 10
```

---

## 🎓 Points Clés à Retenir

### Instructions Conditionnelles
1. **Jcc** = Jump if Condition Code
2. Traité **seulement si** condition remplie
3. Basé sur flags dans RFLAGS

### Registre RFLAGS
1. 64 bits de **flags** (pas de valeurs)
2. Mis à jour par instructions arithmétiques
3. Sub-registres: EFLAGS (32-bit), FLAGS (16-bit)

### Flags Importants
1. **ZF** (Zero Flag) - bit 6
2. **SF** (Sign Flag) - bit 7
3. **CF** (Carry Flag) - bit 0
4. **PF** (Parity Flag) - bit 2

### loop vs jnz
1. `loop` = `dec rcx` + `jnz`
2. `loop` existe pour efficacité
3. Branchements conditionnels plus versatiles

### cmp
1. Compare sans modifier opérandes
2. Syntaxe: `cmp dest, source` (dest - source)
3. Destination DOIT être registre
4. Plus efficace que `sub`

---

## 🚀 Progression Fibonacci

### Code Actuel (3 versions possibles)

**Version 1 - loop:**
```nasm
mov rcx, 10
loopFib:
    add rax, rbx
    xchg rax, rbx
    loop loopFib
```

**Version 2 - jnz:**
```nasm
mov rcx, 10
loopFib:
    add rax, rbx
    xchg rax, rbx
    dec rcx
    jnz loopFib
```

**Version 3 - cmp + js:**
```nasm
loopFib:
    add rax, rbx
    xchg rax, rbx
    cmp rbx, 10
    js loopFib
```

**À vous de choisir la méthode que vous pensez être la meilleure!**

---

## 🔥 GEF - Lecture des Flags

### Format

```
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME]
```

**Règle:**
- **MAJUSCULES** = Flag ON (1)
- minuscules = Flag OFF (0)

### Exemple

```
[ZERO carry PARITY] → ZF=1, CF=0, PF=1
[zero CARRY parity] → ZF=0, CF=1, PF=0
```

---

## 📊 Résumé Instructions de Contrôle

```
Instructions de Contrôle Vues:
├─ loop → Boucle avec compteur rcx
├─ jmp → Saut inconditionnel (toujours)
├─ jnz → Saut si Not Zero
├─ js → Saut si Sign (négatif)
└─ cmp → Compare pour définir flags
```

**Prochaine étape:** Fonctions et syscalls pour I/O! 🚀


