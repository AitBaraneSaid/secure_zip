# SecureZip

[![Licence MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![.NET Framework](https://img.shields.io/badge/.NET%20Framework-4.7-purple.svg)](https://dotnet.microsoft.com/download/dotnet-framework/net47)
[![Build Manuel](https://img.shields.io/badge/CI-manuel-lightgrey.svg)](../../actions/workflows/build.yml)

Outil console C# pour créer des archives ZIP chiffrées **AES-256** (chiffrement WinZip AES-256, méthode 99) compatible 7-Zip, WinRAR et Windows Explorer.  
Aucune dépendance NuGet — uniquement le BCL .NET 4.7.

## Fonctionnalités

- **Chiffrement AES-256** (WinZip AES v2) avec sel aléatoire unique par fichier
- **Dérivation de clé PBKDF2-SHA1** (1000 itérations) + authentification HMAC-SHA1
- **Compression intelligente** : Deflate pour les fichiers texte/données, Stocké automatiquement pour les fichiers déjà compressés (PDF, images, Office, archives…)
- **Support ZIP64** transparent pour les archives/fichiers > 4 Go
- **Streaming** : mémoire constante quelle que soit la taille des fichiers
- **Structure de dossiers préservée** dans l'archive ZIP
- Aucune dépendance externe

## Prérequis

- Windows 7 ou supérieur
- [.NET Framework 4.7](https://dotnet.microsoft.com/download/dotnet-framework/net47) (runtime)
- Pour compiler :
  - **.NET SDK 6+** (recommandé) — `dotnet build` utilise le compilateur Roslyn intégré
  - **OU** Visual Studio 2017+ avec MSBuild ToolsVersion ≥ 15

## Build

### Avec dotnet CLI (recommandé)

```cmd
cd SecureZip
dotnet build SecureZip.sln -c Release
```

L'exécutable est généré dans : `SecureZip\bin\Release\net47\SecureZip.exe`

### Avec MSBuild (Visual Studio 2017+)

```cmd
msbuild SecureZip.sln /p:Configuration=Release
```

### Avec Visual Studio

Ouvrir `SecureZip.sln` dans Visual Studio 2017 ou supérieur, puis **Build → Build Solution** (`Ctrl+Shift+B`).

> **Note :** Le compilateur CSC.exe livré avec le seul .NET Framework 4.0 (sans Visual Studio) ne supporte que C# 5 et ne peut pas compiler ce projet. Utilisez `dotnet build` ou Visual Studio.

## Utilisation

```
SecureZip.exe <dossierSource> <fichierZip> <motDePasse>
```

| Paramètre       | Description                                       |
|-----------------|---------------------------------------------------|
| `dossierSource` | Dossier à compresser (parcouru récursivement)     |
| `fichierZip`    | Chemin du fichier ZIP à créer (`.zip`)            |
| `motDePasse`    | Mot de passe de chiffrement (minimum 6 caractères)|

### Exemples

```cmd
REM Compresser un dossier Documents
SecureZip.exe C:\Documents C:\Exports\archive.zip MonMotDePasse123

REM Chemin contenant des espaces
SecureZip.exe "C:\Mes Documents" "C:\Exports\sauvegarde.zip" S3cr3t!
```

### Aide

```cmd
SecureZip.exe --help
```

## Comportement

- Parcourt récursivement le dossier source
- Préserve la structure des sous-dossiers dans le ZIP (`sous-dossier/fichier.txt`)
- Applique Deflate sur les fichiers compressibles ; bascule en Stocké si la compression augmente la taille
- Ignore automatiquement la compression pour les types déjà compressés : PDF, JPG, PNG, GIF, HEIC, MP4, MP3, ZIP, 7Z, DOCX, XLSX, PPTX, et bien d'autres
- Demande confirmation avant d'écraser un fichier ZIP existant
- Affiche la progression fichier par fichier avec les tailles et le taux de compression
- Codes de retour : `0` = succès, `1` = erreur

## Sécurité

Le chiffrement implémente la spécification **WinZip AES-256 v2** :

| Élément                    | Détail                                           |
|----------------------------|--------------------------------------------------|
| Algorithme de chiffrement  | AES-256-CTR                                      |
| Dérivation de clé          | PBKDF2-SHA1 — 1000 itérations, sel 16 octets     |
| Authentification           | HMAC-SHA1, code d'authentification 10 octets     |
| Générateur de sel          | `RNGCryptoServiceProvider` (cryptographiquement sûr) |
| Sel                        | Unique par fichier — même mot de passe, clés différentes |

L'archive produite est compatible avec 7-Zip, WinRAR et tout outil supportant le chiffrement AES WinZip (méthode 99).

> **Recommandation :** Utilisez un mot de passe long et aléatoire (16+ caractères). La sécurité de l'archive repose entièrement sur la robustesse du mot de passe.

## Structure du projet

```
SecureZip/
├── SecureZip.sln
├── SecureZip/
│   ├── SecureZip.csproj        (.NET Framework 4.7, Console Application, SDK-style)
│   ├── Program.cs              Point d'entrée, parsing des arguments, affichage coloré
│   ├── SecureZipService.cs     Orchestration : scan, validation, statistiques
│   ├── PasswordZipWriter.cs    Moteur AES-256 + ZIP64 (sans dépendance externe)
│   └── README.md
└── SecureZip.Tests/
    ├── SecureZip.Tests.csproj  Projet de tests (.NET Framework 4.7, exécutable)
    └── TestRunner.cs           Suite de 33 tests (framework de test maison, sans NuGet)
```

## Tests

Le projet inclut une suite de 33 tests couvrant :

- Dérivation de clé PBKDF2 (vecteurs de référence, longueurs, unicité par sel)
- Détection automatique de la compression (`ShouldStore`)
- Validation des paramètres (mot de passe vide, entrées nulles)
- Création et intégrité des archives ZIP
- Types pré-compressés (PDF, PNG, XLSX)
- Robustesse : fichiers vides, caractères spéciaux, 10 fichiers simultanés, fichiers 5 Mo

Si 7-Zip est installé (`C:\Program Files\7-Zip\7z.exe`), les tests vérifient également la compatibilité et la validation du mot de passe via `7z.exe t`.

```cmd
cd SecureZip.Tests
dotnet run
```

## Dépendances

Aucune dépendance NuGet. Uniquement les assemblées BCL .NET 4.7 :

- `System.Security.Cryptography` — AES, HMAC-SHA1, PBKDF2, RNG
- `System.IO.Compression` — DeflateStream
- `System` / `System.IO` — types de base

## Licence

Distribué sous licence [MIT](LICENSE) — © 2026 AIT BARANE Said.
