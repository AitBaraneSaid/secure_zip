# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.  
Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/).

## [1.0.0] - 2026-04-24

### Ajouté
- Chiffrement AES-256 (WinZip AES v2, méthode 99) avec sel aléatoire unique par fichier
- Dérivation de clé PBKDF2-SHA1 (1000 itérations) + authentification HMAC-SHA1
- Compression intelligente : Deflate pour les fichiers texte/données, Stocké pour les types déjà compressés (PDF, images, Office, archives)
- Support ZIP64 transparent pour les archives/fichiers > 4 Go
- Streaming I/O : mémoire constante quelle que soit la taille des fichiers
- Préservation de la structure de dossiers dans l'archive ZIP
- Confirmation avant écrasement d'un ZIP existant
- Affichage de la progression fichier par fichier avec taux de compression
- Suite de 33 tests avec framework de test maison (zéro dépendance NuGet)
- Support `--help` en ligne de commande
- Codes de retour : `0` = succès, `1` = erreur
