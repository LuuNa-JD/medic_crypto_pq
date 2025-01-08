# Gestion Sécurisée de Fichiers Médicaux

## Description

### Objectif du Programme

Ce projet propose une solution robuste pour le partage sécurisé de fichiers médicaux entre les patients et les professionnels de santé. Le programme utilise des technologies cryptographiques post-quantiques pour garantir la confidentialité et l'intégrité des données.

1. **Confidentialité** : Les fichiers sont chiffrés pour empêcher tout accès non autorisé.
2. **Authenticité** : Les fichiers sont signés pour garantir leur intégrité et leur origine.
3. **Sécurité** : Utilisation des algorithmes post-quantiques Kyber et Dilithium pour assurer la sécurité future.
4. **Optimisation** : Compression intégrée pour réduire la taille des fichiers lors des transferts.

### Principaux Concepts

1. **Cryptographie Post-Quantique**
    - **Kyber** : Utilisé pour l'échange de clés sécurisées entre le patient et le professionnel.
    - **Dilithium** : Fournit la signature numérique pour garantir l'intégrité et l'origine des fichiers.

2. **Chiffrement Hybride**
    - **AES-GCM (AES-256)** : Permet un chiffrement rapide et sûr des données.
    - **HKDF (HMAC-based Key Derivation Function)** : Dérive une clé symétrique AES à partir du secret partagé généré par Kyber.

3. **Compression**
    - **Zstd** : Un algorithme de compression rapide et performant, intégré pour réduire la taille des fichiers chiffrés avant leur signature.

### Étapes du Programme

1. **Génération de Clés**
    - Le patient et le professionnel génèrent chacun une paire de clés Kyber pour l'échange de clés sécurisées.

2. **Chiffrement et Signature**
    - Lecture du fichier et de la clé publique du destinataire.
    - Génération du secret partagé avec Kyber.
    - Dérivation d'une clé AES-256 avec HKDF.
    - Chiffrement des données avec AES-GCM.
    - Sérialisation et compression avec Zstd.
    - Signature des données compressées avec Dilithium et création de la clé publique Dilithium.
    - Sauvegarde des fichiers dans un dossier `sharing_files`.

3. **Déchiffrement et Vérification**
    - Lecture des clés privées et publiques.
    - Vérification de la signature avec Dilithium et la clé publique partagée.
    - Décompression des données avec Zstd.
    - Désérialisation des données chiffrées.
    - Décapsulation du secret partagé avec Kyber.
    - Dérivation de la clé AES-256 avec HKDF.
    - Déchiffrement avec AES-GCM.
    - Sauvegarde des fichiers dans un dossier `final_files`.

### Points Techniques Clés

1. **Gestion des Nonces**
    - Les nonces sont générés aléatoirement pour chaque fichier et sont stockés dans les fichiers chiffrés pour éviter les attaques de répétition.

2. **Compression avec Zstd**
    - Niveau de compression utilisé : 22 (priorité à une compression maximale).
    - Intégration fluide avec les étapes de sérialisation et de chiffrement.

3. **Sécurité Post-Quantique**
    - Chiffrement Post-Quantique : Résistance aux attaques futures des ordinateurs quantiques.
    - Chiffrement Hybride : Combine la sécurité de Kyber avec la rapidité d'AES-GCM.
    - Authentification : Chaque fichier est signé pour garantir son intégrité et son origine.

## Performance

La compression est effectuée après le chiffrement et la signature pour garantir la confidentialité et l'authenticité des données. Les tests de performance ont montré que le programme est capable de compresser et de décompresser des fichiers de taille variable avec une efficacité élevée. Si on dépasse 50 Mo, la compression prendra beaucoup de temps.

## Installation

### Prérequis

Rust et Cargo installés sur votre machine :
- Installez-les depuis [Rustup.rs](https://rustup.rs/)

### Étapes

1. **Cloner le dépôt GitHub :**

  ```bash
  git clone git@github.com:LuuNa-JD/medic_crypto_pq.git
  cd medic_crypto_pq
  ```

2. **Compiler et exécuter le programme :**

  ```bash
  cargo build --release
  ```
  Le binaire compilé sera disponible dans `target/release`.

3. **Exécuter le programme :**

  Le programme propose trois commandes principales :

  1. **Génération de clés**
    - Créez une paire de clés publique/privée pour le chiffrage Kyber.

      **Syntaxe :**

      ```bash
      cargo run generate-keys <private_key_file> <public_key_file>
      ```

      **Simulation :**

      ```bash
      cargo run generate-keys doctor_kyber_private.key doctor_kyber_public.key
      cargo run generate-keys patient_kyber_private.key patient_kyber_public.key
      ```

  2. **Chiffrement et signature**
      - Chiffrez un fichier avec la clé publique du destinataire et signez-le avec une clé privée Dilithium.

      **Syntaxe :**

      ```bash
      cargo run encrypt-sign <input_file> <output_file> <recipient_public_key_file>
      ```

      **Simulation :**

      ```bash
      cargo run encrypt-sign test_files/image.jpg encrypted_image.json  doctor_kyber_public.key
      ```

      Chiffre `image.jpg`.
      Sauvegarde le fichier chiffré et signé sous `sharing_files/encrypted_image.json`.
      Génère la clé publique Dilithium dans `sharing_files/sender_public_dilithium.key`.

  3. **Déchiffrement et vérification**
      - Déchiffrez un fichier avec votre clé privée et vérifiez son intégrité avec la clé publique de l'expéditeur.

      **Syntaxe :**

      ```bash
      cargo run decrypt-verify <input_file> <output_file> <recipient_private_key_file> <sender_public_key_file>
      ```

      **Simulation :**

      ```bash
      cargo run decrypt-verify sharing_files/encrypted_image.json image2.jpg doctor_kyber_private.key sharing_files/sender_public_dilithium.key
      ```

      Déchiffre `encrypted_image.json`.
      Vérifie la signature avec la clé publique Dilithium de l'expéditeur.
      Sauvegarde le fichier déchiffré sous `final_files/image2.jpg`.

## Conclusion

Ce programme constitue une base solide pour le partage sécurisé de fichiers médicaux dans un environnement blockchain ou classique.

## Auteurs

- [LuuNa-JD](https://github.com/LuuNa-JD)
