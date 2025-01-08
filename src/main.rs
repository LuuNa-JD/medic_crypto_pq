use safe_pqc_kyber::{keypair as kyber_keypair, encapsulate, decapsulate}; // Importation des fonctions de chiffrement Kyber
use pqc_dilithium::{Keypair as DilithiumKeypair, verify}; // Importation des fonctions de signature Dilithium
use rand::thread_rng; // Importation du générateur de nombres aléatoires basé sur le thread actuel
use serde::{Serialize, Deserialize}; // Importation des traits Serialize et Deserialize
use std::fs::{read, write}; // Importation des fonctions de lecture et d'écriture de fichiers
use std::path::Path; // Importation du type Path
use std::fs::create_dir_all; // Importation de la fonction de création de dossiers
use std::env; // Importation du module env
use aes_gcm::aead::{Aead, KeyInit, OsRng}; // Importation des fonctions de chiffrement AES-GCM
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce}; // Importation des fonctions de chiffrement AES-GCM
use hkdf::Hkdf; // Importation de la fonction de dérivation de clé HKDF
use sha2::Sha256; // Importation de l'algorithme de hachage SHA-256
use zstd::stream::encode_all; // Pour la compression
use zstd::stream::decode_all; // Pour la décompression


#[derive(Serialize, Deserialize)]
struct EncryptedFile {
    ciphertext: Vec<u8>,       // Clé chiffrée avec Kyber
    encrypted_data: Vec<u8>,   // Données chiffrées
    nonce: Vec<u8>,            // Nonce utilisé pour AES-GCM
}

#[derive(Serialize, Deserialize)]
struct SignedFile {
    data: Vec<u8>,             // Données signées
    signature: Vec<u8>,        // Signature Dilithium
}

// ---- Génération des clés Kyber pour le contrat de partage ----
fn generate_keypair(output_private: &str, output_public: &str) -> Result<(), String> {
    let mut rng = thread_rng();
    let keypair = kyber_keypair(&mut rng);
    write(output_private, keypair.secret.to_vec()).map_err(|_| "Impossible de sauvegarder la clé privée".to_string())?;
    write(output_public, keypair.public.to_vec()).map_err(|_| "Impossible de sauvegarder la clé publique".to_string())?;
    println!("Clés Kyber générées :\n  Clé privée : {}\n  Clé publique : {}", output_private, output_public);
    Ok(())
}

// ---- Chiffrement et signature ----
fn encrypt_and_sign_file(
    input_file: &str,
    output_file: &str,
    recipient_public_key_file: &str,
) -> Result<(), String> {
    let mut rng = thread_rng();

    // Création du dossier sharing_files s'il n'existe pas
    let sharing_files_dir = Path::new("sharing_files");
    if !sharing_files_dir.exists() {
        create_dir_all(sharing_files_dir).map_err(|_| "Impossible de créer le dossier sharing_files".to_string())?;
    }

    // Lecture de la clé publique du destinataire
    let recipient_public_key = read(recipient_public_key_file)
        .map_err(|_| "Impossible de lire la clé publique du destinataire".to_string())?;

    // Lecture des données du fichier
    let file_data = read(input_file).map_err(|_| "Impossible de lire le fichier".to_string())?;

    // Chiffrement avec Kyber
    let (ciphertext, shared_secret) = encapsulate(&recipient_public_key, &mut rng)
        .expect("Échec du chiffrement");

    // Dérivation de clé à partir du shared_secret
    let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
    let mut aes_key = [0u8; 32]; // Clé 256 bits pour AES-256
    hkdf.expand(b"info", &mut aes_key).expect("Erreur HKDF");

    // Initialisation d'AES-GCM
    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // Génération d'un nonce unique

    // Chiffrement des données
    let encrypted_data = cipher
        .encrypt(&nonce, file_data.as_ref())
        .expect("Erreur lors du chiffrement");

    // Génération des clés Dilithium pour la signature
    let dilithium_keys = DilithiumKeypair::generate();

    // Création de l'objet EncryptedFile
    let encrypted_file = EncryptedFile {
        ciphertext: ciphertext.to_vec(),
        encrypted_data,
        nonce: nonce.to_vec(),
    };

    // Sérialisation des données chiffrées
    let serialized_data = serde_json::to_vec(&encrypted_file)
        .map_err(|_| "Erreur lors de la sérialisation des données chiffrées".to_string())?;

    // Compression des données chiffrées avec Zstd
    println!("Compression des données chiffrées avec Zstd");
    let compressed_data = encode_all(serialized_data.as_slice(), 22)
        .expect("Erreur lors de la compression avec Zstd"); // Niveau 3 : rapide avec bon taux
    println!("Compression terminée, taille des données compressées : {}", compressed_data.len());

    // Signature des données sérialisées
    let signature = dilithium_keys.sign(&compressed_data);
    println!("fichié signé");

    // Création de l'objet SignedFile
    let signed_file = SignedFile {
        data: compressed_data,
        signature: signature.to_vec(),
    };

    // Sérialisation et sauvegarde des données signées
    let serialized_signed_file = serde_json::to_string(&signed_file)
        .map_err(|_| "Erreur lors de la sérialisation du fichier signé".to_string())?;
    let output_path = sharing_files_dir.join(output_file);
    write(output_path, serialized_signed_file)
        .map_err(|_| "Erreur lors de l'écriture du fichier chiffré et signé".to_string())?;

    // Sauvegarde de la clé publique Dilithium pour la vérification
    let public_key_path = sharing_files_dir.join("sender_public_dilithium.key");
    write(public_key_path, dilithium_keys.public)
        .map_err(|_| "Impossible de sauvegarder la clé publique de signature".to_string())?;

    println!("Fichier chiffré et signé avec succès dans sharing_files : {}
    ", output_file);
    Ok(())
}

// ---- Déchiffrement et vérification ----
fn decrypt_and_verify_file(
    input_file: &str,
    output_file: &str,
    recipient_private_key_file: &str,
    sender_public_key_file: &str,
) -> Result<(), String> {

    // Création du dossier final_files s'il n'existe pas
    let final_files_dir = Path::new("final_files");
    if !final_files_dir.exists() {
        create_dir_all(final_files_dir).map_err(|_| "Impossible de créer le dossier final_files".to_string())?;
    }

    // Lecture des clés
    let recipient_private_key = read(recipient_private_key_file)
        .map_err(|_| "Impossible de lire la clé privée du destinataire".to_string())?;
    let sender_public_key = read(sender_public_key_file)
        .map_err(|_| "Impossible de lire la clé publique de l'expéditeur".to_string())?;

    // Lecture du fichier signé
    let file_data = read(input_file).map_err(|_| "Impossible de lire le fichier signé".to_string())?;
    let signed_file: SignedFile = serde_json::from_slice(&file_data)
        .map_err(|_| "Erreur lors de la désérialisation du fichier signé".to_string())?;

    // Vérification de la signature
    verify(&signed_file.signature, &signed_file.data, &sender_public_key)
        .map_err(|_| "Signature invalide ou fichier altéré".to_string())?;
      println!("Signature valide\nFichier signé par l'expéditeur\nLe fichier n'a pas été modifié");

    // Décompression des données chiffrées avec Zstd
    println!("Décompression des données chiffrées avec Zstd");
    let decompressed_data = decode_all(signed_file.data.as_slice())
        .expect("Erreur lors de la décompression avec Zstd");
    println!("Décompression terminée, taille des données décompressées : {}", decompressed_data.len());

    // Désérialisation des données chiffrées
    let encrypted_file: EncryptedFile = serde_json::from_slice(&decompressed_data)
        .map_err(|_| "Erreur lors de la désérialisation des données chiffrées".to_string())?;

    // Décapsulation du secret partagé
    let shared_secret = decapsulate(&encrypted_file.ciphertext, &recipient_private_key)
        .expect("Échec de la décapsulation");

    // Dérivation de clé à partir du shared_secret
    let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
    let mut aes_key = [0u8; 32]; // Clé 256 bits pour AES-256
    hkdf.expand(b"info", &mut aes_key).expect("Erreur HKDF");

    // Initialisation d'AES-GCM
    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(key);

    // Déchiffrement des données
    let decrypted_data = cipher
        .decrypt(Nonce::from_slice(&encrypted_file.nonce), encrypted_file.encrypted_data.as_ref())
        .expect("Erreur lors du déchiffrement");

    let output_path = final_files_dir.join(output_file);
    write(output_path, decrypted_data)
        .map_err(|_| "Erreur lors de l'écriture du fichier déchiffré".to_string())?;

    println!("Fichier déchiffré et vérifié avec succès dans final_files : {}", output_file);
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage :");
        println!("  Générer des clés : generate-keys <private_key_file> <public_key_file>");
        println!("  Chiffrer et signer : encrypt-sign <input_file> <output_file> <recipient_public_key_file>");
        println!("  Déchiffrer et vérifier : decrypt-verify <input_file> <output_file> <recipient_private_key_file> <sender_public_key_file>");
        return;
    }

    match args[1].as_str() {
        "generate-keys" => generate_keypair(&args[2], &args[3]).unwrap_or_else(|e| println!("{}", e)),
        "encrypt-sign" => encrypt_and_sign_file(&args[2], &args[3], &args[4]).unwrap_or_else(|e| println!("{}", e)),
        "decrypt-verify" => decrypt_and_verify_file(&args[2], &args[3], &args[4], &args[5]).unwrap_or_else(|e| println!("{}", e)),
        _ => println!("Commande inconnue."),
    }
}
