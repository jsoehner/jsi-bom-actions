#!/usr/bin/env python3
"""
scan_crypto_ast.py - Multi-Language Semantic AST & Cryptographic Asset Scanner

Scans source code, configurations, Infrastructure-as-Code (IaC), SQL scripts,
and PKI/certificate files across 18+ programming languages and formats:
  - Python (native AST + regex call-site analysis)
  - JavaScript / TypeScript / Node.js / WebCrypto (.js, .ts, .jsx, .tsx, .mjs, .cjs)
  - Go (.go - standard library crypto/*, crypto/mlkem, golang.org/x/crypto, circl)
  - Java / Kotlin / Scala (.java, .kt, .kts, .scala - JCA/JCE/JSSE, BouncyCastle, KEM)
  - Rust (.rs - ring, rustls, RustCrypto, dalek, pqcrypto, ml-kem, ml-dsa, oqs)
  - C# / .NET (.cs - System.Security.Cryptography, .NET 9+ MLKem/MLDsa/SlhDsa, BouncyCastle)
  - C / C++ (.c, .cpp, .cc, .cxx, .h, .hpp - OpenSSL EVP, BoringSSL, libsodium, mbedTLS, wolfSSL, liboqs)
  - Ruby (.rb - OpenSSL, Digest, RbNaCl, BCrypt, Argon2, JWT)
  - PHP (.php - OpenSSL, Sodium, Hash, Password Hashing)
  - Swift (.swift - Apple CryptoKit, MLKEM768/1024, MLDSA65/87, SecKey, CommonCrypto)
  - Dart / Flutter (.dart - cryptography, pointycastle, crypto)
  - Elixir / Erlang (.ex, .exs, .erl - :crypto, :public_key, Plug.Crypto, Argon2, Bcrypt)
  - Shell / PowerShell (.sh, .bash, .ps1 - openssl CLI, ssh-keygen, gpg, cosign)
  - SQL (.sql - pgcrypto, AES_ENCRYPT, SHA2, HASHBYTES)
  - IaC / Config / PKI (.tf, .hcl, .conf, .nginx, .pem, .crt, .cer, Dockerfile)

Discovers all 4 CycloneDX 1.6 cryptographic asset types:
  1. algorithm (ciphers, asymmetric primitives, PQC KEM/signatures, hashes, MACs, KDFs, CSPRNGs)
  2. protocol (TLS, SSH, mTLS, OAuth2/OIDC, IPsec, WireGuard, QUIC)
  3. certificate (X.509 certificates, PEM/CRT bundles, ACM/PKI resources)
  4. related-crypto-material (public/private key definitions, KMS/HSM keys, keystores, nonces/salts)

Reconciles all discovered assets and call-site occurrences into CycloneDX CBOM (oss/cbom.json).
"""

import ast
import os
import sys
import json
import re
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set

# Ordered from most specific parameterizations to general family patterns.
# Each rule defines:
#   pattern: regex
#   name: canonical asset name
#   primitive: CycloneDX algorithm primitive or asset category
#   pqc_status: POST-QUANTUM READY | QUANTUM-VULNERABLE | CLASSICAL/SYMMETRIC
#   param: parameterSetIdentifier / key length / curve / version
#   asset_type: algorithm (default) | protocol | certificate | related-crypto-material
#   std: cryptographic standard
#   mode: optional block/stream cipher mode
#   oid: optional ASN.1 OID
CRYPTO_PATTERNS: List[Dict[str, Any]] = [
    # =========================================================================
    # 1. POST-QUANTUM CRYPTOGRAPHY (NIST FIPS 203, 204, 205 & Hybrid TLS/KEM)
    # =========================================================================
    {
        "pattern": r"\b(?:X25519MLKEM768|SecP256r1MLKEM768|X25519Kyber768(?:Draft00)?|P256_MLKEM768)\b",
        "name": "X25519MLKEM768",
        "primitive": "kem",
        "pqc_status": "POST-QUANTUM READY",
        "param": "X25519+ML-KEM-768",
        "std": "IETF Hybrid KEM / NIST FIPS 203",
        "oid": "1.3.6.1.4.1.22554.5.6.1",
    },
    {
        "pattern": r"\b(?:ML[-_]?KEM[-_]?1024|KYBER[-_]?1024|MLKEM1024|ml_kem1024|GenerateKey1024|Encapsulate1024)\b",
        "name": "ML-KEM-1024",
        "primitive": "kem",
        "pqc_status": "POST-QUANTUM READY",
        "param": "1024",
        "std": "NIST FIPS 203",
        "oid": "2.16.840.1.101.3.4.4.3",
    },
    {
        "pattern": r"\b(?:ML[-_]?KEM[-_]?512|KYBER[-_]?512|MLKEM512|ml_kem512)\b",
        "name": "ML-KEM-512",
        "primitive": "kem",
        "pqc_status": "POST-QUANTUM READY",
        "param": "512",
        "std": "NIST FIPS 203",
        "oid": "2.16.840.1.101.3.4.4.1",
    },
    {
        "pattern": r"\b(?:ML[-_]?KEM[-_]?(?:768)?|KYBER[-_]?(?:768)?|MLKEM768|MLKem|ml_kem768|crypto/mlkem|GenerateKey768|OQS_KEM_alg_ml_kem|KEM\.getInstance\(['\"]ML-?KEM)\b",
        "name": "ML-KEM-768",
        "primitive": "kem",
        "pqc_status": "POST-QUANTUM READY",
        "param": "768",
        "std": "NIST FIPS 203",
        "oid": "2.16.840.1.101.3.4.4.2",
    },
    {
        "pattern": r"\b(?:ML[-_]?DSA[-_]?87|DILITHIUM[-_]?5|MLDSA87|ml_dsa87)\b",
        "name": "ML-DSA-87",
        "primitive": "signature",
        "pqc_status": "POST-QUANTUM READY",
        "param": "87",
        "std": "NIST FIPS 204",
        "oid": "2.16.840.1.101.3.4.3.19",
    },
    {
        "pattern": r"\b(?:ML[-_]?DSA[-_]?44|DILITHIUM[-_]?2|MLDSA44|ml_dsa44)\b",
        "name": "ML-DSA-44",
        "primitive": "signature",
        "pqc_status": "POST-QUANTUM READY",
        "param": "44",
        "std": "NIST FIPS 204",
        "oid": "2.16.840.1.101.3.4.3.17",
    },
    {
        "pattern": r"\b(?:ML[-_]?DSA[-_]?(?:65)?|DILITHIUM[-_]?3?|MLDSA65|MLDsa|ml_dsa65|OQS_SIG_alg_ml_dsa)\b",
        "name": "ML-DSA-65",
        "primitive": "signature",
        "pqc_status": "POST-QUANTUM READY",
        "param": "65",
        "std": "NIST FIPS 204",
        "oid": "2.16.840.1.101.3.4.3.18",
    },
    {
        "pattern": r"\b(?:SLH[-_]?DSA(?:[-_](?:SHA2|SHAKE)[-_](?:128|192|256)[sf])?|SPHINCS\+?[-_]?(?:128|192|256)?|SlhDsa|slh_dsa)\b",
        "name": "SLH-DSA",
        "primitive": "signature",
        "pqc_status": "POST-QUANTUM READY",
        "param": "128s/256f",
        "std": "NIST FIPS 205",
        "oid": "2.16.840.1.101.3.4.3.20",
    },
    {
        "pattern": r"\b(?:FN[-_]?DSA|FALCON[-_]?(?:512|1024)|OQS_SIG_alg_falcon)\b",
        "name": "FN-DSA-FALCON",
        "primitive": "signature",
        "pqc_status": "POST-QUANTUM READY",
        "param": "512/1024",
        "std": "NIST FIPS 206 (Draft)",
    },
    {
        "pattern": r"\b(?:LMS|HSS|XMSS|XMSSMT)\b",
        "name": "Stateful-Hash-Signature",
        "primitive": "signature",
        "pqc_status": "POST-QUANTUM READY",
        "param": "SHA-256",
        "std": "NIST SP 800-208 / RFC 8554 / RFC 8391",
    },
    {
        "pattern": r"\b(?:FrodoKEM|Classic[-_]?McEliece|BIKE[-_]?L[135]|HQC[-_]?(?:128|192|256)|oqs\.KeyEncapsulation|OQS_KEM_new)\b",
        "name": "PQC-KEM",
        "primitive": "kem",
        "pqc_status": "POST-QUANTUM READY",
        "param": "PQC",
        "std": "ISO/NIST Post-Quantum KEM",
    },

    # =========================================================================
    # 2. CLASSICAL ASYMMETRIC PRIMITIVES (Quantum-Vulnerable to Shor's Algorithm)
    # =========================================================================
    {
        "pattern": r"\b(?:RSA[-_]?4096|rsa[-_]?4096|key_size\s*=\s*4096|GenerateKey\([^,]+,\s*4096\)|RSA\.Create\(4096\)|num_bits:\s*4096)\b",
        "name": "RSA-4096",
        "primitive": "signature",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "4096",
        "oid": "1.2.840.113549.1.1.1",
    },
    {
        "pattern": r"\b(?:RSA[-_]?3072|rsa[-_]?3072|key_size\s*=\s*3072|GenerateKey\([^,]+,\s*3072\)|RSA\.Create\(3072\))\b",
        "name": "RSA-3072",
        "primitive": "signature",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "3072",
        "oid": "1.2.840.113549.1.1.1",
    },
    {
        "pattern": r"\b(?:RSA[-_]?1024|rsa[-_]?1024|key_size\s*=\s*1024|GenerateKey\([^,]+,\s*1024\)|RSA\.Create\(1024\))\b",
        "name": "RSA-1024",
        "primitive": "signature",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "1024",
        "oid": "1.2.840.113549.1.1.1",
    },
    {
        "pattern": r"\b(?:RSA[-_]?(?:2048|OAEP|PSS|PKCS1)?|RS256|RS384|RS512|PS256|PS384|PS512|rsa\.generate_private_key|rsa\.GenerateKey|RSA\.Create|RSACryptoServiceProvider|RsaPrivateKey::new|OpenSSL::PKey::RSA|EVP_PKEY_RSA|KeyPairGenerator\.getInstance\(['\"]RSA|openssl\s+genrsa|ssh-keygen\s+.*-t\s+rsa)\b",
        "name": "RSA-2048",
        "primitive": "signature",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "2048",
        "oid": "1.2.840.113549.1.1.1",
    },
    {
        "pattern": r"\b(?:secp384r1|P-?384|SECP384R1|ES384|ECCurve\.NamedCurves\.nistP384|elliptic\.P384\(\)|P384\.Signing|P384\.KeyAgreement)\b",
        "name": "ECDSA-P384",
        "primitive": "signature",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "secp384r1",
        "oid": "1.3.132.0.34",
    },
    {
        "pattern": r"\b(?:secp521r1|P-?521|SECP521R1|ES512|ECCurve\.NamedCurves\.nistP521|elliptic\.P521\(\)|P521\.Signing|P521\.KeyAgreement)\b",
        "name": "ECDSA-P521",
        "primitive": "signature",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "secp521r1",
        "oid": "1.3.132.0.35",
    },
    {
        "pattern": r"\b(?:secp256k1|SECP256K1|k256::ecdsa)\b",
        "name": "ECDSA-secp256k1",
        "primitive": "signature",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "secp256k1",
        "oid": "1.3.132.0.10",
    },
    {
        "pattern": r"\b(?:ECDSA|secp256r1|prime256v1|P-256|SECP256R1|ES256|ECDsa\.Create|ecdsa\.GenerateKey|ecdsa\.Sign|p256::ecdsa|OpenSSL::PKey::EC|P256\.Signing|KeyPairGenerator\.getInstance\(['\"]EC)\b",
        "name": "ECDSA-P256",
        "primitive": "signature",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "secp256r1",
        "oid": "1.2.840.10045.3.1.7",
    },
    {
        "pattern": r"\b(?:ECDH|X25519|X448|curve25519|x25519_dalek|ECDiffieHellman\.Create|ecdh\.X25519|ecdh\.P256|Curve25519\.KeyAgreement|EVP_PKEY_X25519|crypto_box_easy|sodium_crypto_box)\b",
        "name": "ECDH-X25519",
        "primitive": "key-agreement",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "25519",
        "oid": "1.3.101.110",
    },
    {
        "pattern": r"\b(?:Ed25519|Ed448|EdDSA|ed25519\.GenerateKey|ed25519\.Sign|ed25519_dalek|Curve25519\.Signing|OpenSSL::PKey::Ed25519|EVP_PKEY_ED25519|crypto_sign_ed25519|sodium_crypto_sign|ssh-keygen\s+.*-t\s+ed25519)\b",
        "name": "Ed25519",
        "primitive": "signature",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "25519",
        "oid": "1.3.101.112",
    },
    {
        "pattern": r"\b(?:Diffie[-_ ]?Hellman|DHE-|FFDHE|dh\.generate_parameters|KeyAgreement\.getInstance\(['\"]DH)\b",
        "name": "Diffie-Hellman",
        "primitive": "key-agreement",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "2048",
        "oid": "1.2.840.113549.1.3.1",
    },

    # =========================================================================
    # 3. CLASSICAL SYMMETRIC CIPHERS & AEAD (Grover's Algorithm Evaluated)
    # =========================================================================
    {
        "pattern": r"\b(?:AES[-_]?128[-_]?GCM|aes-128-gcm|Aes128Gcm|EVP_aes_128_gcm|AesGcm\.with128bits)\b",
        "name": "AES-128-GCM",
        "primitive": "ae",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "128",
        "mode": "gcm",
        "oid": "2.16.840.1.101.3.4.1.6",
    },
    {
        "pattern": r"\b(?:AES[-_]?128[-_]?CBC|aes-128-cbc|EVP_aes_128_cbc)\b",
        "name": "AES-128-CBC",
        "primitive": "block-cipher",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "128",
        "mode": "cbc",
        "oid": "2.16.840.1.101.3.4.1.2",
    },
    {
        "pattern": r"\b(?:AES[-_]?192[-_]?(?:GCM|CBC|CTR)?|aes-192-(?:gcm|cbc|ctr)|EVP_aes_192_(?:gcm|cbc))\b",
        "name": "AES-192",
        "primitive": "block-cipher",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "192",
    },
    {
        "pattern": r"\b(?:AES[-_]?256[-_]?CBC|aes-256-cbc|EVP_aes_256_cbc)\b",
        "name": "AES-256-CBC",
        "primitive": "block-cipher",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "256",
        "mode": "cbc",
        "oid": "2.16.840.1.101.3.4.1.42",
    },
    {
        "pattern": r"\b(?:AES[-_]?(?:128|192|256)?[-_]?ECB|aes-(?:128|192|256)-ecb|AES/ECB/)\b",
        "name": "AES-ECB",
        "primitive": "block-cipher",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "128",
        "mode": "ecb",
    },
    {
        "pattern": r"\b(?:AES[-_]?(?:256)?[-_]?(?:GCM|CTR|CCM|SIV)?|aes-256-gcm|createCipheriv\(['\"]aes|Aes\.Create|AesGcm|AESGCM\(|Aes256Gcm|cipher\.NewGCM|aes\.NewCipher|AES\.GCM|EVP_aes_256_gcm|Cipher\.getInstance\(['\"]AES|AesGcm\.with256bits|sodium_crypto_aead_aes256gcm|AES_ENCRYPT\()\b",
        "name": "AES-256-GCM",
        "primitive": "block-cipher",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "256",
        "mode": "gcm",
        "oid": "2.16.840.1.101.3.4.1.46",
    },
    {
        "pattern": r"\b(?:Fernet\(|fernet\.Fernet)\b",
        "name": "Fernet-AES-128-CBC",
        "primitive": "ae",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "128",
        "mode": "cbc",
    },
    {
        "pattern": r"\b(?:XChaCha20[-_]?Poly1305|XChaCha20Poly1305|chacha20poly1305\.NewX|crypto_aead_xchacha20poly1305|sodium_crypto_aead_xchacha20poly1305)\b",
        "name": "XChaCha20-Poly1305",
        "primitive": "ae",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "256",
    },
    {
        "pattern": r"\b(?:CHACHA20[-_]?POLY1305|chacha20|ChaCha20Poly1305|ChaChaPoly|chacha20poly1305\.New|EVP_chacha20_poly1305|crypto_aead_chacha20poly1305|crypto_secretbox_easy|sodium_crypto_secretbox)\b",
        "name": "ChaCha20-Poly1305",
        "primitive": "stream-cipher",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "256",
        "oid": "1.2.840.113549.1.9.16.3.18",
    },

    # =========================================================================
    # 4. KEY DERIVATION FUNCTIONS (KDF) & PASSWORD HASHING
    # =========================================================================
    {
        "pattern": r"\b(?:Argon2(?:id|i|d)?|argon2\.hash|PasswordHasher\(|argon2\.IDKey|Argon2PasswordEncoder|PASSWORD_ARGON2ID|PASSWORD_ARGON2I|crypto_pwhash|sodium_crypto_pwhash)\b",
        "name": "Argon2id",
        "primitive": "kdf",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "256",
        "std": "RFC 9106",
    },
    {
        "pattern": r"\b(?:PBKDF2(?:WithHmacSHA(?:256|512|1))?|pbkdf2_hmac|crypto\.pbkdf2(?:Sync)?|pbkdf2\.Key|Rfc2898DeriveBytes|Pbkdf2PasswordEncoder|hash_pbkdf2|EVP_PKCS5_PBKDF2_HMAC)\b",
        "name": "PBKDF2-HMAC-SHA256",
        "primitive": "kdf",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "256",
        "std": "NIST SP 800-132 / RFC 8018",
    },
    {
        "pattern": r"\b(?:scrypt|crypto\.scrypt(?:Sync)?|SCryptPasswordEncoder|EVP_PBE_scrypt)\b",
        "name": "scrypt",
        "primitive": "kdf",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "256",
        "std": "RFC 7914",
    },
    {
        "pattern": r"\b(?:bcrypt\.hashpw|bcrypt\.gensalt|bcrypt\.hash|bcrypt\.GenerateFromPassword|BCryptPasswordEncoder|BCrypt\.Net|BCrypt::Password|PASSWORD_BCRYPT|Bcrypt\.hash_pwd_salt|gen_salt\(['\"]bf['\"]\))\b",
        "name": "bcrypt",
        "primitive": "kdf",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "192",
    },
    {
        "pattern": r"\b(?:HKDF(?:Expand|Extract)?|hkdf\.New|crypto\.hkdf(?:Sync)?|HKDF\.DeriveKey|Hkdf::<|EVP_PKEY_CTX_set_hkdf_md)\b",
        "name": "HKDF-SHA256",
        "primitive": "kdf",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "256",
        "std": "RFC 5869",
    },

    # =========================================================================
    # 5. MESSAGE AUTHENTICATION CODES (MAC) & HASH FUNCTIONS
    # =========================================================================
    {
        "pattern": r"\b(?:HmacSHA512|HMACSHA512|HS512|createHmac\(['\"]sha512)\b",
        "name": "HMAC-SHA512",
        "primitive": "mac",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "512",
    },
    {
        "pattern": r"\b(?:HmacSHA384|HMACSHA384|HS384|createHmac\(['\"]sha384)\b",
        "name": "HMAC-SHA384",
        "primitive": "mac",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "384",
    },
    {
        "pattern": r"\b(?:hmac\.new\(|hmac\.compare_digest\(|HmacSHA256|HMACSHA256|HMAC\(|hmac\.New\(|createHmac\(['\"]sha256|Mac\.getInstance\(['\"]HmacSHA256|hash_hmac\(['\"]sha256|OpenSSL::HMAC|HS256|:crypto\.mac\(:hmac)\b",
        "name": "HMAC-SHA256",
        "primitive": "mac",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "256",
        "oid": "1.2.840.113549.2.9",
    },
    {
        "pattern": r"\b(?:BLAKE3|blake3::hash|blake3\.blake3)\b",
        "name": "BLAKE3",
        "primitive": "hash",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "256",
    },
    {
        "pattern": r"\b(?:BLAKE2[bs]|blake2b|blake2s|hashlib\.blake2[bs]|Blake2b512|Blake2s256|crypto_generichash)\b",
        "name": "BLAKE2b",
        "primitive": "hash",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "512",
        "std": "RFC 7693",
    },
    {
        "pattern": r"\b(?:SHA[-_]?3[-_]?512|sha3_512|hashlib\.sha3_512|Sha3_512|SHA3_512)\b",
        "name": "SHA3-512",
        "primitive": "hash",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "512",
        "std": "NIST FIPS 202",
    },
    {
        "pattern": r"\b(?:SHA[-_]?3(?:[-_]?256)?|sha3|hashlib\.sha3_256|Sha3_256|SHA3_256|SHAKE128|SHAKE256|sha3\.New256|EVP_sha3_256)\b",
        "name": "SHA-3",
        "primitive": "hash",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "256",
        "std": "NIST FIPS 202",
        "oid": "2.16.840.1.101.3.4.2.8",
    },
    {
        "pattern": r"\b(?:SHA[-_]?512|sha512|hashlib\.sha512|createHash\(['\"]sha512|sha512\.New|sha512\.Sum512|SHA512\.HashData|SHA512\.Create|Sha512::new|Digest::SHA512|EVP_sha512|MessageDigest\.getInstance\(['\"]SHA-?512)\b",
        "name": "SHA-512",
        "primitive": "hash",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "512",
        "oid": "2.16.840.1.101.3.4.2.3",
    },
    {
        "pattern": r"\b(?:SHA[-_]?384|sha384|hashlib\.sha384|createHash\(['\"]sha384|sha512\.New384|SHA384\.HashData|SHA384\.Create|Sha384::new|Digest::SHA384|EVP_sha384|MessageDigest\.getInstance\(['\"]SHA-?384)\b",
        "name": "SHA-384",
        "primitive": "hash",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "384",
        "oid": "2.16.840.1.101.3.4.2.2",
    },
    {
        "pattern": r"\b(?:SHA[-_]?256|sha256|hashlib\.sha256|createHash\(['\"]sha256|sha256\.New|sha256\.Sum256|SHA256\.HashData|SHA256\.Create|Sha256::new|Digest::SHA256|EVP_sha256|CC_SHA256|MessageDigest\.getInstance\(['\"]SHA-?256|hash\(['\"]sha256|SHA2\([^,]+,\s*256\))\b",
        "name": "SHA-256",
        "primitive": "hash",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "256",
        "oid": "2.16.840.1.101.3.4.2.1",
    },
    {
        "pattern": r"\b(?:def\s+quickxor_hash|quickxor_hash\(|QuickXorHash)\b",
        "name": "QuickXorHash",
        "primitive": "hash",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "160",
    },

    # =========================================================================
    # 6. DEPRECATED / WEAK CLASSICAL PRIMITIVES (Immediate Remediation Required)
    # =========================================================================
    {
        "pattern": r"\b(?:hashlib\.sha1\(|createHash\(['\"]sha1|MessageDigest\.getInstance\(['\"]SHA-?1|sha1\.New\(|sha1\.Sum\(|SHA1\.Create|SHA1\.HashData|Sha1::new|Digest::SHA1|Insecure\.SHA1|EVP_sha1|hash\(['\"]sha1)\b",
        "name": "SHA-1",
        "primitive": "hash",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "160",
        "oid": "1.3.14.3.2.26",
    },
    {
        "pattern": r"\b(?:hashlib\.md5\(|createHash\(['\"]md5|MessageDigest\.getInstance\(['\"]MD5|md5\.New\(|md5\.Sum\(|MD5\.Create|MD5\.HashData|Md5::new|Digest::MD5|Insecure\.MD5|EVP_md5|hash\(['\"]md5)\b",
        "name": "MD5",
        "primitive": "hash",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "128",
        "oid": "1.2.840.113549.2.5",
    },
    {
        "pattern": r"\b(?:3DES|TripleDES|DESede|DES3\.new|TripleDES\.Create|EVP_des_ede3_cbc|Cipher\.getInstance\(['\"]DESede)\b",
        "name": "3DES",
        "primitive": "block-cipher",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "112",
    },
    {
        "pattern": r"\b(?:RC4|ARC4|ARC4\.new|Cipher\.getInstance\(['\"]RC4|EVP_rc4)\b",
        "name": "RC4",
        "primitive": "stream-cipher",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "128",
    },

    # =========================================================================
    # 7. CSPRNG / RANDOM BIT GENERATORS
    # =========================================================================
    {
        "pattern": r"\b(?:secrets\.token_bytes\(|secrets\.token_hex\(|secrets\.token_urlsafe\(|crypto\.randomBytes\(|crypto\.getRandomValues\(|SecureRandom\.getInstance|RandomNumberGenerator\.Fill|RandomNumberGenerator\.GetBytes|OsRng)\b",
        "name": "CSPRNG-DRBG",
        "primitive": "drbg",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "256",
        "std": "NIST SP 800-90A",
    },

    # =========================================================================
    # 8. PROTOCOLS (TLS, mTLS, SSH, OAuth2/OIDC)
    # =========================================================================
    {
        "pattern": r"\b(?:TLSv1_0|TLSv1_1|VersionTLS10|VersionTLS11|ssl\.PROTOCOL_TLSv1(?:_1)?|TLSv1\.0|TLSv1\.1)\b",
        "name": "TLS-1.0/1.1-Deprecated",
        "primitive": "protocol",
        "asset_type": "protocol",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "1.1",
    },
    {
        "pattern": r"\b(?:ssl\.create_default_context\(|SSLContext\(|TLSVersion\.TLSv1_3|tls\.VersionTLS13|tls\.Dial\(|rustls::ClientConfig|rustls::ServerConfig|SSL_CTX_new\(|InstalledAppFlow\.from_client_secrets_file\(|ConfidentialClientApplication\(|PublicClientApplication\(|ssl_protocols\s+.*TLSv1\.3)\b",
        "name": "TLS-1.3",
        "primitive": "protocol",
        "asset_type": "protocol",
        "pqc_status": "CLASSICAL/SYMMETRIC",
        "param": "1.3",
    },

    # =========================================================================
    # 9. CERTIFICATES & RELATED CRYPTOGRAPHIC MATERIAL (X.509, KMS, Keys)
    # =========================================================================
    {
        "pattern": r"(?:-----BEGIN CERTIFICATE-----|x509\.load_pem_x509_certificate|x509\.load_der_x509_certificate|x509\.ParseCertificate|X509Certificate2|crypto\.X509Certificate|CertificateFactory\.getInstance\(['\"]X\.509|aws_acm_certificate|tls_self_signed_cert)",
        "name": "X.509-Certificate",
        "primitive": "certificate",
        "asset_type": "certificate",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "RSA-2048/ECDSA-P256",
    },
    {
        "pattern": r"(?:-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|-----BEGIN PUBLIC KEY-----|aws_kms_key|google_kms_crypto_key|azurerm_key_vault_key|tls_private_key|KeyStore\.getInstance\()",
        "name": "Cryptographic-Key-Material",
        "primitive": "key",
        "asset_type": "related-crypto-material",
        "pqc_status": "QUANTUM-VULNERABLE",
        "param": "Asymmetric/KMS-Key",
    },
]

# File extensions to scan across 18+ programming languages, scripts, IaC, and PKI
SOURCE_EXTENSIONS = {
    # Python
    ".py",
    # JavaScript / TypeScript
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    # Go
    ".go",
    # Java / Kotlin / Scala
    ".java", ".kt", ".kts", ".scala",
    # C / C++
    ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp",
    # C# / .NET
    ".cs",
    # Rust
    ".rs",
    # Ruby
    ".rb",
    # PHP
    ".php",
    # Swift
    ".swift",
    # Dart / Flutter
    ".dart",
    # Elixir / Erlang
    ".ex", ".exs", ".erl",
    # Shell / PowerShell
    ".sh", ".bash", ".ps1",
    # SQL
    ".sql",
    # IaC & TLS / Proxy Configs & Certificates
    ".tf", ".hcl", ".conf", ".nginx", ".pem", ".crt", ".cer",
}

SPECIAL_FILENAMES = {"Dockerfile", "Containerfile", "nginx.conf"}

EXTENSION_TO_LANGUAGE = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".c": "C/C++",
    ".cpp": "C/C++",
    ".cc": "C/C++",
    ".cxx": "C/C++",
    ".h": "C/C++",
    ".hpp": "C/C++",
    ".cs": "C#",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".swift": "Swift",
    ".dart": "Dart",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".erl": "Erlang",
    ".sh": "Shell",
    ".bash": "Shell",
    ".ps1": "PowerShell",
    ".sql": "SQL",
    ".tf": "Terraform/IaC",
    ".hcl": "Terraform/IaC",
    ".conf": "Configuration",
    ".nginx": "Configuration",
    ".pem": "PKI/Certificate",
    ".crt": "PKI/Certificate",
    ".cer": "PKI/Certificate",
}

IGNORED_DIRS = {
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "env",
    "target", "dist", "build", "out", "bin", "obj", "oss", ".idea", ".vscode",
    ".gradle", ".mvn", ".next", ".nuxt", ".tox", ".mypy_cache", ".pytest_cache",
    "tests", "test", "__tests__", "fixtures", "testdata",
}

IGNORED_FILES = {
    "scan_crypto_ast.py", "analyze_cbom.py", "test_boms.sh", "generate_boms.sh",
    "fetch_oci_cbom.py", "enrich_sbom_gradle.py", "enrich_sbom_python.py",
    "update_os_inventory.py", "attach_oci_bom.sh", "install_to_repo.sh",
    "adr_gatekeeper.py", "pre_commit.py", "parse_cbom.py", "parse_gpg.py",
    "inject_algo.py", "scaffold_governance.py", "catalog.py", "update_readme.py",
    "inspect_memory.py", "check_fork_guardrail.py", "restore_skills.py",
    "sync.py", "deploy_skills.py",
}

# Ignore parser tools, benchmarks, and test fixtures when scanning production AST
IGNORED_FILE_PREFIXES = ("parse_", "test_", "mock_", "bench_")
IGNORED_FILE_SUFFIXES = (
    "_test.py", "_test.go", "_spec.js", "_spec.ts", ".test.js", ".test.ts",
    ".test.tsx", ".spec.tsx", "_spec.rb", "Test.java", "Tests.java", "Tests.cs",
)

# Patterns indicating string mappings, CLI definitions, or regexes rather than crypto instantiations
NON_CALL_PATTERNS = [
    r"^\s*[\"'][0-9a-zA-Z_-]+[\"']\s*:\s*[\"']",  # Dictionary mapping e.g. "1": "RSA"
    r"^\s*(?:help|description|epilog|usage)\s*=",  # CLI argument help text
    r"(?:keywords|keyword_list|vulnerable_keywords|pqc_keywords|ALGO_MAP|CRYPTO_PATTERNS)\s*=\s*\[",
    r"parser\.add_argument\(",                      # ArgumentParser calls
    r"^\s*(?:print|logger\.\w+|console\.log|fmt\.Print|log\.Print|System\.out\.print)\s*\(",
]


def _extract_python_ast_callsites(source: str, rel_path: str) -> List[Dict[str, Any]]:
    """
    Use Python's built-in `ast` module to accurately resolve function calls,
    keyword arguments (e.g., key_size=4096), and imported cryptographic symbols.
    """
    results: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(source, filename=rel_path)
    except Exception:
        return results

    lines = source.splitlines()

    # Map local alias -> full imported path
    alias_map: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                local_name = n.asname or n.name
                alias_map[local_name] = n.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for n in node.names:
                local_name = n.asname or n.name
                alias_map[local_name] = f"{mod}.{n.name}" if mod else n.name

    def resolve_attr(expr: ast.AST) -> str:
        if isinstance(expr, ast.Name):
            return alias_map.get(expr.id, expr.id)
        if isinstance(expr, ast.Attribute):
            parent = resolve_attr(expr.value)
            return f"{parent}.{expr.attr}" if parent else expr.attr
        return ""

    def get_kw_int(call_node: ast.Call, kw_names: Tuple[str, ...]) -> Optional[int]:
        for kw in call_node.keywords:
            if kw.arg in kw_names and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                return kw.value.value
        for arg in call_node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, int) and arg.value in (128, 192, 256, 384, 512, 1024, 2048, 3072, 4096):
                return arg.value
        return None

    def get_first_str_arg(call_node: ast.Call) -> Optional[str]:
        if call_node.args and isinstance(call_node.args[0], ast.Constant) and isinstance(call_node.args[0].value, str):
            return call_node.args[0].value
        for kw in call_node.keywords:
            if kw.arg in ("name", "algorithm", "digestmod", "cipher") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        lineno = getattr(node, "lineno", 0)
        if lineno <= 0 or lineno > len(lines):
            continue
        snippet = lines[lineno - 1].strip()[:120]
        target = resolve_attr(node.func)
        if not target:
            continue
        target_lower = target.lower()

        # 1. RSA key generation with dynamic key_size inspection
        if target_lower.endswith(("rsa.generate_private_key", "rsa.generate", "rsa.newkeys")):
            ksize = get_kw_int(node, ("key_size", "bits", "nbits")) or 2048
            results.append({
                "file": rel_path,
                "line": lineno,
                "snippet": snippet,
                "name": f"RSA-{ksize}",
                "primitive": "signature",
                "asset_type": "algorithm",
                "pqc_status": "QUANTUM-VULNERABLE",
                "parameter_set": str(ksize),
                "standard": "PKCS#1 / FIPS 186-5",
                "language": "Python",
            })
        # 2. Elliptic Curve key generation with curve inspection
        elif target_lower.endswith("ec.generate_private_key"):
            curve_name = "secp256r1"
            algo_label = "ECDSA-P256"
            all_arg_nodes = list(node.args) + [kw.value for kw in node.keywords]
            for a in all_arg_nodes:
                c_str = resolve_attr(a.func if isinstance(a, ast.Call) else a).upper()
                if "384" in c_str:
                    curve_name, algo_label = "secp384r1", "ECDSA-P384"
                elif "521" in c_str:
                    curve_name, algo_label = "secp521r1", "ECDSA-P521"
                elif "256K1" in c_str:
                    curve_name, algo_label = "secp256k1", "ECDSA-secp256k1"
            results.append({
                "file": rel_path,
                "line": lineno,
                "snippet": snippet,
                "name": algo_label,
                "primitive": "signature",
                "asset_type": "algorithm",
                "pqc_status": "QUANTUM-VULNERABLE",
                "parameter_set": curve_name,
                "standard": "FIPS 186-5",
                "language": "Python",
            })
        # 3. hashlib.new('...') dynamic algorithm resolution
        elif target_lower.endswith("hashlib.new"):
            algo_arg = (get_first_str_arg(node) or "").upper().replace("_", "-")
            if algo_arg:
                is_weak = algo_arg in ("MD5", "SHA1", "SHA-1", "RIPEMD160")
                param = "128" if "MD5" in algo_arg else "160" if "1" in algo_arg else "512" if "512" in algo_arg else "384" if "384" in algo_arg else "256"
                canonical = "SHA-1" if algo_arg == "SHA1" else ("SHA-256" if algo_arg == "SHA256" else algo_arg)
                results.append({
                    "file": rel_path,
                    "line": lineno,
                    "snippet": snippet,
                    "name": canonical,
                    "primitive": "hash",
                    "asset_type": "algorithm",
                    "pqc_status": "QUANTUM-VULNERABLE" if is_weak else "CLASSICAL/SYMMETRIC",
                    "parameter_set": param,
                    "standard": "FIPS 180-4 / FIPS 202",
                    "language": "Python",
                })
        # 4. hashlib.pbkdf2_hmac
        elif target_lower.endswith("pbkdf2_hmac"):
            results.append({
                "file": rel_path,
                "line": lineno,
                "snippet": snippet,
                "name": "PBKDF2-HMAC-SHA256",
                "primitive": "kdf",
                "asset_type": "algorithm",
                "pqc_status": "CLASSICAL/SYMMETRIC",
                "parameter_set": "256",
                "standard": "NIST SP 800-132",
                "language": "Python",
            })

    return results


def scan_source_files(root_dir: Path) -> List[Dict[str, Any]]:
    """Scan all source code, IaC, config, and PKI files in directory tree for crypto assets."""
    call_sites: List[Dict[str, Any]] = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Prune ignored directories
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".")]

        for fname in filenames:
            if fname in IGNORED_FILES:
                continue
            if any(fname.startswith(prefix) for prefix in IGNORED_FILE_PREFIXES):
                continue
            if any(fname.endswith(suffix) for suffix in IGNORED_FILE_SUFFIXES):
                continue

            ext = os.path.splitext(fname)[1].lower()
            if ext not in SOURCE_EXTENSIONS and fname not in SPECIAL_FILENAMES:
                continue

            fpath = Path(dirpath) / fname
            rel_path = str(fpath.relative_to(root_dir))
            language = EXTENSION_TO_LANGUAGE.get(ext, "Configuration" if fname in SPECIAL_FILENAMES else "Unknown")

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                print(f"Warning reading {fpath}: {e}", file=sys.stderr)
                continue

            # Track (line, primitive_category) already recorded so specific patterns
            # (e.g., RSA-4096 or AES-128-GCM) prevent duplicate generic fallback matches on the same line
            recorded_line_primitives: Set[Tuple[int, str]] = set()

            # 1. Python AST semantic pass
            if ext == ".py":
                ast_sites = _extract_python_ast_callsites(content, rel_path)
                for site in ast_sites:
                    call_sites.append(site)
                    recorded_line_primitives.add((site["line"], site["primitive"]))

            # 2. Multi-language line-by-line pattern pass with comment & docstring stripping
            in_multiline_comment = False
            multiline_delim = None

            for lineno, line in enumerate(content.splitlines(), start=1):
                line_stripped = line.strip()
                if not line_stripped:
                    continue

                # Python triple-quote docstring tracking
                if ext == ".py":
                    if not in_multiline_comment:
                        for delim in ('"""', "'''"):
                            if line_stripped.startswith(delim):
                                in_multiline_comment = True
                                multiline_delim = delim
                                if line_stripped.count(delim) >= 2:
                                    in_multiline_comment = False
                                    multiline_delim = None
                                break
                        if in_multiline_comment:
                            continue
                    else:
                        if multiline_delim and multiline_delim in line_stripped:
                            in_multiline_comment = False
                            multiline_delim = None
                        continue

                # C/Java/JS/Go/Rust/CSS/SQL multiline comment tracking (/* ... */)
                if line_stripped.startswith("/*"):
                    if "*/" not in line_stripped:
                        in_multiline_comment = True
                        multiline_delim = "*/"
                    continue
                elif in_multiline_comment and multiline_delim == "*/":
                    if "*/" in line_stripped:
                        in_multiline_comment = False
                        multiline_delim = None
                    continue

                # Single-line comment check (allow PEM -----BEGIN headers which start with -)
                if (
                    line_stripped.startswith("//")
                    or line_stripped.startswith("#")
                    or line_stripped.startswith("*")
                    or (line_stripped.startswith("--") and not line_stripped.startswith("-----BEGIN"))
                ):
                    continue

                # Filter non-call statements (dicts, CLI help, print statements, keyword lists)
                if any(re.search(pat, line) for pat in NON_CALL_PATTERNS):
                    continue

                for rule in CRYPTO_PATTERNS:
                    prim_key = rule.get("asset_type", rule["primitive"])
                    if (lineno, rule["primitive"]) in recorded_line_primitives or (lineno, prim_key) in recorded_line_primitives:
                        continue
                    if re.search(rule["pattern"], line, re.IGNORECASE):
                        # Redact snippet if it is inside a PEM file to ensure secret hygiene
                        safe_snippet = (
                            "[PEM/PKI Header Detected]"
                            if "-----BEGIN" in line_stripped and "PRIVATE KEY" in line_stripped
                            else line_stripped[:120]
                        )
                        call_sites.append({
                            "file": rel_path,
                            "line": lineno,
                            "snippet": safe_snippet,
                            "name": rule["name"],
                            "primitive": rule["primitive"],
                            "asset_type": rule.get("asset_type", "algorithm"),
                            "pqc_status": rule["pqc_status"],
                            "parameter_set": rule.get("param", "N/A"),
                            "mode": rule.get("mode"),
                            "oid": rule.get("oid"),
                            "standard": rule.get("std", "Classical"),
                            "language": language,
                        })
                        recorded_line_primitives.add((lineno, rule["primitive"]))
                        recorded_line_primitives.add((lineno, prim_key))

    return call_sites


def merge_cbomkit_outputs(cbom_path: Path) -> None:
    """
    If cbomkit-action generated `cbom_*.json` files in the same output directory,
    merge their components into `cbom_path` (`oss/cbom.json`) before AST reconciliation.
    """
    parent_dir = cbom_path.parent
    if not parent_dir.exists():
        return

    extra_files = sorted(
        f for f in parent_dir.glob("cbom*.json")
        if f.resolve() != cbom_path.resolve() and f.is_file()
    )
    if not extra_files:
        return

    if cbom_path.exists():
        try:
            base_data = json.loads(cbom_path.read_text(encoding="utf-8"))
        except Exception:
            base_data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}
    else:
        base_data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}

    base_comps = base_data.setdefault("components", [])
    seen_names = {c.get("name", "").upper() for c in base_comps if c.get("name")}

    for ef in extra_files:
        try:
            edata = json.loads(ef.read_text(encoding="utf-8"))
            for comp in edata.get("components", []):
                cname = comp.get("name", "").upper()
                if cname and cname not in seen_names:
                    base_comps.append(comp)
                    seen_names.add(cname)
        except Exception:
            continue

    cbom_path.write_text(json.dumps(base_data, indent=2), encoding="utf-8")


def reconcile_with_cbom(call_sites: List[Dict[str, Any]], cbom_path: Path) -> Tuple[int, int]:
    """
    Reconciles AST call sites with the generated CycloneDX CBOM.
    If CBOM components are missing instantiated functions, protocols, certificates,
    or key materials found in source AST, enriches the CBOM components to ensure
    100% complete coverage.
    """
    merge_cbomkit_outputs(cbom_path)

    if not cbom_path.exists():
        cbom_data: Dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:auto-generated-cbom",
            "version": 1,
            "components": [],
        }
    else:
        with open(cbom_path, "r", encoding="utf-8") as f:
            cbom_data = json.load(f)

    existing_components = cbom_data.get("components", [])

    def matches_existing(candidate: str, existing: str) -> bool:
        if candidate == existing:
            return True
        # Prevent false collisions across distinct SHA family members (SHA-1, SHA-256, SHA-384, SHA-512, SHA-3, SHA3-512)
        if candidate.startswith("SHA") and existing.startswith("SHA") and candidate != existing:
            return False
        # Prevent false collisions across distinct AES or RSA or ECDSA key sizes/modes
        for prefix in ("AES-", "RSA-", "ECDSA-", "ML-KEM-", "ML-DSA-", "HMAC-"):
            if candidate.startswith(prefix) and existing.startswith(prefix) and candidate != existing:
                return False
        base_cand = candidate.split("-")[0]
        base_exist = existing.split("-")[0]
        return base_cand == base_exist and (candidate in existing or existing in candidate)

    comp_map: Dict[str, Dict[str, Any]] = {}
    for comp in existing_components:
        name_u = comp.get("name", "").upper()
        comp_map[name_u] = comp

    def find_matching_comp(candidate: str) -> Optional[Dict[str, Any]]:
        for name_u, comp in comp_map.items():
            if matches_existing(candidate, name_u):
                return comp
        return None

    added_count = 0
    for site in call_sites:
        site_name_u = site["name"].upper()
        matched_comp = find_matching_comp(site_name_u)
        occ_entry = {
            "location": f"{site['file']}:{site['line']}",
            "snippet": site.get("snippet", ""),
            "language": site.get("language", "Unknown"),
        }

        if matched_comp:
            evidence = matched_comp.setdefault("evidence", {})
            occurrences = evidence.setdefault("occurrences", [])
            if not any(o.get("location") == occ_entry["location"] for o in occurrences):
                occurrences.append(occ_entry)
        else:
            asset_type = site.get("asset_type") or ("protocol" if site["primitive"] == "protocol" else "algorithm")
            if asset_type == "protocol":
                crypto_props: Dict[str, Any] = {
                    "assetType": "protocol",
                    "protocolProperties": {
                        "type": "tls",
                        "version": site["parameter_set"],
                    },
                }
            elif asset_type == "certificate":
                crypto_props = {
                    "assetType": "certificate",
                    "certificateProperties": {
                        "subjectName": site["name"],
                        "certificateFormat": "X.509",
                    },
                }
            elif asset_type == "related-crypto-material":
                crypto_props = {
                    "assetType": "related-crypto-material",
                    "relatedCryptoMaterialProperties": {
                        "type": "key-material",
                        "format": site["parameter_set"],
                    },
                }
            else:
                algo_props: Dict[str, Any] = {
                    "name": site["name"],
                    "primitive": site["primitive"],
                    "parameterSetIdentifier": site["parameter_set"],
                    "executionEnvironment": "software-plain-ram",
                }
                if site.get("mode"):
                    algo_props["mode"] = site["mode"]
                crypto_props = {
                    "assetType": "algorithm",
                    "algorithmProperties": algo_props,
                }
                if site.get("oid"):
                    crypto_props["oid"] = site["oid"]

            new_comp = {
                "type": "cryptographic-asset",
                "name": site["name"],
                "cryptoProperties": crypto_props,
                "evidence": {
                    "occurrences": [occ_entry],
                },
            }
            existing_components.append(new_comp)
            comp_map[site_name_u] = new_comp
            added_count += 1

    cbom_data["components"] = existing_components
    cbom_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cbom_path, "w", encoding="utf-8") as f:
        json.dump(cbom_data, f, indent=2)

    return added_count, len(existing_components)


def main():
    parser = argparse.ArgumentParser(description="Scan source AST for crypto call sites and reconcile with CBOM.")
    parser.add_argument("target_dir", type=Path, help="Root directory of target repository")
    parser.add_argument("--cbom", type=Path, default=Path("oss/cbom.json"), help="Path to CycloneDX CBOM JSON file")
    parser.add_argument("--output-json", type=Path, help="Path to write raw call-site inventory JSON")
    args = parser.parse_args()

    if not args.target_dir.is_dir():
        print(f"Error: Target directory not found: {args.target_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"🔍 Scanning source code AST in {args.target_dir} for cryptographic instantiations ...")
    call_sites = scan_source_files(args.target_dir)
    langs = sorted({s.get("language", "Unknown") for s in call_sites})
    lang_note = f" across {', '.join(langs)}" if langs else ""
    print(f"✅ Found {len(call_sites)} cryptographic call site(s){lang_note}.")

    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(call_sites, f, indent=2)
        print(f"Saved call-site inventory to: {args.output_json}")

    added, total = reconcile_with_cbom(call_sites, args.cbom)
    if added > 0:
        print(f"⚡ Reconciled CBOM: Injected {added} missing AST cryptographic asset(s). Total assets in CBOM: {total}")
    else:
        print(f"✅ CBOM Reconciled: All AST call sites are fully accounted for. Total assets in CBOM: {total}")


if __name__ == "__main__":
    main()
