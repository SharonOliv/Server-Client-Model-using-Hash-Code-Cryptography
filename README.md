<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Server-Client Model using Hash Code Cryptography</title>
</head>
<body>
    <h1>Server-Client Model using Hash Code Cryptography</h1>

    <p><strong>Secure message transmission</strong> using Diffie-Hellman key exchange, AES encryption, and SHA-512 hashing to ensure confidentiality and integrity.</p>

    <h2>Project Overview</h2>
    <p>This project demonstrates secure message exchange between a client and server, ensuring <strong>confidentiality</strong> and <strong>integrity</strong>.</p>

    <h3>It includes:</h3>
    <ul>
        <li><strong>SHA-512 hashing</strong> to generate a secure hash code of a given message.</li>
        <li><strong>Diffie-Hellman key exchange</strong> to securely generate a shared session key.</li>
        <li><strong>AES encryption</strong> to encrypt both the message and its hash for confidentiality.</li>
        <li><strong>Integrity verification</strong> by validating the received hash against the message.</li>
    </ul>

    <h2>Features</h2>
    <ul>
        <li>Generate SHA-512 hash codes.</li>
        <li>Secure session key generation using Diffie-Hellman.</li>
        <li>Encrypt and decrypt messages using AES symmetric encryption.</li>
        <li>Ensure data integrity by verifying message hashes after decryption.</li>
    </ul>

    <h2>Technologies Used</h2>
    <ul>
        <li>Python 3</li>
        <li>Cryptography library (for AES, Diffie-Hellman)</li>
        <li>hashlib (for SHA-512)</li>
    </ul>

</body>
</html>
