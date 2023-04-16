import ntru

def generate_key_pair():
    # Génération des paramètres pour l'algorithme NTRU
    params = ntru.EncryptionParameters(ntru.EES1171EP1)
    # Génération des clés publiques et privées
    pub_key, priv_key = ntru.generate_keypair(params)
    # Conversion des clés en chaînes de caractères
    pub_key_str = pub_key.export()
    priv_key_str = priv_key.export()
    return pub_key_str, priv_key_str

def encrypt(public_key, message):
    # Chargement de la clé publique à partir de la chaîne de caractères
    pub_key = ntru.PublicKey.import_(public_key)
    # Chiffrement du message
    ciphertext = pub_key.encrypt(message.encode())
    # Conversion du texte chiffré en hexadécimal pour l'affichage
    ciphertext_hex = ciphertext.export().hex()
    return ciphertext_hex

def decrypt(private_key, ciphertext_hex):
    # Chargement de la clé privée à partir de la chaîne de caractères
    priv_key = ntru.PrivateKey.import_(private_key)
    # Conversion du texte chiffré de l'hexadécimal
    ciphertext = ntru.Ciphertext.import_(bytes.fromhex(ciphertext_hex))
    # Déchiffrement du message
    plaintext = priv_key.decrypt(ciphertext)
    return plaintext.decode()

public_key, private_key = generate_key_pair()

message = "Bonjour, comment ça va?"
ciphertext = encrypt(public_key, message)
print("Message chiffré:", ciphertext)

decrypted_message = decrypt(private_key, ciphertext)
print("Message déchiffré:", decrypted_message)
