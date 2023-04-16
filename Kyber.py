import kyber

def generate_key_pair():
    # Génération des paramètres pour l'algorithme Kyber
    params = kyber.Params(kyber.Kyber768)
    # Génération des clés publiques et privées
    pub_key, priv_key = kyber.keypair(params)
    # Conversion des clés en chaînes de caractères
    pub_key_str = pub_key.tostring()
    priv_key_str = priv_key.tostring()
    return pub_key_str, priv_key_str

def encrypt(public_key, message):
    # Chargement de la clé publique à partir de la chaîne de caractères
    pub_key = kyber.PublicKey.fromstring(public_key)
    # Chiffrement du message
    ciphertext, shared_key = kyber.encrypt(pub_key, message.encode())
    # Conversion du texte chiffré et de la clé partagée en hexadécimal pour l'affichage
    ciphertext_hex = ciphertext.tostring().hex()
    shared_key_hex = shared_key.tostring().hex()
    return ciphertext_hex, shared_key_hex

def decrypt(private_key, ciphertext_hex, shared_key_hex):
    # Chargement de la clé privée à partir de la chaîne de caractères
    priv_key = kyber.PrivateKey.fromstring(private_key)
    # Conversion du texte chiffré et de la clé partagée de l'hexadécimal
    ciphertext = kyber.Ciphertext.fromstring(bytes.fromhex(ciphertext_hex))
    shared_key = kyber.SharedKey.fromstring(bytes.fromhex(shared_key_hex))
    # Déchiffrement du message
    plaintext = kyber.decrypt(priv_key, ciphertext, shared_key)
    return plaintext.decode()

public_key, private_key = generate_key_pair()

message = "Bonjour, comment ça va?"
ciphertext, shared_key = encrypt(public_key, message)
print("Message chiffré:", ciphertext)
print("Clé partagée:", shared_key)

decrypted_message = decrypt(private_key, ciphertext, shared_key)
print("Message déchiffré:", decrypted_message)
