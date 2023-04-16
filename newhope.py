import newhope

def generate_key_pair():
    # Génération des paramètres pour l'algorithme NewHope
    params = newhope.Parameters(newhope.Params1024_509)
    # Génération des clés publiques et privées
    pub_key, priv_key = newhope.keygen(params)
    # Conversion des clés en chaînes de caractères
    pub_key_str = pub_key.serialize()
    priv_key_str = priv_key.serialize()
    return pub_key_str, priv_key_str

def encrypt(public_key, message):
    # Chargement de la clé publique à partir de la chaîne de caractères
    pub_key = newhope.PublicKey.deserialize(public_key)
    # Chiffrement du message
    ciphertext, shared_key = newhope.encrypt(pub_key, message.encode())
    # Conversion du texte chiffré et de la clé partagée en hexadécimal pour l'affichage
    ciphertext_hex = ciphertext.serialize().hex()
    shared_key_hex = shared_key.serialize().hex()
    return ciphertext_hex, shared_key_hex

def decrypt(private_key, ciphertext_hex, shared_key_hex):
    # Chargement de la clé privée à partir de la chaîne de caractères
    priv_key = newhope.PrivateKey.deserialize(private_key)
    # Conversion du texte chiffré et de la clé partagée de l'hexadécimal
    ciphertext = newhope.Ciphertext.deserialize(bytes.fromhex(ciphertext_hex))
    shared_key = newhope.SharedKey.deserialize(bytes.fromhex(shared_key_hex))
    # Déchiffrement du message
    plaintext = newhope.decrypt(priv_key, ciphertext, shared_key)
    return plaintext.decode()

public_key, private_key = generate_key_pair()

message = "Bonjour, comment ça va?"
ciphertext, shared_key = encrypt(public_key, message)
print("Message chiffré:", ciphertext)
print("Clé partagée:", shared_key)

decrypted_message = decrypt(private_key, ciphertext, shared_key)
print("Message déchiffré:", decrypted_message)
