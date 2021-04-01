import requests

SERVER_ADDRESS = "127.0.0.1:5000"
URL = "http://" + SERVER_ADDRESS + "/api/"


# 1. Generate Alice keys

## Private / public keypair
response = requests.get(URL + "genkey")
assert response.status_code == 200
data = response.json()
assert data["status"] == "ok"
alices_private_key = data["privateKey"]
alices_public_key = data["publicKey"]

## Signing / verifying keypair
response = requests.get(URL + "genkey")
assert response.status_code == 200
data = response.json()
assert data["status"] == "ok"
alices_signing_key = data["privateKey"]
alices_verifying_key = data["publicKey"]

# 2. Generate Bob keys

## Private / public keypair
response = requests.get(URL + "genkey")
assert response.status_code == 200
data = response.json()
assert data["status"] == "ok"
bobs_private_key = data["privateKey"]
bobs_public_key = data["publicKey"]

# 3. Encrypt plaintext for Alice

plaintext = 'Proxy Re-encryption is cool!'
print("plaintext: {}".format(plaintext))
response = requests.post(
    URL + 'encrypt',
    json={"publicKey": alices_public_key, "plaintext": plaintext}
)
#print("Request: {}".format(response.text))
assert response.status_code == 200
data = response.json()
assert data["status"] == "ok"
ciphertext = data["ciphertext"]
alice_capsule = data["capsule"]

print("ciphertext: {}".format(ciphertext))
print("alice's encrypted message: {}".format(alice_capsule))
print()

# 4. Test alice's decryption
response = requests.post(
    URL + "decrypt",
    json={"receiverPrivateKey": alices_private_key, "ciphertext": ciphertext, "capsule": alice_capsule}
)
assert response.status_code == 200
data = response.json()
assert data["status"] == "ok"
assert data["plaintext"] == plaintext
print("Alice successfuly decrypt her message!")

# 5. Test bob's decryption (should fail)
response = requests.post(
    URL + "decrypt",
    json={"receiverPrivateKey": bobs_private_key, "ciphertext": ciphertext, "capsule": alice_capsule}
)
assert response.status_code == 200
data = response.json()
assert data["status"] == "error"
print("Bob could not decrypt Alice's message!")
print()

# 6. Generate re-encryption key
response = requests.post(
    URL + "gen_renc_key",
    json={"delegatorPrivateKey": alices_private_key,
          "delegatorSigningKey": alices_signing_key,
          "receiverPublicKey": bobs_public_key}
)
assert response.status_code == 200
data = response.json()
assert data["status"] == "ok"
alice_to_bob_rencryption_key = data["reencKey"]
print("Re-encryption key from alice to bob generated")

# 7. Re-encrypt message
response = requests.post(
    URL + "re_encrypt",
    json={"delegatorPublicKey": alices_public_key,
          "delegatorVerifyingKey": alices_verifying_key,
          "receiverPublicKey": bobs_public_key,
          "reencKey": alice_to_bob_rencryption_key,
          "capsule": alice_capsule}
)
assert response.status_code == 200
data = response.json()
assert data["status"] == "ok"
bob_cfrag = data["cfrag"]
print()
print("Bob's encrypted capsule fragment: {}".format(bob_cfrag))

# 5. Finally, bob decryption
response = requests.post(
    URL + "decrypt_reenc",
    json={ # Decryption parameters
          "receiverPrivateKey": bobs_private_key,
          "ciphertext": ciphertext,
          "capsule": alice_capsule,
          # Re-encryption additional parameters
          "receiverPublicKey": bobs_public_key,
          "delegatorPublicKey": alices_public_key,
          "delegatorVerifyingKey": alices_verifying_key,
          "cfrag": bob_cfrag}
)
#print("Request: {}".format(response.text))
assert response.status_code == 200
data = response.json()
assert data["status"] == "ok"
assert data["plaintext"] == plaintext

print("Bob successfuly decrypted Alice's re-encrypted message!")
print("Original message: {}".format(data["plaintext"]))
