import requests

SERVER_ADDRESS = "127.0.0.1:5000"
URL = "http://" + SERVER_ADDRESS + "/api/"

username = ''

# Clés de l'utilisateur
private_key = ''
public_key = ''
signing_key = ''
verifying_key = ''

# Fonctions pour le menu principal
def connexion():
	user = input('Nom d\'utilisateur : ')
	## Récupération des clés
	response = requests.post(
		URL + "keygenerator/getallkeys",
		json={"username": user}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] == "ok"):
		private_key = data["privateKey"]
		public_key = data["publicKey"]
		signing_key = data["signingKey"]
		verifying_key = data["verifyingKey"]
		username = user
		return True, private_key, public_key, signing_key, verifying_key, user
	else:
		print(data["error"])
		return False, '', '', '', '', ''
	
def inscription():
	username = input('Nom d\'utilisateur : ')
	response = requests.post(
		URL + "socialnetwork/genuser",
		json={"username": username}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] == "ok"):
		print("Bienvenue " + username)
		return True
	else:
		print(data["error"])
		return False

# Fonctions d'envoi et de réception de messages

def envoiContenuIndividuel():
	print("envoi de message individuel")

	# Choix du destinataire
	choixEnvoi = input('A qui voulez-vous envoyer ce message\nChoix : ')
	response = requests.post(
		URL + "socialnetwork/checkuserexistence",
		json={"usernames": [choixEnvoi]}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] != "ok"):
		print(data["error"])
		return False

	# Message et chiffrement
	message = input('Veuillez entrer votre message\nMessage : ')
	response = requests.post(
		URL + "client/encrypt",
		json={"publicKey": public_key, "plaintext": message}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] != "ok"):
		print(data["error"])
		return False
	ciphertext = data["ciphertext"]
	capsule = data["capsule"]
	print("ciphertext: {}".format(ciphertext))
	print("alice's encrypted message: {}".format(capsule))

	# Envoi du message chiffré et de la capsule
	response = requests.post(
		URL + "socialnetwork/sendmessage",
		json={"sender": username, "link": ciphertext, "capsule": capsule}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] != "ok"):
		print(data["error"])
		return False

	return True


def envoiContenuCollectif():
	print("envoi de message collectif")

def receptionContenu():
	print("réception de contenu")

# Connexion ou inscription
choice = 0
validation = False

while(choice != '1' or not validation):
	choice = input('1 - Se connecter\n2 - Creer nouvel utilisateur\nChoix : ')

	if(choice == '1'):
		validation, private_key, public_key, signing_key, verifying_key, username = connexion()
	if(choice == '2'):
		validation = inscription()
		
# Menu utilisateur connecté		
while(choice != '4'):
	choice = input('1 - Partager du contenu à une personne\n2 - Partager du contenu à un groupe\n3 - Recevoir le contenu qui m\'est destiné\n4 - Quitter\nChoix : ')

	if(choice == '1'):
		validation = envoiContenuIndividuel()
	if(choice == '2'):
		validation = envoiContenuCollectif()
	if(choice == '3'):
		validation = receptionContenu()



# 1. Generate Alice keys



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
    json={"publicKey": public_key, "plaintext": plaintext}
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
    json={"receiverPrivateKey": private_key, "ciphertext": ciphertext, "capsule": alice_capsule}
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
    json={"delegatorPrivateKey": private_key,
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
    json={"delegatorPublicKey": public_key,
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
          "delegatorPublicKey": public_key,
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
