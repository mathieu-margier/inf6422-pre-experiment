import requests
import os
import base64

SERVER_ADDRESS = "127.0.0.1:5000"
URL = "http://" + SERVER_ADDRESS + "/api/"

username = ''

# Clés de l'utilisateur
private_key = ''
public_key = ''
signing_key = ''
verifying_key = ''

# Dossier pour stocker les fichiers télécharges
DOWNLOAD_FOLDER = "downloads"
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

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
	print("{}'s encrypted message: {}".format(username, capsule))

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
	message_number = data["messageNumber"]

	# Récupération clé publique du destinataire
	response = requests.post(
		URL + "socialnetwork/getpublickeys",
		json={"username": choixEnvoi}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] != "ok"):
		print(data["error"])
		return False
	receiver_public_key = data["publicKey"]

	# Génération de la re-encryption key
	response = requests.post(
		URL + "client/gen_renc_key",
		json={"delegatorPrivateKey": private_key,
			"delegatorSigningKey": signing_key,
			"receiverPublicKey": receiver_public_key,
			"receiverUsername": choixEnvoi,
			"messageNumber": message_number}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] != "ok"):
		print(data["error"])
		return False
	print("Re-encryption key from {} to {} generated".format(username, choixEnvoi))

	return True

def envoiContenuCollectif():
	print("envoi de message collectif")
	return True

def receptionContenu():
	print("réception de contenu")
	# Récupération du contenu de Bob
	response = requests.post(
		URL + "socialnetwork/getcontent",
		json={"username": username}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] != "ok"):
		print(data["error"])
		return False

	messages = data["contents"]


	# Re-encryption des messages
	for message in messages:
		message_number = message[0]
		message_sender = message[1]
		message_content = message[2]
		message_capsule = message[3]

		# Récupération clé publique du destinataire
		response = requests.post(
			URL + "socialnetwork/getpublickeys",
			json={"username": message_sender}
		)
		assert response.status_code == 200
		data = response.json()
		if(data["status"] != "ok"):
			print(data["error"])
			return False
		sender_public_key = data["publicKey"]
		sender_verifying_key = data["verifyingKey"]

		# Re-encryption du message
		response = requests.post(
			URL + "proxy/re_encrypt",
			json={"delegatorPublicKey": sender_public_key,
				"delegatorVerifyingKey": sender_verifying_key,
				"receiverPublicKey": public_key,
				"capsule": message_capsule,
				"messageNumber": message_number,
				"receiver": username}
		)
		assert response.status_code == 200
		data = response.json()
		if(data["status"] != "ok"):
			print(data["error"])
			return False
		receiver_cfrag = data["cfrag"]
		print()
		print("{}'s encrypted capsule fragment: {}".format(username, receiver_cfrag))

		# Déchiffrement du receveur
		response = requests.post(
			URL + "decrypt_reenc",
			json={ # Decryption parameters
				"receiverPrivateKey": private_key,
				"ciphertext": message_content,
				"capsule": message_capsule,
				# Re-encryption additional parameters
				"receiverPublicKey": public_key,
				"delegatorPublicKey": sender_public_key,
				"delegatorVerifyingKey": sender_verifying_key,
				"cfrag": receiver_cfrag}
		)
		#print("Request: {}".format(response.text))
		assert response.status_code == 200
		data = response.json()
		if(data["status"] != "ok"):
			print(data["error"])
			return False
		print("plaintext : ")
		print(data["plaintext"])
		print("{} successfuly decrypted {}'s re-encrypted message!".format(username, message_sender))

# Fonctions d'envoi et de réception de fichiers
def envoiFichierIndividuel():
	print("envoi de fichier individuel")

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

	# Choix du fichier
	filePath = input("Veuillez entrer le chemin d'accès vers votre fichier : ")

	if not os.path.isfile(filePath):
		print("Le chemin donné n'est pas un fichier")
		return False

	fileContent = b''
	with open(filePath, 'rb') as f:
		fileContent = f.read()

	# Génération de clé et chiffrement symétrique du fichier
	response = requests.post(
		URL + "client/encrypt_file",
		json={"content": base64.b64encode(fileContent).decode('ascii')}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] != "ok"):
		print(data["error"])
		return False
	fileKey = data["key"]
	fileEncryptedContent = data["content"]
	print("symetric key generated: {}".format(fileKey))

	# Chiffrement de la clé symétrique
	response = requests.post(
		URL + "client/encrypt",
		json={"publicKey": public_key, "plaintext": fileKey}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] != "ok"):
		print(data["error"])
		return False
	keyCiphertext = data["ciphertext"]
	keyCapsule = data["capsule"]
	print("symmetric key ciphertext: {}".format(keyCiphertext))
	print("{}'s encrypted symmetric key: {}".format(username, keyCapsule))

	# Envoi du fichier chiffré, ainsi que la clé chiffrée et la capsule associée
	response = requests.post(
		URL + "socialnetwork/sendfile",
		json={
			"sender": username,
			"encryptedFile": fileEncryptedContent,
			"keyCiphertext": keyCiphertext, "keyCapsule": keyCapsule
		}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] != "ok"):
		print(data["error"])
		return False
	message_number = data["messageNumber"]

	# Récupération clé publique du destinataire
	response = requests.post(
		URL + "socialnetwork/getpublickeys",
		json={"username": choixEnvoi}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] != "ok"):
		print(data["error"])
		return False
	receiver_public_key = data["publicKey"]

	# Génération de la re-encryption key
	response = requests.post(
		URL + "client/gen_renc_key",
		json={"delegatorPrivateKey": private_key,
			"delegatorSigningKey": signing_key,
			"receiverPublicKey": receiver_public_key,
			"receiverUsername": choixEnvoi,
			"messageNumber": message_number}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] != "ok"):
		print(data["error"])
		return False
	print("Re-encryption key from {} to {} generated".format(username, choixEnvoi))

	return True

def receptionFichiers():
	print("réception des fichiers")
	# Récupération du contenu de Bob
	response = requests.post(
		URL + "socialnetwork/getfiles",
		json={"username": username}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] != "ok"):
		print(data["error"])
		return False

	files = data["contents"]

	for file in files:
		file_number, file_sender, file_path, file_key_ciphertext, file_key_capsule = file

		# Récupération clé publique de l'émetteur
		response = requests.post(
			URL + "socialnetwork/getpublickeys",
			json={"username": file_sender}
		)
		assert response.status_code == 200
		data = response.json()
		if(data["status"] != "ok"):
			print(data["error"])
			return False
		sender_public_key = data["publicKey"]
		sender_verifying_key = data["verifyingKey"]

		# Re-chiffrement de la clé symétrique
		response = requests.post(
			URL + "proxy/re_encrypt",
			json={"delegatorPublicKey": sender_public_key,
				"delegatorVerifyingKey": sender_verifying_key,
				"receiverPublicKey": public_key,
				"capsule": file_key_capsule,
				"messageNumber": file_number,
				"receiver": username}
		)
		assert response.status_code == 200
		data = response.json()
		if(data["status"] != "ok"):
			print(data["error"])
			return False
		receiver_cfrag = data["cfrag"]
		print()
		print("{}'s encrypted capsule fragment: {}".format(username, receiver_cfrag))

		# Déchiffrement de la clé symétrique par le receveur
		response = requests.post(
			URL + "decrypt_reenc",
			json={ # Decryption parameters
				"receiverPrivateKey": private_key,
				"ciphertext": file_key_ciphertext,
				"capsule": file_key_capsule,
				# Re-encryption additional parameters
				"receiverPublicKey": public_key,
				"delegatorPublicKey": sender_public_key,
				"delegatorVerifyingKey": sender_verifying_key,
				"cfrag": receiver_cfrag}
		)
		#print("Request: {}".format(response.text))
		assert response.status_code == 200
		data = response.json()
		if(data["status"] != "ok"):
			print(data["error"])
			return False
		file_key = data["plaintext"]
		print("symmetric key decrypted : {}".format(file_key))


		# Téléchargement du fichier chiffré par clé symétrique
		response = requests.post(
			URL + "socialnetwork/download_file",
			json={"filePath": file_path}
		)
		assert response.status_code == 200
		data = response.json()
		if(data["status"] != "ok"):
			print(data["error"])
			return False
		file_encrypted_content = data["content"]

		# Déchiffrement et sauvegarde du fichier chiffré par clé symétrique
		response = requests.post(
			URL + "client/decrypt_file",
			json={"key": file_key, "content": file_encrypted_content}
		)
		assert response.status_code == 200
		data = response.json()
		if(data["status"] != "ok"):
			print(data["error"])
			return False
		file_decrypted_content = data["content"]

		local_file = os.path.join(DOWNLOAD_FOLDER, "{}_{}".format(username, file_number))
		with open(local_file, "wb") as f:
			f.write(base64.b64decode(file_decrypted_content.encode('ascii')))

		print("{} successfuly decrypted {}'s re-encrypted file!".format(username, file_sender))
		print("Saved to {}".format(local_file))

# Connexion ou inscription
choice = 0
validation = False

while(choice != '1' or not validation):
	choice = input('1 - Se connecter\n2 - Creer nouvel utilisateur\nChoix : ')

	if(choice == '1'):
		validation, private_key, public_key, signing_key, verifying_key, username = connexion()
	if(choice == '2'):
		validation = inscription()

connected_choices = [
	("Partager du contenu à une personne", envoiContenuIndividuel),
	("Partager un fichier à une personne", envoiFichierIndividuel),
	("Partager du contenu à un groupe", envoiContenuCollectif),
	("Recevoir le contenu qui m'est destiné", receptionContenu),
	("Recevoir les fichiers qui me sont destinés", receptionFichiers)
]

connected_input_dialog = ""
for i, (msg, f) in enumerate(connected_choices):
	connected_input_dialog += "{} - {}\n".format(i+1, msg)
connected_input_dialog += "{} - Quitter\n".format(len(connected_choices) + 1)
connected_input_dialog += "Choix : "

# Menu utilisateur connecté
while(choice != str(len(connected_choices)+1)):
	choice = input(connected_input_dialog)

	try:
		choiceIndex = int(choice) - 1

		if 0 <= choiceIndex < len(connected_choices):
			validation = connected_choices[choiceIndex][1]()
	except ValueError as e:
		print("Invalid choice : not a number")


# ## Signing / verifying keypair
# response = requests.get(URL + "genkey")
# assert response.status_code == 200
# data = response.json()
# assert data["status"] == "ok"
# alices_signing_key = data["privateKey"]
# alices_verifying_key = data["publicKey"]

# # 2. Generate Bob keys

# ## Private / public keypair
# response = requests.get(URL + "genkey")
# assert response.status_code == 200
# data = response.json()
# assert data["status"] == "ok"
# bobs_private_key = data["privateKey"]
# bobs_public_key = data["publicKey"]

# # 3. Encrypt plaintext for Alice

# plaintext = 'Proxy Re-encryption is cool!'
# print("plaintext: {}".format(plaintext))
# response = requests.post(
#     URL + 'encrypt',
#     json={"publicKey": public_key, "plaintext": plaintext}
# )
# #print("Request: {}".format(response.text))
# assert response.status_code == 200
# data = response.json()
# assert data["status"] == "ok"
# ciphertext = data["ciphertext"]
# alice_capsule = data["capsule"]

# print("ciphertext: {}".format(ciphertext))
# print("alice's encrypted message: {}".format(alice_capsule))
# print()

# # 4. Test alice's decryption
# response = requests.post(
#     URL + "decrypt",
#     json={"receiverPrivateKey": private_key, "ciphertext": ciphertext, "capsule": alice_capsule}
# )
# assert response.status_code == 200
# data = response.json()
# assert data["status"] == "ok"
# assert data["plaintext"] == plaintext
# print("Alice successfuly decrypt her message!")

# # 5. Test bob's decryption (should fail)
# response = requests.post(
#     URL + "decrypt",
#     json={"receiverPrivateKey": bobs_private_key, "ciphertext": ciphertext, "capsule": alice_capsule}
# )
# assert response.status_code == 200
# data = response.json()
# assert data["status"] == "error"
# print("Bob could not decrypt Alice's message!")
# print()

# # 6. Generate re-encryption key
# response = requests.post(
#     URL + "gen_renc_key",
#     json={"delegatorPrivateKey": private_key,
#           "delegatorSigningKey": alices_signing_key,
#           "receiverPublicKey": bobs_public_key}
# )
# assert response.status_code == 200
# data = response.json()
# assert data["status"] == "ok"
# alice_to_bob_rencryption_key = data["reencKey"]
# print("Re-encryption key from alice to bob generated")

# # 7. Re-encrypt message
# response = requests.post(
#     URL + "re_encrypt",
#     json={"delegatorPublicKey": public_key,
#           "delegatorVerifyingKey": alices_verifying_key,
#           "receiverPublicKey": bobs_public_key,
#           "reencKey": alice_to_bob_rencryption_key,
#           "capsule": alice_capsule}
# )
# assert response.status_code == 200
# data = response.json()
# assert data["status"] == "ok"
# bob_cfrag = data["cfrag"]
# print()
# print("Bob's encrypted capsule fragment: {}".format(bob_cfrag))

# # 5. Finally, bob decryption
# response = requests.post(
#     URL + "decrypt_reenc",
#     json={ # Decryption parameters
#           "receiverPrivateKey": bobs_private_key,
#           "ciphertext": ciphertext,
#           "capsule": alice_capsule,
#           # Re-encryption additional parameters
#           "receiverPublicKey": bobs_public_key,
#           "delegatorPublicKey": public_key,
#           "delegatorVerifyingKey": alices_verifying_key,
#           "cfrag": bob_cfrag}
# )
# #print("Request: {}".format(response.text))
# assert response.status_code == 200
# data = response.json()
# assert data["status"] == "ok"
# assert data["plaintext"] == plaintext

# print("Bob successfuly decrypted Alice's re-encrypted message!")
# print("Original message: {}".format(data["plaintext"]))
