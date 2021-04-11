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
		print("clé public : " + public_key)
		print("clé privée : " + private_key)
		print("clé de signature : " + signing_key)
		print("clé de verification : " + verifying_key)
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
	print('CHIFFREMENT')
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
	print("capsule : {}".format(capsule))

	# Envoi du message chiffré et de la capsule
	print ('ENVOI AU RESEAU SOCIAL')
	response = requests.post(
		URL + "socialnetwork/sendmessage",
		json={"sender": username, "link": ciphertext, "capsule": capsule, "IsEncrypted": True}
	)
	assert response.status_code == 200
	data = response.json()
	if(data["status"] != "ok"):
		print(data["error"])
		return False
	message_number = data["messageNumber"]

	# Récupération clé publique du destinataire
	print('RECUPERATION CLE PUBLIQUE DU DESTINATAIRE')
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
	print("clé publique destinataire : " + receiver_public_key)

	# Génération de la re-encryption key
	print('GENERATION ET STOCKAGE DE LA CLE DE RE-ENCRYPTION')
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

	return True

def envoiContenuCollectif():
	print("envoi de message collectif")
	recievers=[]
	number_reviever = int(input('A combien de personnes voulez vous envoyer ce message\nNombre : '))
	for i in range(number_reviever):

		# Choix du destinataire
		choixEnvoi = input('A qui voulez-vous envoyer ce message\nChoix : ')
		response = requests.post(
			URL + "socialnetwork/checkuserexistence",
			json={"usernames": [choixEnvoi]}
		)
		assert response.status_code == 200
		data = response.json()
		if (data["status"] != "ok"):
			print(data["error"])
			return False
		recievers.append(choixEnvoi)

	# Message et chiffrement
	message = input('Veuillez entrer votre message\nMessage : ')
	print('CHIFFREMENT DU MESSAGE')
	response = requests.post(
		URL + "client/encrypt",
		json={"publicKey": public_key, "plaintext": message}
	)
	assert response.status_code == 200
	data = response.json()
	if (data["status"] != "ok"):
		print(data["error"])
		return False
	ciphertext = data["ciphertext"]
	capsule = data["capsule"]
	print("ciphertext: {}".format(ciphertext))
	print("capsule: {}".format(capsule))

	# Envoi du message chiffré et de la capsule
	print('ENVOI MESSAGE AU RESEAU SOCIAL')
	response = requests.post(
		URL + "socialnetwork/sendmessage",
		json={"sender": username, "link": ciphertext, "capsule": capsule, "IsEncrypted": True}
	)
	assert response.status_code == 200
	data = response.json()
	if (data["status"] != "ok"):
		print(data["error"])
		return False
	message_number = data["messageNumber"]

	# Récupération clé publique du destinataire
	print('RECUPERATION CLES PUBLIQUES ET GENERATION CLES DE REENCRYPTION POUR CHAQUE DESTINATAIRE')
	for person in recievers:
		response = requests.post(
			URL + "socialnetwork/getpublickeys",
			json={"username": person}
		)
		assert response.status_code == 200
		data = response.json()
		if (data["status"] != "ok"):
			print(data["error"])
			return False
		receiver_public_key = data["publicKey"]

	# Génération de la re-encryption key
		response = requests.post(
			URL + "client/gen_renc_key",
			json={"delegatorPrivateKey": private_key,
				  "delegatorSigningKey": signing_key,
				  "receiverPublicKey": receiver_public_key,
				  "receiverUsername": person,
				  "messageNumber": message_number}
		)
		assert response.status_code == 200
		data = response.json()
		if (data["status"] != "ok"):
			print(data["error"])
			return False
		print("Re-encryption key from "+ username +" to "+ person + " generated")

	return True

def receptionContenu():
	print("RECUPERATION DU CONTENU CHIFFRE DEPUIS LE RESEAU SOCIAL")
	# Récupération du contenu de Bob
	response = requests.post(
		URL + "socialnetwork/getcontent",
		json={"username": username, "IsEncrypted" : True}
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

		print('message chiffré : '+message_content)

		# Récupération clé publique de l'emetteur
		print ('RECUPERATION CLE PUBLIQUE DE L\'EMETTEUR')
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

		print('clé publique emetteur : '+ sender_public_key)
		print('clé de verification emetteur : ' + sender_verifying_key)

		# Re-encryption du message
		print('RE-ENCRYPTION DU MESSAGE')
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
		print("message re-encrypté: {}".format(receiver_cfrag))

		# Déchiffrement du receveur
		print('DECHIFFREMENT DESTINATAIRE')
		response = requests.post(
			URL + "client/decrypt_reenc",
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
		assert response.status_code == 200
		data = response.json()
		if(data["status"] != "ok"):
			print(data["error"])
			return False
		print("from : " + message_sender)
		print("plaintext : ")
		print(data["plaintext"])
		print("OPERATION TERMINEE")

def boiteEnvoie():
	print("visualiation des messages émis")
	# Récupération du contenu
	print('RECUPERATION DES MESSAGES CHIFFRES DEPUIS LE RESEAU SOCIAL')
	response = requests.post(
		URL + "socialnetwork/getowncontent",
		json={"username": username}
	)
	assert response.status_code == 200
	data = response.json()
	if (data["status"] != "ok"):
		print(data["error"])
		return False

	messages = data["contents"]

	# Re-encryption des messages
	for message in messages:
		message_number = message[0]
		message_content = message[2]
		message_capsule = message[3]
		message_encrypted = message[4]

		if not message_encrypted:
			print("message numéro : " + str(message_number) + " (non chiffré)")
			print("plaintext : ")
			print(message_content)
			print("OPERATION TERMINEE")
			return

		print('message chiffré : ' + message_content)

		# Déchiffrement du receveur
		print('DECHIFFREMENT RECEVEUR')
		response = requests.post(
			URL + "client/decrypt",
			json={"receiverPrivateKey": private_key, "ciphertext": message_content, "capsule": message_capsule}
		)
		# print("Request: {}".format(response.text))
		assert response.status_code == 200
		data = response.json()
		if (data["status"] != "ok"):
			print(data["error"])
			return False
		print("message numéro : " + str(message_number))
		print("plaintext : ")
		print(data["plaintext"])

		print("OPERATION TERMINEE")


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
			URL + "client/decrypt_reenc",
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

# Envoi/récpetion de message non chiffré
def envoieSansEncryption():
	print("envoi de message individuel sans encryption")

	# Message et chiffrement
	message = input('Veuillez entrer votre message\nMessage : ')

	# Envoi du message chiffré et de la capsule
	print('ENVOI AU RESEAU SOCIAL')
	response = requests.post(
		URL + "socialnetwork/sendmessage",
		json={"sender": username, "link": message, "capsule": message, "IsEncrypted": False}
	)
	assert response.status_code == 200
	data = response.json()
	if (data["status"] != "ok"):
		print(data["error"])
		return False

	return True

def receptionSansEncryption():
	print("réception de contenu non encrypté")
	# Récupération du contenu
	print('RECUPERATION DU CONTENU')
	response = requests.post(
		URL + "socialnetwork/getcontent",
		json={"username": username, "IsEncrypted": False},
	)
	assert response.status_code == 200
	data = response.json()
	if (data["status"] != "ok"):
		print(data["error"])
		return False

	messages = data["contents"]

	for message in messages:
		message_number = message[0]
		message_sender = message[1]
		message_content = message[2]

		print("de : " + message_sender)
		print("numero : " + str(message_number))
		print("message non chiffré : ")
		print(message_content)

	return True

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
	("Partager du contenu à un groupe", envoiContenuCollectif),
	("Partager un fichier à une personne", envoiFichierIndividuel),
	("Partager du contenu non chiffré à tout le monde", envoieSansEncryption),
	("Voir mes messages envoyés", boiteEnvoie),
	("Recevoir le contenu qui m'est destiné", receptionContenu),
	("Recevoir du contenu non chiffré", receptionSansEncryption),
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
