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
		message_capsule = message[4]

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
		message_capsule = message[4]
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
		
# Menu utilisateur connecté
while(choice != '7'):
	choice = input('1 - Partager du contenu à une personne\n2 - Partager du contenu à un groupe\n3 - Recevoir le contenu qui m\'est destiné\n4 - Voir mes messages envoyés\n5 - Partager du contenu non chiffré à tout le monde\n6 - Recevoir du contenu non chiffré\n7 - Quitter\nChoix : ')

	if(choice == '1'):
		validation = envoiContenuIndividuel()
	if(choice == '2'):
		validation = envoiContenuCollectif()
	if(choice == '3'):
		validation = receptionContenu()
	if (choice == '4'):
		validation = boiteEnvoie()
	if (choice == '5'):
		validation = envoieSansEncryption()
	if (choice == '6'):
		validation = receptionSansEncryption()
