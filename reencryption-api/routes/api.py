import time
import random
import statistics
import sqlite3
from . import database
from flask import Flask, Blueprint, request, abort, json
from umbral import pre, keys, config, signing, kfrags, cfrags

api = Blueprint('api', __name__)

# Setup PRE
config.set_default_curve()

# Statistics of durations (in second) for each PRE endpoint
time_stats_endpoints = {
    "genkey": [],
    "genuser": [],
    "getallkeys": [],
    "getpublickey": [],
    "encrypt": [],
    "gen_renc_key": [],
    "re_encrypt": [],
    "decrypt": [],
    "decrypt_reenc": [],
    "send_message": []
}

# Counter to find messages

message_counter = 0

# Database init
conn = sqlite3.connect('social_network.db')
c = conn.cursor()
database.initialisation_data_base(c)
conn.commit()
conn.close()


@api.route("/genkey", methods=["GET"])
def genkey():
    start = time.perf_counter()
    private_key = keys.UmbralPrivateKey.gen_key()
    public_key = private_key.get_pubkey()
    end = time.perf_counter()

    time_stats_endpoints["genkey"].append(end - start)

    return {"status": "ok", "privateKey": private_key.to_bytes().hex(), "publicKey": public_key.to_bytes().hex()}

# Social network endpoints (réalisés par le réseau social)
@api.route("socialnetwork/genuser", methods=["POST"])    
def genuser(): 
	if request.content_type.lower() != "application/json":
		abort(415)

	data = request.get_json()
	
	if "username" in data:
		try:
			start = time.perf_counter()
			conn = sqlite3.connect('social_network.db')
			c = conn.cursor()
			testExistence = database.show_element(c, "users", "FirstName", data["username"])
			if(testExistence != None):
				print("Utilisateur deja present")
				conn.close()
				return {"status": "error", "error": "Nom d utilisateur deja utilisé"}
				
			else:
				print("Ajout de l utilisateur")
				private_key = keys.UmbralPrivateKey.gen_key()
				public_key = private_key.get_pubkey()
				signing_key = keys.UmbralPrivateKey.gen_key()
				verifying_key = signing_key.get_pubkey()
				database.add_user(c, data["username"], private_key.to_bytes().hex(), public_key.to_bytes().hex(), signing_key.to_bytes().hex(), verifying_key.to_bytes().hex())
				conn.commit()
				conn.close()
				end = time.perf_counter()
				time_stats_endpoints["genuser"].append(end - start)
				return {"status": "ok"}
				
		except Exception as e:
			print(e)
			return {"status": "error", "error": str(e)}

	abort(400)

@api.route("socialnetwork/getpublickey", methods=["POST"])
def get_public_key(): 
	if request.content_type.lower() != "application/json":
		abort(415)

	data = request.get_json()

	if "username" in data:
		try:
			start = time.perf_counter()
			conn = sqlite3.connect('social_network.db')
			c = conn.cursor()
			user = database.show_element(c, "users", "FirstName", data["username"])
			if(user == None):
				print("L\'utilisateur n\'existe pas")
				conn.close()
				return {"status": "error", "error": "L\'utilisateur n\'existe pas"}
			public_key = user[1]
			conn.close()
			end = time.perf_counter()
			time_stats_endpoints["getpublickey"].append(end - start)
			return {"status": "ok", "publicKey": public_key}
		except Exception as e:
			print(e)
			return {"status": "error", "error": str(e)}
	
	abort(400)

@api.route("socialnetwork/sendmessage", methods=["POST"])    
def send_message(): 
    if request.content_type.lower() != "application/json":
        abort(415)

    data = request.get_json()
    
    if "sender" in data and "link" in data and "capsule" in data:
        try:
            print("Ajout du message")
            start = time.perf_counter()
            conn = sqlite3.connect('social_network.db')
            c = conn.cursor()

            global message_counter
            message_counter += 1
            database.add_message(c, message_counter, data["sender"], data["link"], True, data["capsule"])
            database.show_table(c, "message")
            conn.commit()
            conn.close()
            end = time.perf_counter()
            time_stats_endpoints["send_message"].append(end - start)
            return {"status": "ok", "messageNumber": message_counter}
                
        except Exception as e:
            print(e)
            return {"status": "error", "error": str(e)}

    abort(400)

@api.route("socialnetwork/getcontent", methods=["POST"])
def get_content(): 
    if request.content_type.lower() != "application/json":
        abort(415)

    data = request.get_json()

    if "username" in data:
        try:
            start = time.perf_counter()
            conn = sqlite3.connect('social_network.db')
            c = conn.cursor()
            contents = database.get_content(c, data["username"])
            print(contents)
            conn.close()
            end = time.perf_counter()
            time_stats_endpoints["getpublickey"].append(end - start)
            return {"status": "ok", "contents": contents}
        except Exception as e:
            print(e)
            return {"status": "error", "error": str(e)}

    abort(400)

@api.route("socialnetwork/checkuserexistence", methods=["POST"])
def checkuserexistence(): 
    if request.content_type.lower() != "application/json":
        abort(415)

    data = request.get_json()

    if "usernames" in data:
        try:
            # start = time.perf_counter()
            conn = sqlite3.connect('social_network.db')
            c = conn.cursor()
            for username in data["usernames"]:
                user = database.show_element(c, "users", "FirstName", username)
                if(user == None):
                    print("L\'utilisateur n\'existe pas")
                    conn.close()
                    return {"status": "error", "error": "Un des utilisateurs n\'existe pas"}
                conn.close()
            # end = time.perf_counter()
            # time_stats_endpoints["getallkeys"].append(end - start)
            return {"status": "ok"}
        except Exception as e:
            print(e)
            return {"status": "error", "error": str(e)}
    
    abort(400)

# Key generator endpoints (réalisés par le générateur de clé)
@api.route("keygenerator/getallkeys", methods=["POST"])
def getallkeys(): 
	if request.content_type.lower() != "application/json":
		abort(415)

	data = request.get_json()

	if "username" in data:
		try:
			start = time.perf_counter()
			conn = sqlite3.connect('social_network.db')
			c = conn.cursor()
			user = database.show_element(c, "users", "FirstName", data["username"])
			if(user == None):
				print("L\'utilisateur n\'existe pas")
				conn.close()
				return {"status": "error", "error": "L\'utilisateur n\'existe pas"}
			private_key = user[2]
			public_key = user[1]
			signing_key = user[4]
			verifying_key = user[3]
			conn.close()
			end = time.perf_counter()
			time_stats_endpoints["getallkeys"].append(end - start)
			return {"status": "ok", "privateKey": private_key, "publicKey": public_key, "signingKey": signing_key, "verifyingKey": verifying_key}
		except Exception as e:
			print(e)
			return {"status": "error", "error": str(e)}
	
	abort(400)

# Client tasks endpoints (réalisé sur le client)
@api.route("client/encrypt", methods=["POST"])
def encrypt():
    if request.content_type.lower() != "application/json":
        abort(415)

    data = request.get_json()

    if "publicKey" in data and "plaintext" in data:
        try:
            start = time.perf_counter()
            publicKey = keys.UmbralPublicKey.from_hex(data["publicKey"])
            plaintext = data["plaintext"].encode("utf-8")
            ciphertext, capsule = pre.encrypt(publicKey, plaintext)
            end = time.perf_counter()

            time_stats_endpoints["encrypt"].append(end - start)

            return {"status": "ok", "ciphertext": ciphertext.hex(), "capsule": capsule.to_bytes().hex()}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    abort(400)

@api.route("client/gen_renc_key", methods=["POST"])
def gen_rencryption_key():
    if request.content_type.lower() != "application/json":
        abort(415)

    data = request.get_json()

    if "delegatorPrivateKey" in data and "delegatorSigningKey" in data and "receiverPublicKey" in data and "receiverUsername" in data and "messageNumber" in data:
        try:
            start = time.perf_counter()
            delegatorPrivKey = keys.UmbralPrivateKey.from_bytes(bytes.fromhex(data["delegatorPrivateKey"]))
            delegatorSignKey = keys.UmbralPrivateKey.from_bytes(bytes.fromhex(data["delegatorSigningKey"]))
            receiverPublicKey = keys.UmbralPublicKey.from_hex(data["receiverPublicKey"])
            signer = signing.Signer(private_key=delegatorSignKey)

            [kfrag] = pre.generate_kfrags(delegating_privkey=delegatorPrivKey,
                                         signer=signer,
                                         receiving_pubkey=receiverPublicKey,
                                         threshold=1,
                                         N=1)
            conn = sqlite3.connect('social_network.db')
            c = conn.cursor()
            database.add_reenc_key(c, data["messageNumber"], data["receiverUsername"], kfrag.to_bytes().hex())
            conn.commit()
            end = time.perf_counter()

            time_stats_endpoints["gen_renc_key"].append(end - start)
            database.show_table(c, "proxy")
            conn.close()
            return {"status": "ok"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    abort(400)

@api.route("/decrypt", methods=["POST"])
def decrypt():
    if request.content_type.lower() != "application/json":
        abort(415)

    data = request.get_json()

    if "receiverPrivateKey" in data and "ciphertext" in data and "capsule" in data:
        try:
            start = time.perf_counter()
            privateKey = keys.UmbralPrivateKey.from_bytes(bytes.fromhex(data["receiverPrivateKey"]))
            ciphertext = bytes.fromhex(data["ciphertext"])
            capsule = pre.Capsule.from_bytes(bytes.fromhex(data["capsule"]), config.default_params())
            plaintext = pre.decrypt(ciphertext=ciphertext,
                                capsule=capsule,
                                decrypting_key=privateKey)
            end = time.perf_counter()

            time_stats_endpoints["decrypt"].append(end - start)

            return {"status": "ok", "plaintext": plaintext.decode("utf-8")}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    abort(400)

@api.route("/decrypt_reenc", methods=["POST"])
def decrypt_reenc():
    if request.content_type.lower() != "application/json":
        abort(415)

    data = request.get_json()

    if ("receiverPrivateKey" in data and "ciphertext" in data and "capsule" in data
        and "cfrag" in data and "receiverPublicKey" in data
        and "delegatorPublicKey" in data and "delegatorVerifyingKey" in data):

        try:
            start = time.perf_counter()
            privateKey = keys.UmbralPrivateKey.from_bytes(bytes.fromhex(data["receiverPrivateKey"]))
            ciphertext = bytes.fromhex(data["ciphertext"])
            capsule = pre.Capsule.from_bytes(bytes.fromhex(data["capsule"]), config.default_params())

            cfrag = cfrags.CapsuleFrag.from_bytes(bytes.fromhex(data["cfrag"]))
            delegatorPubKey = keys.UmbralPublicKey.from_hex(data["delegatorPublicKey"])
            delegatorVerifKey = keys.UmbralPublicKey.from_hex(data["delegatorVerifyingKey"])
            receiverPublicKey = keys.UmbralPublicKey.from_hex(data["receiverPublicKey"])
            capsule.set_correctness_keys(delegating=delegatorPubKey,
                                             receiving=receiverPublicKey,
                                             verifying=delegatorVerifKey)
            capsule.attach_cfrag(cfrag)
            plaintext = pre.decrypt(ciphertext=ciphertext,
                                capsule=capsule,
                                decrypting_key=privateKey)
            end = time.perf_counter()

            time_stats_endpoints["decrypt_reenc"].append(end - start)

            return {"status": "ok", "plaintext": plaintext.decode("utf-8")}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    abort(400)

# Proxy re-encryption endpoints (réalisés par le proxy)
@api.route("/re_encrypt", methods=["POST"])
def re_encrypt():
    if request.content_type.lower() != "application/json":
        abort(415)

    data = request.get_json()

    if ("delegatorPublicKey" in data and "delegatorVerifyingKey" in data
        and "receiverPublicKey" in data and "capsule" in data
        and "reencKey" in data):
        try:
            start = time.perf_counter()
            delegatorPubKey = keys.UmbralPublicKey.from_hex(data["delegatorPublicKey"])
            delegatorVerifKey = keys.UmbralPublicKey.from_hex(data["delegatorVerifyingKey"])
            receiverPublicKey = keys.UmbralPublicKey.from_hex(data["receiverPublicKey"])
            reencKey = kfrags.KFrag.from_bytes(bytes.fromhex(data["reencKey"]))
            capsule = pre.Capsule.from_bytes(bytes.fromhex(data["capsule"]), config.default_params())

            capsule.set_correctness_keys(delegating=delegatorPubKey,
                                             receiving=receiverPublicKey,
                                             verifying=delegatorVerifKey)

            cfrag = pre.reencrypt(kfrag=reencKey, capsule=capsule)
            end = time.perf_counter()

            time_stats_endpoints["re_encrypt"].append(end - start)

            return {"status": "ok", "cfrag": cfrag.to_bytes().hex()}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    abort(400)



# Stats endpoints

@api.route("/time_raw/<endpoint>", methods=["GET"])
def time_raw(endpoint):
    if endpoint in time_stats_endpoints:
        return {"status": "ok", "times": time_stats_endpoints[endpoint]}
    else:
        return {"status": "error", "error": "Wrong endpoint '{}', shoud be one of {}".format(endpoint, list(time_stats_endpoints))}

@api.route("/time_stats/<endpoint>", methods=["GET"])
def time_stats(endpoint):
    if endpoint in time_stats_endpoints:
        times = time_stats_endpoints[endpoint]
        return {
            "status": "ok",
            "mean": statistics.mean(times),
            "stdev": statistics.stdev(times),
            "min": min(times),
            "max": max(times),
            "median": statistics.median(times),
            "quantiles": statistics.quantiles(times)
        }
    else:
        return {"status": "error", "error": "Wrong endpoint '{}', shoud be one of {}".format(endpoint, list(time_stats_endpoints))}



