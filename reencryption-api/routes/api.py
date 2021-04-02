import time
import random
import statistics
from flask import Flask, Blueprint, request, abort, json
from umbral import pre, keys, config, signing, kfrags, cfrags

api = Blueprint('api', __name__)

# Setup PRE
config.set_default_curve()

# Statistics of durations (in second) for each PRE endpoint
time_stats_endpoints = {
    "genkey": [],
    "encrypt": [],
    "gen_renc_key": [],
    "re_encrypt": [],
    "decrypt": [],
    "decrypt_reenc": []
}

# Proxy Rencryption endpoints
@api.route("/genkey", methods=["GET"])
def genkey():
    start = time.perf_counter()
    private_key = keys.UmbralPrivateKey.gen_key()
    public_key = private_key.get_pubkey()
    end = time.perf_counter()

    time_stats_endpoints["genkey"].append(end - start)

    return {"status": "ok", "privateKey": private_key.to_bytes().hex(), "publicKey": public_key.to_bytes().hex()}

@api.route("/encrypt", methods=["POST"])
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

@api.route("/gen_renc_key", methods=["POST"])
def gen_rencryption_key():
    if request.content_type.lower() != "application/json":
        abort(415)

    data = request.get_json()

    if "delegatorPrivateKey" in data and "delegatorSigningKey" in data and "receiverPublicKey" in data:
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
            end = time.perf_counter()

            time_stats_endpoints["gen_renc_key"].append(end - start)

            return {"status": "ok", "reencKey": kfrag.to_bytes().hex()}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    abort(400)

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
