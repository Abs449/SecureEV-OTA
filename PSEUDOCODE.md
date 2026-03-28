# SecureEV-OTA Core Implementation Pseudocode

This file contains the core pseudocode for each major module in the SecureEV-OTA project.

## 1) `src/crypto/ecc_core.py`

```pseudocode
class ECCCore:
    DEFAULT_CURVE = SECP256R1

    function __init__(curve=DEFAULT_CURVE):
        self.curve = curve
        self.curve_obj = get_curve_object(curve)

    static function get_curve_info(curve):
        return CURVE_SECURITY_LEVELS[curve]

    static function _get_curve_object(curve):
        if curve == ED25519: raise NotImplemented
        return mapping[curve]

    static function _generate_key_id(public_key):
        bytes = public_key.compress()
        return sha256(bytes)[:16]

    function generate_keypair():
        priv = ec.generate_private_key(self.curve_obj)
        pub = priv.public_key()
        key_id = _generate_key_id(pub)
        return ECCKeyPair(priv, pub, self.curve, key_id)

    function sign(private_key, data, key_id=None):
        sig = private_key.sign(data, ECDSA(SHA256))
        if key_id is None:
            key_id = _generate_key_id(private_key.public_key())
        return ECDSASignature(sig, "ecdsa-...-sha256", key_id)

    function verify(public_key, signature, data):
        try:
            public_key.verify(signature, data, ECDSA(SHA256))
            return true
        except InvalidSignature:
            return false
        except Exception:
            raise ECCVerificationError

class ECDHKeyExchange:
    function __init__(curve=SECP256R1):
        self.ecc_core = ECCCore(curve)

    function generate_ephemeral_keypair():
        return self.ecc_core.generate_keypair()

    function derive_shared_secret(priv, peer_pub):
        return priv.exchange(ECDH, peer_pub)

    function derive_session_key(priv, peer_pub, ...):
        ss = derive_shared_secret(priv, peer_pub)
        return HKDF(SHA256, length=32, info="secureev-ota-session").derive(ss)

    function generate_nonce(length=12):
        return secrets.token_bytes(length)
```

## 2) `src/security/e2e_encryption.py`

```pseudocode
class E2EEncryption:
    function __init__(mode=AES_256_GCM):
        session_keys = {}
        nonce_history = {}
        encryption_counter = {}

    function generate_ephemeral_keypair():
        priv = ec.generate_private_key(SECP256R1)
        return (priv, priv.public_key())

    function derive_session_key(our_priv, peer_pub, context):
        shared = ECDH(our_priv, peer_pub)
        derived = HKDF(SHA256).derive(shared)
        key_id = sha256(derived)[:16]
        session = SessionKey(derived, key_id, now(), now()+duration)
        store session
        return session

    function encrypt(plaintext, our_priv, peer_pub, aad):
        session = derive_session_key(our_priv, peer_pub)
        nonce = _generate_unique_nonce(session.key_id)
        ciphertext_tag = AESGCM(session.key).encrypt(nonce, plaintext, aad)
        ciphertext = ciphertext_tag[:-taglen]
        tag = ciphertext_tag[-taglen:]
        return EncryptedPackage(ciphertext, nonce, tag, session.key_id, api_key, sender_public_key)

    function decrypt(package, our_priv, aad):
        peer_pub = parse(public_key=package.sender_public_key)
        session = derive_session_key(our_priv, peer_pub)
        validate key_id, expiry, nonce reuse
        plaintext = AESGCM(session.key).decrypt(package.nonce, package.ciphertext+package.tag, aad)
        mark nonce used
        return plaintext
```

## 3) `src/security/dos_protection.py`

```pseudocode
class TokenBucket:
    function __init__(capacity, fill_rate):
        tokens = capacity
        last_update = now()

    function _refill_locked():
        elapsed = now() - last_update
        tokens = min(capacity, tokens + elapsed * fill_rate)
        last_update = now()

    function consume(amount=1):
        with lock:
            _refill_locked()
            if tokens >= amount:
                tokens -= amount
                return true
            return false

    function time_until_next_token():
        with lock:
            _refill_locked()
            if tokens >= 1: return 0
            return (1 - tokens) / fill_rate

class DoSProtection:
    function __init__(...):
        global_limiter = TokenBucket(...)
        vehicle_limiters = {}
        violation_counts = {}
        block_expiry = {}
        blacklist = set()

    function is_request_allowed(vehicle_id):
        if vehicle_id in blacklist: return false
        if vehicle_id in block_expiry and now() < block_expiry[vehicle_id]: return false
        if not global_limiter.consume(): return false

        bucket = vehicle_limiters.get(vehicle_id)
        if bucket is null:
            bucket = TokenBucket(per_vehicle_capacity, per_vehicle_rate)
            vehicle_limiters[vehicle_id] = bucket

        if not bucket.consume():
            violation_counts[vehicle_id] += 1
            if violation_counts[vehicle_id] > 1:
                backoff = min(base_backoff * 2**(violation_counts-1), max_backoff)
                block_expiry[vehicle_id] = now() + backoff
            return false

        last_seen[vehicle_id] = now()
        return true

    function get_retry_after(vehicle_id):
        if vehicle_id in block_expiry: return max(0, block_expiry[vehicle_id] - now())
        if vehicle_id in blacklist: return 3600
        global_wait = global_limiter.time_until_next_token()
        vehicle_wait = vehicle_limiters.get(vehicle_id).time_until_next_token() if exists else 0
        return max(global_wait, vehicle_wait)
```

## 4) `src/uptane/metadata.py`

```pseudocode
class Metadata:
    function signed_part():
        return {"_type": role, "expires": expires, "version": version}

    function sign(keypair, ecc):
        payload = json.dumps(signed_part(), sort_keys=True).encode()
        signature = ecc.sign(keypair.private_key, payload, keypair.key_id)
        signatures.append(signature.to_dict())

    function to_dict():
        return {"signed": signed_part(), "signatures": signatures}

class RootMetadata(Metadata):
    function signed_part():
        base = super().signed_part()
        base["keys"] = keys
        base["roles"] = {role: {"threshold": ..., "keyids": ...}}
        return base

class TargetsMetadata(Metadata):
    function add_target(filename, file_hash, length, hardware_id):
        targets[filename] = {"hashes":{"sha256":file_hash}, "length":length, "custom":{"hardwareId":hardware_id}}

class SnapshotMetadata(Metadata):
    function add_metadata_version(filename, version):
        meta[filename] = {"version": version}

class TimestampMetadata(Metadata):
    function signed_part():
        base = super().signed_part()
        base["meta"] = {"snapshot.json": {"hashes":{"sha256":snapshot_hash}, "length":snapshot_size}}
        return base
```

## 5) `src/server/director.py`

```pseudocode
POST /register:
    db.vehicles[vehicle_id] = {"ecu_id":..., "public_key":..., "hardware_id":..., "last_seen": now()}
    dos.reset_vehicle(vehicle_id)
    return {"status":"success"}

GET /manifest/{vehicle_id}:
    if not dos.is_request_allowed(vehicle_id): return 429
    if vehicle not registered:
        dos.report_invalid_request(vehicle_id)
        return 404
    fw = db.firmware_inventory[vehicle.hardware_id]
    if fw missing: return {"status":"up_to_date"}

    manifest = TargetsMetadata(expires=..., version=1)
    manifest.add_target(fw.filename, fw.hash, fw.size, vehicle.hardware_id)
    manifest.sign(DIRECTOR_KEY, ecc)
    return manifest.to_dict()

POST /check_updates:
    return get_manifest(vehicle_id)
```

## 6) `src/server/image_repo.py`

```pseudocode
GET /metadata/targets.json:
    manifest = TargetsMetadata(...)
    for each file in images:
        hash=sha256(file_bytes)
        manifest.add_target(filename, hash, len(file_bytes), "EV-MODEL-S")
    manifest.sign(IMAGE_REPO_KEY, ecc)
    return manifest.to_dict()

GET /targets/{filename}?vehicle_pub_key=...:
    if not dos.is_request_allowed(vehicle_pub_key): return 429
    firmware = read_file(filename)
    vehicle_pub = public_key_from_bytes(hex)
    server_priv, server_pub = e2e.generate_ephemeral_keypair()
    package = e2e.encrypt(firmware, server_priv, vehicle_pub, aad=json(...))
    package.metadata = metadata
    return package.to_dict()
```

## 7) `src/client/ecu.py`

```pseudocode
class PrimaryECU:
    function __init__(vehicle_id, director_url, image_repo_url, director_public_key_hex):
        ecc = ECCCore()
        e2e = E2EEncryption()
        metadata_manager = MetadataManager(ecc)
        keypair = ecc.generate_keypair()
        trust_pub_key = parse(director_public_key_hex)
        metadata_manager.trusted_keys[trust_key_id] = trust_pub_key

    async function register():
        payload = {...}
        POST director/register

    async function poll_for_updates():
        response = POST director/check_updates?vehicle_id
        targets = metadata_manager.verify_metadata(response, "targets")
        if targets empty: return
        filename, target_info = first_entry(targets)
        await _download_and_install(filename, target_info)

    async function _download_and_install(filename, target_info):
        response = GET image_repo/targets/filename?vehicle_pub_key=...&vehicle_id=...
        if response contains ciphertext:
            package = EncryptedPackage.from_dict(response)
            plaintext = e2e.decrypt(package, keypair.private_key, aad=json(response.metadata))
        verify sha256(plaintext) == target_info.hashes.sha256
        install firmware
```

## 8) `src/simulation/manager.py`

```pseudocode
class FleetManager:
    function spawn_agents(count):
        for i in range(count):
            agents.append(VehicleAgent(...))

    async function start_simulation():
        for agent in agents:
            tasks.append(asyncio.create_task(agent.run()))

    async function stop_simulation():
        for agent in agents: agent.stop()
        await asyncio.gather(*tasks)

    function get_stats():
        return Counter(statuses)

class VehicleAgent:
    async function run():
        while not stopped:
            if not registered: await ecu.register()
            await ecu.poll_for_updates()
            sleep(rand_interval)
```
