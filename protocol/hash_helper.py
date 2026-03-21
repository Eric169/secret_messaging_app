from hashlib import sha256, pbkdf2_hmac
import json
import secrets

def hash_values(*values) -> int:
    h = sha256()

    for v in values:
        h.update(str(v).encode())

    return int.from_bytes(h.digest(), "big")

def hash_payload(payload: dict) -> int:
    data = json.dumps(payload, sort_keys=True).encode()

    digest = sha256(data).digest()

    return int.from_bytes(digest, "big")

def pre_hash_password(password: str, salt: str) -> str:
    h = sha256(f"{password}{salt}".encode())
    return h.hexdigest()

def hash_password(password: str, salt: str = None, iterations: int = 100000) -> str:
    if salt is None:
        salt_bytes = secrets.token_bytes(16)
        salt = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt)
    
    hash_bytes = pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt_bytes,
        iterations
    )
    
    return f"pbkdf2:sha256:{iterations}${salt}${hash_bytes.hex()}"

def verify_password(password: str, hashed_password: str) -> bool:
    try:
        parts = hashed_password.split('$')
        header, salt, original_hash = parts
        
        method, algo, iterations = header.split(':')
        if method != 'pbkdf2' or algo != 'sha256':
            return False
            
        new_hash = hash_password(password, salt, int(iterations))
        return new_hash == hashed_password
    except Exception:
        return False

