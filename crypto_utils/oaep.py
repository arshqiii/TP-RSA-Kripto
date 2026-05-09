import hashlib
import secrets


def _xor_bytes(a: bytes, b: bytes) -> bytes:
	if len(a) != len(b):
		raise ValueError("Panjang byte harus sama untuk XOR.")
	return bytes(x ^ y for x, y in zip(a, b))


def mgf1(seed: bytes, length: int, hash_name: str = "sha256") -> bytes:
	if not isinstance(seed, (bytes, bytearray)):
		raise TypeError("Seed harus bertipe bytes.")
	if length < 0:
		raise ValueError("Length tidak boleh negatif.")

	counter = 0
	output = bytearray()
	hash_func = hashlib.new(hash_name)
	h_len = hash_func.digest_size

	while len(output) < length:
		c = counter.to_bytes(4, byteorder="big")
		digest = hashlib.new(hash_name, seed + c).digest()
		output.extend(digest)
		counter += 1

	return bytes(output[:length])


def oaep_encode(message: bytes, key_size_bytes: int, label: bytes = b"", hash_name: str = "sha256") -> bytes:
	if not isinstance(message, (bytes, bytearray)):
		raise TypeError("Message harus bertipe bytes.")
	if not isinstance(label, (bytes, bytearray)):
		raise TypeError("Label harus bertipe bytes.")
	if key_size_bytes <= 0:
		raise ValueError("Key size harus lebih besar dari 0.")

	hash_func = hashlib.new(hash_name)
	h_len = hash_func.digest_size

	max_message_len = key_size_bytes - (2 * h_len) - 2
	if len(message) > max_message_len:
		raise ValueError("Panjang message terlalu besar untuk OAEP.")

	l_hash = hashlib.new(hash_name, label).digest()
	ps = b"\x00" * (key_size_bytes - len(message) - (2 * h_len) - 2)
	db = l_hash + ps + b"\x01" + bytes(message)

	seed = secrets.token_bytes(h_len)
	db_mask = mgf1(seed, key_size_bytes - h_len - 1, hash_name=hash_name)
	masked_db = _xor_bytes(db, db_mask)
	seed_mask = mgf1(masked_db, h_len, hash_name=hash_name)
	masked_seed = _xor_bytes(seed, seed_mask)

	return b"\x00" + masked_seed + masked_db


def oaep_decode(encoded: bytes, key_size_bytes: int, label: bytes = b"", hash_name: str = "sha256") -> bytes:
	if not isinstance(encoded, (bytes, bytearray)):
		raise TypeError("Encoded message harus bertipe bytes.")
	if not isinstance(label, (bytes, bytearray)):
		raise TypeError("Label harus bertipe bytes.")
	if key_size_bytes <= 0:
		raise ValueError("Key size harus lebih besar dari 0.")
	if len(encoded) != key_size_bytes:
		raise ValueError("Panjang encoded message tidak sesuai dengan key size.")

	hash_func = hashlib.new(hash_name)
	h_len = hash_func.digest_size

	if key_size_bytes < (2 * h_len) + 2:
		raise ValueError("Key size terlalu kecil untuk OAEP.")

	if encoded[0] != 0x00:
		raise ValueError("OAEP decoding error: byte awal tidak valid.")

	masked_seed = encoded[1:1 + h_len]
	masked_db = encoded[1 + h_len:]

	seed_mask = mgf1(masked_db, h_len, hash_name=hash_name)
	seed = _xor_bytes(masked_seed, seed_mask)
	db_mask = mgf1(seed, key_size_bytes - h_len - 1, hash_name=hash_name)
	db = _xor_bytes(masked_db, db_mask)

	l_hash = hashlib.new(hash_name, label).digest()
	if db[:h_len] != l_hash:
		raise ValueError("OAEP decoding error: hash label tidak cocok.")

	rest = db[h_len:]
	try:
		sep_index = rest.index(b"\x01")
	except ValueError as exc:
		raise ValueError("OAEP decoding error: separator 0x01 tidak ditemukan.") from exc

	if any(byte != 0x00 for byte in rest[:sep_index]):
		raise ValueError("OAEP decoding error: padding PS tidak valid.")

	return rest[sep_index + 1:]
