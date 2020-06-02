import os
import hashlib

DEFAULT_HASH_ALGO = hashlib.sha1

DEFAULT_BYTEORDER = 'big'

DEFAULT_ENCODING = 'utf-8'

DEFAULT_RADIX = 16


def get_randombytes(len):
	'''Generates len length secure random bytes.'''
	return os.urandom(len)


def obj_to_bytes(obj):
	'''Converts object to byte array.'''
	if type(obj) == int:
		return obj.to_bytes((obj.bit_length() + 7)//8, byteorder=DEFAULT_BYTEORDER)
	elif type(obj) == str:
		return bytes(obj, DEFAULT_ENCODING)
	else:
		return None


def obj_to_int(obj):
	'''Converts object to integer.'''
	if type(obj) == bytes:
		return int.from_bytes(obj, byteorder=DEFAULT_BYTEORDER)
	elif type(obj) == str:
		return int(obj, DEFAULT_RADIX)
	else:
		return obj


def compute_padding(obj, byte_length):
	r = obj_to_bytes(obj)
	padding = b'\x00'*((byte_length+7)//8 - len(r))
	return padding+r


def compute_hash(*args):
	'''Hashes concatenated argument objects.'''
	algorithm = DEFAULT_HASH_ALGO
	m = algorithm()
	for i in args:
		m.update(i if type(i) == bytes else obj_to_bytes(i))
	return m.digest()


def compute_M(g, N, I, s, A, B, K):
	'''
	Calculates evidence message.
	'''
	hashed_g = compute_hash(g)
	hashed_N = compute_hash(N)
	hashed_I = compute_hash(I)
	hashed_xor = bytes(map(lambda i: i[0]^i[1], zip(hashed_g, hashed_N)))
	return compute_hash(hashed_xor, hashed_I, s, A, B, K)
