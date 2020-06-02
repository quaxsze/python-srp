from utils import get_randombytes, obj_to_bytes, obj_to_int, compute_hash, compute_padding, compute_M, DEFAULT_BYTEORDER
from rfc5054_values import gN_1024

DEFAULT_GROUP_PARAMETERS = gN_1024

DEFAULT_SALT_SIZE = 32

DEFAULT_SECRETSIZE = 256


class Client:
	"SRP client-side class."
	def __init__(self, gn=DEFAULT_GROUP_PARAMETERS):
		self.username = ''
		self.password = ''
		self.g = gn['g']
		self.N = gn['N']
		self.a = 0
		self.A = 0
		self.M = b''
		self.hashed_AMK = b''
		self.session_key = b''
		self.auth = False
	
	def _compute_x(self, salt, username, password):
		'''
		Computes x according to the RFC formula:
		x = SHA1(s | SHA1(I | ":" | P))
		'''
		separator = b':'
		h_up = compute_hash(username, separator, password)
		x = compute_hash(salt, h_up)
		return int.from_bytes(x, byteorder=DEFAULT_BYTEORDER)

	def compute_verifier(self, username, password, gn=DEFAULT_GROUP_PARAMETERS, byte_size=DEFAULT_SALT_SIZE):
		'''
		Creates the SRP verifier according to the RFC formula:
		x = SHA1(s | SHA1(I | ":" | P))
        v = g^x % N
		'''
		self.username = username
		self.password = password
		salt = get_randombytes(byte_size)
		x = self._compute_x(salt, username, password)
		verifier = pow(self.g, x, self.N)
		return salt, verifier

	def compute_client_values(self, byte_size=DEFAULT_SECRETSIZE):
		'''
		Computes client's private and public values:
		a = random()
		A = g^a % N  
		'''
		self.a = obj_to_int(get_randombytes(byte_size))
		self.A = pow(self.g, self.a, self.N)
		return self.A
	
	def compute_premaster_secret(self, salt, server_B):
		'''
		Calculates client premaster secret
        u = SHA1(PAD(A) | PAD(B))
        k = SHA1(N | PAD(g))
        x = SHA1(s | SHA1(I | ":" | P))
        <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N
		'''
		server_B = obj_to_int(server_B)
		l = self.N.bit_length()

		padded_client_A = compute_padding(self.A, l)
		padded_server_B = compute_padding(server_B, l)

		u = obj_to_int(compute_hash(padded_client_A, padded_server_B))
		x = self._compute_x(salt, self.username, self.password)

		padded_g = compute_padding(self.g, l)
		k = obj_to_int(compute_hash(self.N, padded_g))

		t1 = server_B - k * pow(self.g, x, self.N)
		t2 = self.a + u * x
		self.premaster_secret = pow(t1, t2, self.N)
		return self.premaster_secret
	
	def compute_session_key(self, salt, server_B):
		'''
		Calculates client's session key and evidence message.
		M = H(H(N) XOR H(g) | H(U) | s | A | B | K)
		H(A | M | K)
		'''
		self.session_key = compute_hash(self.premaster_secret)
		self.M = compute_M(self.g, self.N, self.username, salt, self.A, server_B, self.session_key)
		self.hashed_AMK = compute_hash(self.A, self.M, self.session_key)
		return self.M
	
	def verify_session(self, server_hashed_AMK):
		if self.hashed_AMK == server_hashed_AMK:
			self.auth = True
		return self.hashed_AMK

	@property
	def authenticated(self):
		return self.auth


class Server:
	"SRP server-side class."
	def __init__(self, gn=DEFAULT_GROUP_PARAMETERS):
		self.g = gn['g']
		self.N = gn['N']
		self.b = 0
		self.B = 0
		self.M = b''
		self.hashed_AMK = b''
		self.session_key = b''
		self.auth = False

	def compute_server_values(self, username, verifier, byte_size=DEFAULT_SECRETSIZE):
		'''
		Calculates server values
		b = random()
		k = SHA1(N | PAD(g))
		B = k*v + g^b % N
		'''
		l = self.N.bit_length()

		self.b = obj_to_int(get_randombytes(byte_size))
		k = obj_to_int(compute_hash(self.N, compute_padding(self.g, l)))

		self.B = (k * verifier + pow(self.g, self.b, self.N)) % self.N
		return self.B

	def compute_premaster_secret(self, username, salt, verifier, client_A, scs=DEFAULT_SECRETSIZE):
		'''
		Calculates server premaster secret
		u = SHA1(PAD(A) | PAD(B))
		<premaster secret> = (A * v^u) ^ b % N
		'''
		l = self.N.bit_length()
		padded_client_A = compute_padding(client_A, l)
		padded_server_B = compute_padding(self.B, l)
		u = obj_to_int(compute_hash(padded_client_A, padded_server_B))

		self.premaster_secret = pow(client_A * pow(verifier, u, self.N), self.b, self.N)
		return self.premaster_secret

	def compute_session_key(self, username, salt, client_A):
		'''
		Calculates server's session key and evidence message.
		M = H(H(N) XOR H(g) | H(U) | s | A | B | K)
		H(A | M | K)
		'''
		self.session_key = compute_hash(self.premaster_secret)
		self.M = compute_M(self.g, self.N, username, salt, client_A, self.B, self.session_key)
		self.hashed_AMK = compute_hash(client_A, self.M, self.session_key)
		return self.M
	
	def verify_session(self, client_M):
		if self.M == client_M:
			self.auth = True
		return self.hashed_AMK

	@property
	def authenticated(self):
		return self.auth
