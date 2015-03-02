local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
size_t crypto_sign_ed25519_bytes(void);
size_t crypto_sign_ed25519_seedbytes(void);
size_t crypto_sign_ed25519_publickeybytes(void);
size_t crypto_sign_ed25519_secretkeybytes(void);
const char * crypto_sign_ed25519_primitive(void);
int crypto_sign_ed25519(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
int crypto_sign_ed25519_open(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
int crypto_sign_ed25519_keypair(unsigned char *,unsigned char *);
int crypto_sign_ed25519_seed_keypair(unsigned char *,unsigned char *,const unsigned char *);
size_t crypto_sign_bytes(void);
size_t crypto_sign_seedbytes(void);
size_t crypto_sign_publickeybytes(void);
size_t crypto_sign_secretkeybytes(void);
const char *crypto_sign_primitive(void);
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed);
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk);
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);
size_t crypto_sign_edwards25519sha512batch_bytes(void);
size_t crypto_sign_edwards25519sha512batch_publickeybytes(void);
size_t crypto_sign_edwards25519sha512batch_secretkeybytes(void);
const char * crypto_sign_edwards25519sha512batch_primitive(void);
int crypto_sign_edwards25519sha512batch(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
int crypto_sign_edwards25519sha512batch_open(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
int crypto_sign_edwards25519sha512batch_keypair(unsigned char *,unsigned char *);
]]

local _M = { }

_M.bytes = function() return tonumber(lib.crypto_sign_bytes()) end
_M.seedbytes = function() return tonumber(lib.crypto_sign_seedbytes()) end
_M.publickeybytes = function() return tonumber(lib.crypto_sign_publickeybytes()) end
_M.secretkeybytes = function() return tonumber(lib.crypto_sign_secretkeybytes()) end
_M.primitive = function() return ffi.string(lib.crypto_sign_primitive()) end
_M.seed_keypair = lib.crypto_sign_seed_keypair
_M.keypair = function(pk, sk)
	pk = pk or ffi.new("unsigned char[?]", _M.publickeybytes())
	sk = sk or ffi.new("unsigned char[?]", _M.secretkeybytes())
	assert(lib.crypto_sign_keypair(pk, sk) == 0, "crypto_sign_keypairfunction returned non-zero")
	return pk, sk
end
_M.sign = function(sm, smlen, m, mlen, sk)
	mlen = mlen or #m
	sm = sm or ffi.new("unsigned char[?]", mlen + _M.bytes())
	smlen = smlen or ffi.new("unsigned long long[1]")
	assert(lib.crypto_sign(sm, smlen, m, mlen, sk) == 0, "crypto_sign returned non-zero")
	return sm, smlen[0]
end
_M.open = function(m, mlen, sm, smlen, pk)
	smlen = smlen or #sm
	m = m or ffi.new("unsigned char[?]", smlen)
	mlen = mlen or ffi.new("unsigned long long[1]")
	assert(lib.crypto_sign_open(m, mlen, sm, smlen, pk) == 0, "crypto_sign_open returned non-zero")
	return m, mlen[0]
end

return setmetatable ( _M , { __call = function(_M, ...) return _M.sign(...) end } )
