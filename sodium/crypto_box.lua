local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
size_t crypto_box_curve25519xsalsa20poly1305_publickeybytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_secretkeybytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_beforenmbytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_noncebytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_zerobytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_boxzerobytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_macbytes(void);
const char * crypto_box_curve25519xsalsa20poly1305_primitive(void);
int crypto_box_curve25519xsalsa20poly1305(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *,const unsigned char *);
int crypto_box_curve25519xsalsa20poly1305_open(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *,const unsigned char *);
int crypto_box_curve25519xsalsa20poly1305_keypair(unsigned char *,unsigned char *);
int crypto_box_curve25519xsalsa20poly1305_beforenm(unsigned char *,const unsigned char *,const unsigned char *);
int crypto_box_curve25519xsalsa20poly1305_afternm(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
int crypto_box_curve25519xsalsa20poly1305_open_afternm(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
size_t crypto_box_publickeybytes(void);
size_t crypto_box_secretkeybytes(void);
size_t crypto_box_beforenmbytes(void);
size_t crypto_box_noncebytes(void);
size_t crypto_box_zerobytes(void);
size_t crypto_box_boxzerobytes(void);
size_t crypto_box_macbytes(void);
const char *crypto_box_primitive(void);
int crypto_box_keypair(unsigned char *pk, unsigned char *sk);
int crypto_box_beforenm(unsigned char *k, const unsigned char *pk,
                        const unsigned char *sk);
int crypto_box_afternm(unsigned char *c, const unsigned char *m,
                       unsigned long long mlen, const unsigned char *n,
                       const unsigned char *k);
int crypto_box_open_afternm(unsigned char *m, const unsigned char *c,
                            unsigned long long clen, const unsigned char *n,
                            const unsigned char *k);
int crypto_box(unsigned char *c, const unsigned char *m,
               unsigned long long mlen, const unsigned char *n,
               const unsigned char *pk, const unsigned char *sk);
int crypto_box_open(unsigned char *m, const unsigned char *c,
                    unsigned long long clen, const unsigned char *n,
                    const unsigned char *pk, const unsigned char *sk);
]]

local _M = { }

_M.publickeybytes = function() return tonumber(lib.crypto_box_publickeybytes()) end
_M.secretkeybytes = function() return tonumber(lib.crypto_box_secretkeybytes()) end
_M.beforenmbytes = function() return tonumber(lib.crypto_box_beforenmbytes()) end
_M.noncebytes = function() return tonumber(lib.crypto_box_noncebytes()) end
_M.zerobytes = function() return tonumber(lib.crypto_box_zerobytes()) end
_M.boxzerobytes = function() return tonumber(lib.crypto_box_boxzerobytes()) end
_M.macbytes = function() return tonumber(lib.crypto_box_macbytes()) end
_M.primitive = function() return ffi.string(lib.crypto_box_primitive()) end
_M.keypair = function(pk, sk)
	pk = pk or ffi.new("unsigned char[?]", _M.publickeybytes())
	sk = sk or ffi.new("unsigned char[?]", _M.secretkeybytes())
	assert(lib.crypto_box_keypair(pk, sk) == 0, "crypto_box_keypair returned non-zero")
	return pk, sk
end
_M.beforenm = function(k,pk,sk)
	k = k or ffi.new("unsigned char[?]", _M.beforenmbytes())
	assert(lib.crypto_box_beforenm(k,pk,sk) == 0, "crypto_beforenm returned non-zero")
	return k
end
_M.afternm = function(c,m,mlen,n,k)
	mlen = mlen or #m
	c = c or ffi.new("unsigned char[?]", mlen)
	assert(lib.crypto_box_afternm(c,m,mlen,n,k) == 0, "crypto_afternm returned non-zero")
	return c
end
_M.open_afternm = function(m,c,clen,n,k)
	clen = clen or #c
	m = m or ffi.new("unsigned char[?]", clen)
	assert(lib.crypto_box_open_afternm(m,c,clen,n,k) == 0, "crypto_open_afternm returned non-zero")
	return m
end
_M.box = function(c,m,mlen,n,pk,sk)
	mlen = mlen or #m
	c = c or ffi.new("unsigned char[?]", mlen)
	assert(lib.crypto_box(c,m,mlen,n,pk,sk) == 0, "crypto_box returned non-zero")
	return c
end
_M.open = function(m,c,clen,n,pk,sk)
	clen = clen or #c
	m = m or ffi.new("unsigned char[?]", clen)
	assert(lib.crypto_box_open(m,c,clen,n,pk,sk) == 0, "crypto_box_open returned non-zero")
	return m
end

return setmetatable ( _M , { __call = function(_M, ...) return _M.box(...) end } )
