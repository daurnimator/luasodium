local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
size_t crypto_secretbox_xsalsa20poly1305_keybytes(void);
size_t crypto_secretbox_xsalsa20poly1305_noncebytes(void);
size_t crypto_secretbox_xsalsa20poly1305_zerobytes(void);
size_t crypto_secretbox_xsalsa20poly1305_boxzerobytes(void);
const char * crypto_secretbox_xsalsa20poly1305_primitive(void);
int crypto_secretbox_xsalsa20poly1305(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
int crypto_secretbox_xsalsa20poly1305_open(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
size_t crypto_secretbox_keybytes(void);
size_t crypto_secretbox_noncebytes(void);
size_t crypto_secretbox_zerobytes(void);
size_t crypto_secretbox_boxzerobytes(void);
const char *crypto_secretbox_primitive(void);
int crypto_secretbox(unsigned char *c, const unsigned char *m,
                     unsigned long long mlen, const unsigned char *n,
                     const unsigned char *k);
int crypto_secretbox_open(unsigned char *m, const unsigned char *c,
                          unsigned long long clen, const unsigned char *n,
                          const unsigned char *k);
]]

local _M = { }

_M.keybytes = function() return tonumber(lib.crypto_secretbox_keybytes()) end
_M.noncebytes = function() return tonumber(lib.crypto_secretbox_noncebytes()) end
_M.zerobytes = function() return tonumber(lib.crypto_secretbox_zerobytes()) end
_M.boxzerobytes = function() return tonumber(lib.crypto_secretbox_boxzerobytes()) end
_M.primitive = function() return ffi.string(lib.crypto_secretbox_primitive()) end
_M.secretbox = function(c, m, mlen, n, k)
	mlen = mlen or #m
	c = c or ffi.new("unsigned char[?]", mlen)
	assert(lib.crypto_secretbox(c, m, mlen, n, k) == 0, "crypto_secretbox returned non-zero")
	return c, mlen
end
_M.open = function(m, c, clen, n, k)
	clen = clen or #c
	m = m or ffi.new("unsigned char[?]", clen)
	assert(lib.crypto_secretbox_open(m, c, clen, n, k) == 0, "crypto_secretbox_open returned non-zero")
	return m, clen
end

return setmetatable ( _M , { __call = function(_M, ...) return _M.secretbox(...) end } )
