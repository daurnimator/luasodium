local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
typedef struct crypto_onetimeauth_poly1305_implementation {
    const char *(*implementation_name)(void);
    int (*onetimeauth)(unsigned char *out,
                               const unsigned char *in,
                               unsigned long long inlen,
                               const unsigned char *k);
    int (*onetimeauth_verify)(const unsigned char *h,
                                      const unsigned char *in,
                                      unsigned long long inlen,
                                      const unsigned char *k);
} crypto_onetimeauth_poly1305_implementation;
size_t crypto_onetimeauth_poly1305_bytes(void);
size_t crypto_onetimeauth_poly1305_keybytes(void);
const char * crypto_onetimeauth_poly1305_primitive(void);
const char *crypto_onetimeauth_poly1305_implementation_name(void);
int crypto_onetimeauth_poly1305_set_implementation(crypto_onetimeauth_poly1305_implementation *impl);
crypto_onetimeauth_poly1305_implementation *
        crypto_onetimeauth_pick_best_implementation(void);
int crypto_onetimeauth_poly1305(unsigned char *out,
                                const unsigned char *in,
                                unsigned long long inlen,
                                const unsigned char *k);
int crypto_onetimeauth_poly1305_verify(const unsigned char *h,
                                       const unsigned char *in,
                                       unsigned long long inlen,
                                       const unsigned char *k);
size_t crypto_onetimeauth_bytes(void);
size_t crypto_onetimeauth_keybytes(void);
const char *crypto_onetimeauth_primitive(void);
int crypto_onetimeauth(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen, const unsigned char *k);
int crypto_onetimeauth_verify(const unsigned char *h, const unsigned char *in,
                              unsigned long long inlen, const unsigned char *k);
]]

local _M = { }

_M.bytes = function() return tonumber(lib.crypto_onetimeauth_bytes()) end
_M.keybytes = function() return tonumber(lib.crypto_onetimeauth_keybytes()) end
_M.primitive = function() return ffi.string(lib.crypto_onetimeauth_primitive()) end
_M.onetimeauth = function(a,m,mlen,k)
	a = a or ffi.new("unsigned char[?]", _M.bytes())
	mlen = mlen or #m
	assert(lib.crypto_onetimeauth(a,m,mlen,k) == 0, "crypto_onetimeauth returned non-zero")
	return a
end
_M.verify = function(a,m,mlen,k)
	mlen = mlen or #m
	return lib.crypto_onetimeauth_verify(a,m,mlen,k) == 0
end

return setmetatable ( _M , { __call = function(_M, ...) return _M.onetimeauth(...) end } )
