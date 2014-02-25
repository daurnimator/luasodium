local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
size_t crypto_auth_hmacsha512256_bytes(void);
size_t crypto_auth_hmacsha512256_keybytes(void);
const char * crypto_auth_hmacsha512256_primitive(void);
int crypto_auth_hmacsha512256(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
int crypto_auth_hmacsha512256_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
size_t crypto_auth_bytes(void);
size_t crypto_auth_keybytes(void);
const char *crypto_auth_primitive(void);
int crypto_auth(unsigned char *out, const unsigned char *in,
                unsigned long long inlen, const unsigned char *k);
int crypto_auth_verify(const unsigned char *h, const unsigned char *in,
                       unsigned long long inlen, const unsigned char *k);
size_t crypto_auth_hmacsha256_bytes(void);
size_t crypto_auth_hmacsha256_keybytes(void);
const char * crypto_auth_hmacsha256_primitive(void);
int crypto_auth_hmacsha256(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
int crypto_auth_hmacsha256_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
]]

local _M = { }

_M.bytes = function() return tonumber(lib.crypto_auth_bytes()) end
_M.keybytes = function() return tonumber(lib.crypto_auth_keybytes()) end
_M.primitive = function() return ffi.string(lib.crypto_auth_primitive()) end
_M.auth = function(out, inbuff, inlen, key) 
	local outlen = _M.bytes()
	out = out or ffi.new("unsigned char[?]", outlen)
	assert(lib.crypto_auth(out, inbuff, inlen or #inbuff, key) == 0, "crypto_auth returned non-zero")
	return out, outlen
end
_M.verify = function(h, inbuff, inlen, key)
	return lib.crypto_auth_verify(h, inbuff, inlen or #inbuff, key) == 0
end

return setmetatable ( _M , { __call = function(_M, ...) return _M.auth(...) end } )
