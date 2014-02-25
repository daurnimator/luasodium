local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
size_t crypto_hash_sha512_bytes(void);
const char * crypto_hash_sha512_primitive(void);
int crypto_hash_sha512(unsigned char *,const unsigned char *,unsigned long long);
int crypto_hash(unsigned char *out, const unsigned char *in,
                unsigned long long inlen);
size_t crypto_hash_sha256_bytes(void);
const char * crypto_hash_sha256_primitive(void);
int crypto_hash_sha256(unsigned char *,const unsigned char *,unsigned long long);
]]

local _M = { }

_M.hash = lib.crypto_hash

return setmetatable ( _M , { __call = function(_M, ...) return _M.hash(...) end } )

