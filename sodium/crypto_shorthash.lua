local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
size_t crypto_shorthash_siphash24_bytes(void);
const char * crypto_shorthash_siphash24_primitive(void);
int crypto_shorthash_siphash24(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
size_t crypto_shorthash_bytes(void);
size_t crypto_shorthash_keybytes(void);
const char *crypto_shorthash_primitive(void);
int crypto_shorthash(unsigned char *out, const unsigned char *in,
                     unsigned long long inlen, const unsigned char *k);
]]

local _M = { }

_M.bytes = function() return tonumber(lib.crypto_shorthash_bytes()) end
_M.keybytes = function() return tonumber(lib.crypto_shorthash_keybytes()) end
_M.primitive = function() return ffi.string(lib.crypto_shorthash_primitive()) end
_M.shorthash = function(out, inbuf, inlen, k)
	out = out or ffi.new("unsigned char[?]", _M.bytes())
	inlen = inlen or #inbuf
	assert(lib.crypto_shorthash(out, inbuf, inlen, k) == 0, "crypto_shorthash returned non-zero")
	return out
end

return setmetatable ( _M , { __call = function(_M, ...) return _M.shorthash(...) end } )

