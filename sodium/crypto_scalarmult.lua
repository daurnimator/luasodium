local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
size_t crypto_scalarmult_curve25519_bytes(void);
size_t crypto_scalarmult_curve25519_scalarbytes(void);
int crypto_scalarmult_curve25519(unsigned char *,const unsigned char *,const unsigned char *);
int crypto_scalarmult_curve25519_base(unsigned char *,const unsigned char *);
size_t crypto_scalarmult_bytes(void);
size_t crypto_scalarmult_scalarbytes(void);
const char *crypto_scalarmult_primitive(void);
int crypto_scalarmult_base(unsigned char *q, const unsigned char *n);
int crypto_scalarmult(unsigned char *q, const unsigned char *n,
                      const unsigned char *p);
]]

local _M = { }

_M.bytes = function() return tonumber(lib.crypto_scalarmult_bytes()) end
_M.scalarbytes = function() return tonumber(lib.crypto_scalarmult_scalarbytes()) end
_M.primitive = function() return ffi.string(lib.crypto_scalarmult_primitive()) end
_M.base = function(q, n)
	assert(lib.crypto_scalarmult_base(q, n) == 0, "crypto_scalarmult_base returned non-zero")
	return q
end
_M.scalarmult = function(q, n, p)
	q = q or ffi.new("unsigned char[?]", _M.bytes())
	assert(lib.crypto_scalarmult(q, n, p) == 0, "crypto_scalarmult returned non-zero")
	return q
end

return setmetatable ( _M , { __call = function(_M, ...) return _M.scalarmult(...) end } )
