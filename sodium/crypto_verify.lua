local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
size_t crypto_verify_16_bytes(void);
int crypto_verify_16(const unsigned char *x, const unsigned char *y);
size_t crypto_verify_32_bytes(void);
int crypto_verify_32(const unsigned char *x, const unsigned char *y);
]]

local _M = { }

_M["16"] = lib.crypto_verify_16
_M["32"] = lib.crypto_verify_32

return _M
