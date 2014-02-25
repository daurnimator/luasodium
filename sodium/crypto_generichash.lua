local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
#pragma pack(push, 1)
__attribute__((aligned(64))) typedef struct crypto_generichash_blake2b_state {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[2 * 128U];
    size_t buflen;
    uint8_t last_node;
} crypto_generichash_blake2b_state;
#pragma pack(pop)
size_t crypto_generichash_blake2b_bytes_min(void);
size_t crypto_generichash_blake2b_bytes_max(void);
size_t crypto_generichash_blake2b_keybytes_min(void);
size_t crypto_generichash_blake2b_keybytes_max(void);
size_t crypto_generichash_blake2b_blockbytes(void);
const char * crypto_generichash_blake2b_blockbytes_primitive(void);
int crypto_generichash_blake2b(unsigned char *out, size_t outlen,
                               const unsigned char *in,
                               unsigned long long inlen,
                               const unsigned char *key, size_t keylen);
int crypto_generichash_blake2b_init(crypto_generichash_blake2b_state *state,
                                    const unsigned char *key,
                                    const size_t keylen, const size_t outlen);
int crypto_generichash_blake2b_update(crypto_generichash_blake2b_state *state,
                                      const unsigned char *in,
                                      unsigned long long inlen);
int crypto_generichash_blake2b_final(crypto_generichash_blake2b_state *state,
                                     unsigned char *out,
                                     const size_t outlen);
size_t crypto_generichash_bytes(void);
size_t crypto_generichash_bytes_min(void);
size_t crypto_generichash_bytes_max(void);
size_t crypto_generichash_keybytes(void);
size_t crypto_generichash_keybytes_min(void);
size_t crypto_generichash_keybytes_max(void);
size_t crypto_generichash_blockbytes(void);
const char *crypto_generichash_primitive(void);
typedef crypto_generichash_blake2b_state crypto_generichash_state;
int crypto_generichash(unsigned char *out, size_t outlen,
                       const unsigned char *in, unsigned long long inlen,
                       const unsigned char *key, size_t keylen);
int crypto_generichash_init(crypto_generichash_state *state,
                            const unsigned char *key,
                            const size_t keylen, const size_t outlen);
int crypto_generichash_update(crypto_generichash_state *state,
                              const unsigned char *in,
                              unsigned long long inlen);
int crypto_generichash_final(crypto_generichash_state *state,
                             unsigned char *out, const size_t outlen);

]]

local _M = { }

_M.bytes = function() return tonumber(crypto_generichash_bytes()) end
_M.bytes_min = function() return tonumber(crypto_generichash_bytes_min()) end
_M.bytes_max = function() return tonumber(crypto_generichash_bytes_max()) end
_M.keybytes = function() return tonumber(crypto_generichash_keybytes()) end
_M.keybytes_min = function() return tonumber(crypto_generichash_keybytes_min()) end
_M.keybytes_max = function() return tonumber(crypto_generichash_keybytes_max()) end
_M.blockbytes = function() return tonumber(crypto_generichash_blockbytes()) end
_M.primitive = function() return ffi.string(lib.crypto_generichash_primitive()) end
_M.generichash = function(out, outlen, inbuf, inlen, key, keylen)
	out = out or ffi.new("unsigned char[?]", outlen)
	inlen = inlen or #inbuf
	keylen = keylen or (key and #key or 0)
	assert(lib.crypto_generichash(out, outlen, inbuf, inlen, key, keylen) == 0, "crypto_generichash returned non-zero")
	return out, outlen
end
_M.init = function(state, key, keylen, outlen)
	keylen = keylen or (key and #key or 0)
	assert(lib.crypto_generichash_init(state, key, keylen, outlen) == 0, "crypto_generichash_init returned non-zero")
	return state
end
_M.update = function(state, inbuf, inlen)
	inlen = inlen or #inbuf
	assert(lib.crypto_generichash_update(state, inbuf, inlen) == 0, "crypto_generichash_update returned non-zero")
	return state
end
_M.final = function(state, out, outlen)
	out = out or ffi.new("unsigned char[?]", outlen)
	assert(lib.crypto_generichash_final(state, out, outlen) == 0, "crypto_generichash_final returned non-zero")
	return out, outlen
end
_M.stream = ffi.metatype("struct crypto_generichash_blake2b_state", {
	__index = {
		init = _M.init ;
		update = _M.update ;
		final = _M.final ;
	} ;
})

return setmetatable ( _M , { __call = function(_M, ...) return _M.generichash(...) end } )
