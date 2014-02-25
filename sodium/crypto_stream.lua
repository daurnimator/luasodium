local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
size_t crypto_stream_xsalsa20_keybytes(void);
size_t crypto_stream_xsalsa20_noncebytes(void);
const char * crypto_stream_xsalsa20_primitive(void);
int crypto_stream_xsalsa20(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
int crypto_stream_xsalsa20_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
size_t crypto_stream_keybytes(void);
size_t crypto_stream_noncebytes(void);
const char *crypto_stream_primitive(void);
int crypto_stream(unsigned char *c, unsigned long long clen,
                  const unsigned char *n, const unsigned char *k);
int crypto_stream_xor(unsigned char *c, const unsigned char *m,
                      unsigned long long mlen, const unsigned char *n,
                      const unsigned char *k);
size_t crypto_stream_aes128ctr_keybytes(void);
size_t crypto_stream_aes128ctr_noncebytes(void);
size_t crypto_stream_aes128ctr_beforenmbytes(void);
const char * crypto_stream_aes128ctr_primitive(void);
int crypto_stream_aes128ctr(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
int crypto_stream_aes128ctr_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
int crypto_stream_aes128ctr_beforenm(unsigned char *,const unsigned char *);
int crypto_stream_aes128ctr_afternm(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
int crypto_stream_aes128ctr_xor_afternm(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
size_t crypto_stream_aes256estream_keybytes(void);
size_t crypto_stream_aes256estream_noncebytes(void);
size_t crypto_stream_aes256estream_beforenmbytes(void);
const char * crypto_stream_aes256estream_primitive(void);
int crypto_stream_aes256estream(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
int crypto_stream_aes256estream_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
int crypto_stream_aes256estream_beforenm(unsigned char *,const unsigned char *);
int crypto_stream_aes256estream_afternm(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
int crypto_stream_aes256estream_xor_afternm(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
size_t crypto_stream_salsa20_keybytes(void);
size_t crypto_stream_salsa20_noncebytes(void);
const char * crypto_stream_salsa20_primitive(void);
int crypto_stream_salsa20(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
int crypto_stream_salsa20_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
size_t crypto_stream_salsa2012_keybytes(void);
size_t crypto_stream_salsa2012_noncebytes(void);
const char * crypto_stream_salsa2012_primitive(void);
int crypto_stream_salsa2012(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
int crypto_stream_salsa2012_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
size_t crypto_stream_salsa208_keybytes(void);
size_t crypto_stream_salsa208_noncebytes(void);
const char * crypto_stream_salsa208_primitive(void);
int crypto_stream_salsa208(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
int crypto_stream_salsa208_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
]]

local _M = { }

_M.keybytes = function() return tonumber(lib.crypto_stream_keybytes()) end
_M.noncebytes = function() return tonumber(lib.crypto_stream_noncebytes()) end
_M.primitive = function() return ffi.string(lib.crypto_stream_primitive()) end
_M.stream = function(c, clen, n, k)
	c = c or ffi.new("unsigned char[?]", clen)
	assert(lib.crypto_stream(c, clen, n, k) == 0, "crypto_stream returned non-zero")
	return c, clen
end
_M.xor = function(c, m, mlen, n, k)
	mlen = mlen or #m
	c = c or ffi.new("unsigned char[?]", mlen)
	assert(lib.crypto_stream_xor(c, m, mlen, n, k) == 0, "crypto_stream_xor returned non-zero")
	return c, mlen
end

return setmetatable ( _M , { __call = function(_M, ...) return _M.stream(...) end } )
