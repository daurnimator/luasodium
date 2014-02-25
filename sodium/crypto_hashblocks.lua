local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
size_t crypto_hashblocks_sha256_statebytes(void);
size_t crypto_hashblocks_sha256_blockbytes(void);
const char * crypto_hashblocks_sha256_primitive(void);
int crypto_hashblocks_sha256(unsigned char *,const unsigned char *,unsigned long long);
size_t crypto_hashblocks_sha512_statebytes(void);
size_t crypto_hashblocks_sha512_blockbytes(void);
const char * crypto_hashblocks_sha512_primitive(void);
int crypto_hashblocks_sha512(unsigned char *,const unsigned char *,unsigned long long);
]]
