local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
size_t crypto_core_hsalsa20_outputbytes(void);
size_t crypto_core_hsalsa20_inputbytes(void);
size_t crypto_core_hsalsa20_keybytes(void);
size_t crypto_core_hsalsa20_constbytes(void);
const char * crypto_core_hsalsa20_primitive(void);
int crypto_core_hsalsa20(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);
size_t crypto_core_salsa20_outputbytes(void);
size_t crypto_core_salsa20_inputbytes(void);
size_t crypto_core_salsa20_keybytes(void);
size_t crypto_core_salsa20_constbytes(void);
const char * crypto_core_salsa20_primitive(void);
int crypto_core_salsa20(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);
size_t crypto_core_salsa2012_outputbytes(void);
size_t crypto_core_salsa2012_inputbytes(void);
size_t crypto_core_salsa2012_keybytes(void);
size_t crypto_core_salsa2012_constbytes(void);
const char * crypto_core_salsa2012_primitive(void);
int crypto_core_salsa2012(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);
size_t crypto_core_salsa208_outputbytes(void);
size_t crypto_core_salsa208_inputbytes(void);
size_t crypto_core_salsa208_keybytes(void);
size_t crypto_core_salsa208_constbytes(void);
const char * crypto_core_salsa208_primitive(void);
int crypto_core_salsa208(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);
]]
