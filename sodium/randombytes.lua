local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
typedef struct randombytes_implementation {
    const char *(*implementation_name)(void);
    uint32_t (*random)(void);
    void (*stir)(void);
    uint32_t (*uniform)(const uint32_t upper_bound);
    void (*buf)(void * const buf, const size_t size);
    int (*close)(void);
} randombytes_implementation;
int randombytes_set_implementation(randombytes_implementation *impl);
void randombytes(unsigned char * const buf, const unsigned long long buf_len);
const char *randombytes_implementation_name(void);
uint32_t randombytes_random(void);
void randombytes_stir(void);
uint32_t randombytes_uniform(const uint32_t upper_bound);
void randombytes_buf(void * const buf, const size_t size);
int randombytes_close(void);
extern struct randombytes_implementation randombytes_salsa20_implementation;
const char *randombytes_salsa20_implementation_name(void);
uint32_t randombytes_salsa20_random(void);
void randombytes_salsa20_random_stir(void);
uint32_t randombytes_salsa20_random_uniform(const uint32_t upper_bound);
void randombytes_salsa20_random_buf(void * const buf, const size_t size);
int randombytes_salsa20_random_close(void);
extern struct randombytes_implementation randombytes_sysrandom_implementation;
const char *randombytes_sysrandom_implementation_name(void);
uint32_t randombytes_sysrandom(void);
void randombytes_sysrandom_stir(void);
uint32_t randombytes_sysrandom_uniform(const uint32_t upper_bound);
void randombytes_sysrandom_buf(void * const buf, const size_t size);
int randombytes_sysrandom_close(void);
]]

local _M = { }

_M.random = function() return tonumber(lib.randombytes_random()) end
_M.stir = lib.randombytes_stir
_M.uniform = function(upper) return tonumber(lib.randombytes_uniform(upper)) end
_M.buf = function(buf, size)
	buf = buf or ffi.new("unsigned char[?]", size)
	lib.randombytes_buf(buf, size)
	return buf, size
end
_M.close = function()
	assert(lib.randombytes_close() == 0, "randombytes_close returned non-zero")
end

return _M
