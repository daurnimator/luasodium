local ffi = require "ffi"
local lib = ffi.load "sodium"

ffi.cdef [[
int sodium_init(void);
unsigned char *_sodium_alignedcalloc(unsigned char ** const unaligned_p,
                                     const size_t len);
void sodium_memzero(void * const pnt, const size_t len);
int sodium_memcmp(const void * const b1_, const void * const b2_, size_t size);
char *sodium_bin2hex(char * const hex, const size_t hexlen,
                     const unsigned char *bin, const size_t binlen);
const char *sodium_version_string(void);
int sodium_library_version_major(void);
int sodium_library_version_minor(void);
]]

local _M = { }

_M.init = function()
	local r = lib.sodium_init()
	if r < 0 then error("sodium was unable to initialise") end
	return r > 1
end
_M.memzero = lib.sodium_memzero
_M.memcmp = lib.sodium_memcmp
_M.bin2hex = function(hex, hexlen, bin, binlen)
	binlen = binlen or #bin
	hexlen = hexlen or binlen*2
	hex = hex or ffi.new("unsigned char[?]", hexlen)
	lib.sodium_bin2hex(hex, hexlen, bin, binlen)
	return hex, hexlen
end
_M.version_string = function() return ffi.string(lib.sodium_version_string()) end
_M.library_version_major = function() return tonumber(lib.sodium_library_version_major()) end
_M.library_version_minor = function() return tonumber(lib.sodium_library_version_minor)) end

return _M
