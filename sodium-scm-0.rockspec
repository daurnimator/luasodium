package = "sodium"
version = "scm-0"

description = {
	summary = "Lua binding to libsodium (https://github.com/jedisct1/libsodium)" ;
	detailed = [[
This library is a Lua binding to [libsodium](https://github.com/jedisct1/libsodium);
which is a repackaging of [NaCl: Networking and Cryptography library](http://nacl.cr.yp.to/).
	]] ;
	license = "MIT/X11" ;
}

dependencies = {
	"lua >= 5.1" ;
	"lua < 5.3" ;
}

source = {
	url = "git://github.com/daurnimator/luasodium.git" ;
}

build = {
	type = "builtin" ;
	modules = {
		["sodium.init"]               = "sodium/init.lua" ;
		["sodium.crypto_auth"]        = "sodium/crypto_auth.lua" ;
		["sodium.crypto_box"]         = "sodium/crypto_box.lua" ;
		["sodium.crypto_core"]        = "sodium/crypto_core.lua" ;
		["sodium.crypto_generichash"] = "sodium/crypto_generichash.lua" ;
		["sodium.crypto_hash"]        = "sodium/crypto_hash.lua" ;
		["sodium.crypto_hashblocks"]  = "sodium/crypto_hashblocks.lua" ;
		["sodium.crypto_onetimeauth"] = "sodium/crypto_onetimeauth.lua" ;
		["sodium.crypto_scalarmult"]  = "sodium/crypto_scalarmult.lua" ;
		["sodium.crypto_secretbox"]   = "sodium/crypto_secretbox.lua" ;
		["sodium.crypto_shorthash"]   = "sodium/crypto_shorthash.lua" ;
		["sodium.crypto_secretbox"]   = "sodium/crypto_secretbox.lua" ;
		["sodium.crypto_sign"]        = "sodium/crypto_sign.lua" ;
		["sodium.crypto_stream"]      = "sodium/crypto_stream.lua" ;
		["sodium.crypto_verify"]      = "sodium/crypto_verify.lua" ;
		["sodium.randombytes"]        = "sodium/randombytes.lua" ;
	} ;
}
