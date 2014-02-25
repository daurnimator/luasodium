# Sodium

This library is a Lua binding to [libsodium](https://github.com/jedisct1/libsodium); 
which is a repackaging of [NaCl: Networking and Cryptography library](http://nacl.cr.yp.to/).

It uses the FFI library that comes with LuaJIT or via [luaffi](https://github.com/jmckaskill/luaffi).

## Status

### Complete

  - Low-level wrappers via the FFI for libsodium/NaCl

### To do

  - Higher level wrappers to allow use of common lua idioms
  - Documentation
  - DNSCurve Example

## Documentation

As it stands, only the low level binding is done;
It is extremly easy to shoot yourself in the foot, as many parameters are not checked for validity.

Please refer to the [official NaCl documentation](http://nacl.cr.yp.to/) for now: all caveats found there apply.
