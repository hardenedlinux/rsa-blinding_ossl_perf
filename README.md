## RSA blinding performance benchmark in OpenSSL

BoringSSL retired RSA blinding due they're quite confident about the RSA implementation in BoringSSL has been constant-time for a while. It was the trigginer point for us to look into how's the performance hits with RSA blinding in OpenSSL.

## What is RSA blinding and why we need it

RSA blinding is a technique that randomizes the input to an RSA private‑key operation (signing or decryption) so that the actual computation performed by the device is independent of the original plaintext or ciphertext.

Given a message m (or ciphertext c) and a private key (N,d):

  * Choose a random blinding factor r such that gcd(r,N)=1.
  * Compute the blinded value: m′=m⋅r^e (mod N) or c′=c⋅r^e (mod N) where e is the public exponent.
  * Perform the private‑key exponentiation on the blinded value: s′=(m′)^d (mod N) or p′=(c′)^d (mod N)
  * Remove the blinding factor: s=s′⋅r^−1 (modN) or p=p′⋅r^−1(mod N) The result s (signature) or p (plaintext) is exactly the same as if the operation had been performed without blinding.

This is one of earliest mitigation against side channel attack [dropped](https://paulkocher.com/doc/TimingAttacks.pdf) by Paul C. Kocher.

## RSA blinding in OpenSSL

It's enabled by default since 2003 and OpenSSL has been done the constant-time for the BN_ functions since 2023. RSA blinding is still there but cost less performance as we thought (less than 1%). The OpenSSL's speed utility doesn't provide the benchmark about the one without enabling RSA blinding. Two approach can be utilized for the benchmark.

1, Use this [tiny patch](https://github.com/hardenedlinux/rsa-blinding_ossl_perf/blob/master/blinding_off.patch):
```
Default:
version: 3.6.0
built on: Sun Dec 14 06:10:01 2025 UTC
options: bn(64,64)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -fPIC -pthread -m64 -Wa,--noexecstack -Wall -fzero-call-used-regs=used-gpr -DOPENSSL_TLS_SECURITY_LEVEL=2 -g -O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -ffile-prefix-map=/build/openssl-S7huCI/openssl-3.0.13=. -fstack-protector-strong -fstack-clash-protection -Wformat -Werror=format-security -fcf-protection -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -Wdate-time -D_FORTIFY_SOURCE=3 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG
CPUINFO: OPENSSL_ia32cap=0x7ef8320b078bffff:0x0040069c219c97a9:0x0000000000000010:0x0000000000000000:0x0000000000000000
                   sign    verify    encrypt   decrypt   sign/s verify/s  encr./s  decr./s
rsa   512 bits 0.000029s 0.000002s 0.000002s 0.000031s  35036.0 658506.1 495000.8  32359.3
rsa  1024 bits 0.000065s 0.000004s 0.000005s 0.000069s  15307.8 250621.4 217599.6  14496.9
rsa  2048 bits 0.000450s 0.000013s 0.000014s 0.000454s   2220.3  77590.4  73102.4   2201.3
rsa  3072 bits 0.001366s 0.000027s 0.000028s 0.001373s    732.0  36534.6  35143.8    728.2
rsa  4096 bits 0.003096s 0.000047s 0.000048s 0.003103s    323.0  21191.5  20700.8    322.3
rsa  7680 bits 0.027425s 0.000161s 0.000162s 0.027500s     36.5   6227.1   6167.1     36.4
rsa 15360 bits 0.145652s 0.000630s 0.000633s 0.145652s      6.9   1587.0   1579.0      6.9


Blinding off:
version: 3.6.0
built on: Sun Dec 14 06:10:01 2025 UTC
options: bn(64,64)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -fPIC -pthread -m64 -Wa,--noexecstack -Wall -fzero-call-used-regs=used-gpr -DOPENSSL_TLS_SECURITY_LEVEL=2 -g -O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -ffile-prefix-map=/build/openssl-S7huCI/openssl-3.0.13=. -fstack-protector-strong -fstack-clash-protection -Wformat -Werror=format-security -fcf-protection -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -Wdate-time -D_FORTIFY_SOURCE=3 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG
CPUINFO: OPENSSL_ia32cap=0x7ef8320b078bffff:0x0040069c219c97a9:0x0000000000000010:0x0000000000000000:0x0000000000000000
                   sign    verify    encrypt   decrypt   sign/s verify/s  encr./s  decr./s
rsa   512 bits 0.000029s 0.000002s 0.000002s 0.000031s  35048.7 657883.1 496318.1  32387.9
rsa  1024 bits 0.000065s 0.000004s 0.000005s 0.000069s  15305.9 248873.3 216991.4  14471.6
rsa  2048 bits 0.000449s 0.000013s 0.000014s 0.000454s   2227.0  77356.2  72826.8   2204.9
rsa  3072 bits 0.001369s 0.000027s 0.000028s 0.001375s    730.2  36564.3  35279.1    727.5
rsa  4096 bits 0.003097s 0.000047s 0.000048s 0.003102s    322.9  21188.6  20678.7    322.4
rsa  7680 bits 0.027350s 0.000161s 0.000162s 0.027350s     36.6   6228.1   6163.2     36.6
rsa 15360 bits 0.146087s 0.000631s 0.000634s 0.145652s      6.8   1584.3   1577.1      6.9
```

2, LD_PRELOAD is a [good tool](https://github.com/hardenedlinux/rsa-blinding_ossl_perf/blob/master/blinding_off.patch) which is not only being used by userland rootkit:
```
LD_PRELOAD blinding off:
version: 3.6.0
built on: Sun Dec 14 07:55:37 2025 UTC
options: bn(64,64)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -fPIC -pthread -m64 -Wa,--noexecstack -Wall -fzero-call-used-regs=used-gpr -DOPENSSL_TLS_SECURITY_LEVEL=2 -g -O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -fstack-protector-strong -fstack-clash-protection -Wformat -Werror=format-security -fcf-protection -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -Wdate-time -D_FORTIFY_SOURCE=3 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG
CPUINFO: OPENSSL_ia32cap=0x7ef8320b078bffff:0x0040069c219c97a9:0x0000000000000010:0x0000000000000000:0x0000000000000000
                   sign    verify    encrypt   decrypt   sign/s verify/s  encr./s  decr./s
rsa   512 bits 0.000029s 0.000002s 0.000002s 0.000031s  34924.5 656780.3 493226.8  32269.0
rsa  1024 bits 0.000065s 0.000004s 0.000005s 0.000069s  15272.6 249891.7 216428.6  14438.3
rsa  2048 bits 0.000449s 0.000013s 0.000014s 0.000453s   2227.8  77507.2  72963.1   2205.5
rsa  3072 bits 0.001371s 0.000027s 0.000028s 0.001377s    729.5  36409.4  35274.1    726.2
rsa  4096 bits 0.003101s 0.000048s 0.000049s 0.003108s    322.5  20847.7  20362.6    321.8
rsa  7680 bits 0.027452s 0.000160s 0.000162s 0.027527s     36.4   6231.6   6159.0     36.3
rsa 15360 bits 0.145797s 0.000631s 0.000633s 0.145797s      6.9   1586.0   1578.9      6.9

LD_PRELOAD blinding on:
version: 3.6.0
built on: Sun Dec 14 07:55:37 2025 UTC
options: bn(64,64)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -fPIC -pthread -m64 -Wa,--noexecstack -Wall -fzero-call-used-regs=used-gpr -DOPENSSL_TLS_SECURITY_LEVEL=2 -g -O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -fstack-protector-strong -fstack-clash-protection -Wformat -Werror=format-security -fcf-protection -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -Wdate-time -D_FORTIFY_SOURCE=3 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG
CPUINFO: OPENSSL_ia32cap=0x7ef8320b078bffff:0x0040069c219c97a9:0x0000000000000010:0x0000000000000000:0x0000000000000000
                   sign    verify    encrypt   decrypt   sign/s verify/s  encr./s  decr./s
rsa   512 bits 0.000029s 0.000002s 0.000002s 0.000031s  34931.2 658230.2 493063.0  32186.6
rsa  1024 bits 0.000066s 0.000004s 0.000005s 0.000069s  15253.5 250361.3 216917.3  14438.9
rsa  2048 bits 0.000450s 0.000013s 0.000014s 0.000453s   2221.2  77457.8  72879.6   2205.1
rsa  3072 bits 0.001369s 0.000027s 0.000028s 0.001375s    730.3  36539.7  35305.9    727.5
rsa  4096 bits 0.003100s 0.000047s 0.000048s 0.003111s    322.6  21150.4  20635.0    321.5
rsa  7680 bits 0.027322s 0.000161s 0.000163s 0.027322s     36.6   6224.5   6148.5     36.6
rsa 15360 bits 0.146087s 0.000631s 0.000635s 0.145797s      6.8   1583.9   1575.6      6.9
```
