# sphss - Simple and Portable HSS signatures
Simple and portable implementation of LMS/HSS signatures. The code tries to make everything simple as possible to use LMS Hash Based Signature Scheme from [RFC 8554](https://datatracker.ietf.org/doc/html/rfc8554).

**Disclaimer**: this version is reference only. It is not side-channel protected. Also, it is not optimized.
# LMS/HSS Signatures
The code is a KISS (Keep it simple stupid) of LMS/HSS signatures.
It is based entire in the [RFC 8554](https://datatracker.ietf.org/doc/html/rfc8554).


## How to run
-Select the best flavour in the Makefile, for example:
```Makefile
COMPILE_FLAGS = -DLMOTS_SHA256_N32_W8 -DLMS_SHA256_M32_H5
```
The other options for LMOTS are:
```
-DLMOTS_SHA256_N32_W1

-DLMOTS_SHA256_N32_W2

-DLMOTS_SHA256_N32_W4

-DLMOTS_SHA256_N32_W8
```
The other options for LMS are:
```
-DLMS_SHA256_M32_H5

-DLMS_SHA256_M32_H10

-DLMS_SHA256_M32_H15

-DLMS_SHA256_M32_H20

-DLMS_SHA256_M32_H25
```
Then it is just call make:
```Console
foo@bar: make
foo@bar: ./sphss
```

## Tests

## Benchmark
Using cpucycle from [Supercop](https://bench.cr.yp.to/supercop.html), we reach the following values for COMPILE_FLAGS = -DLMOTS_SHA256_N32_W8 -DLMS_SHA256_M32_H5 (in an Intel(R) Core(TM) i7-10610U CPU @ 1.80GHz, gcc 11.2.0):

```
median lms-ots keygen: 5616362 cycles
median lms-ots sign: 2786342 cycles
median lms-ots verify: 2868226 cycles
median lms keygen: 183550217 cycles
median lms sign: 184972134 cycles
median lms verify: 2938331 cycles
median hss keygen: 549353814 cycles
median hss sign: 184756800 cycles
median hss verify: 5838829 cycles
```
