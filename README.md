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
Using cpucycle from [Supercop](https://bench.cr.yp.to/supercop.html), we reach the following values (in an Intel(R) Core(TM) i7-10610U CPU @ 1.80GHz):

```
median lms-ots keygen: 7893243 cycles 
median lms-ots sign: 3907529 cycles 
median lms-ots verify: 3990474 cycles 
median lms keygen: 294766029 cycles 
median lms sign: 300630336 cycles 
median lms verify: 4644142 cycles 
median hss keygen: 838803787 cycles 
median hss sign: 283486422 cycles 
median hss verify: 8780359 cycles 
```
