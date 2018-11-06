# Reference implementation of qTESLA-III-size in portable C

# Linux

To compile, do:

make 

which by default sets ARCH=x64, CC=gcc and DEBUG=FALSE, or do:

make ARCH=[x64/x86/ARM/ARM64] CC=[gcc/clang] DEBUG=[TRUE/FALSE]

The following executables are generated: "test\_qtesla-III-size", "PQCtestKAT\_sign-III-size"
and "PQCgenKAT\_sign-III-size".

To get cycle counts for key generation, signing and verification, execute:

./test\_qtesla-III-size

To test against known answer values in the KAT folder, execute:

./PQCtestKAT\_sign-III-size

To generate new KAT files, execute:

./PQCgenKAT\_sign-III-size

Using DEBUG=TRUE generates statistics on acceptance rates and timings for internal functions. 

