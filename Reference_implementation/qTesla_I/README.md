# Reference implementation of qTESLA-I in portable C

# Linux

To compile, do:

make 

which by default sets ARCH=x64, CC=gcc and DEBUG=FALSE, or do:

make ARCH=[x64/x86/ARM/ARM64] CC=[gcc/clang] DEBUG=[TRUE/FALSE]

The following executables are generated: "test\_qtesla-I", "PQCtestKAT\_sign-I" and "PQCgenKAT\_sign-I".

To get cycle counts for key generation, signing and verification, execute:

./test\_qtesla-I

To test against known answer values in the KAT folder, execute:

./PQCtestKAT\_sign-I

To generate new KAT files, execute:

./PQCgenKAT\_sign-I

Using DEBUG=TRUE generates statistics on acceptance rates and timings for internal functions. 

