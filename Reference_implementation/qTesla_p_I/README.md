# Reference implementation of qTESLA-p-I in portable C

# Linux

To compile, do:

make 

which by default sets ARCH=x64, CC=gcc and DEBUG=FALSE, or do:

make ARCH=[x64/x86/ARM/ARM64] CC=[gcc/clang] DEBUG=[TRUE/FALSE]

The following executables are generated: "test\_qtesla-p-I", "PQCtestKAT\_sign-p-I" and "PQCgenKAT\_sign-p-I".

To get cycle counts for key generation, signing and verification, execute:

./test\_qtesla-p-I

To test against known answer values in the KAT folder, execute:

./PQCtestKAT\_sign-p-I

To generate new KAT files, execute:

./PQCgenKAT\_sign-p-I

Using DEBUG=TRUE generates statistics on acceptance rates and timings for internal functions. 

