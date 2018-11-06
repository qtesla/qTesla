# Reference implementation of qTESLA-p-III in portable C

# Linux

To compile, do:

make 

which by default sets ARCH=x64, CC=gcc and DEBUG=FALSE, or do:

make ARCH=[x64/x86/ARM/ARM64] CC=[gcc/clang] DEBUG=[TRUE/FALSE]

The following executables are generated: "test\_qtesla-p-III", "PQCtestKAT\_sign-p-III" and "PQCgenKAT\_sign-p-III".

To get cycle counts for key generation, signing and verification, execute:

./test\_qtesla-p-III

To test against known answer values in the KAT folder, execute:

./PQCtestKAT\_sign-p-III

To generate new KAT files, execute:

./PQCgenKAT\_sign-p-III

Using DEBUG=TRUE generates statistics on acceptance rates and timings for internal functions. 

