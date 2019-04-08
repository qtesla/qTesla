//************************************************************************************
// qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
//
// Abstract: optimized polynomial multiplication for case N = 512 written in 
//           x64 assembly with AVX2 support for Linux 
//************************************************************************************

.intel_syntax noprefix 

// Registers that are used for parameter passing:
#define reg_p1  rdi
#define reg_p2  rsi
#define reg_p3  rdx
#define reg_p4  rcx
#define reg_p5  r8


.text
//**********************************************************************************
//  Polynomial multiplication based on the NTT, case N = 512
//  Operation: c [reg_p1] <- NTT(a) [reg_p2] * b [reg_p5], 
//             [reg_p3] points to table with the NTT constants,
//             [reg_p4] points to a temporary storage of size 4*2*N bytes. 
//
//  NTT implementation is an optimized variant of the approach by G. Seiler, 
//  "Faster AVX2 optimized NTT multiplication for Ring-LWE lattice cryptography",
//  https://eprint.iacr.org/2018/039.pdf.
//  See also https://eprint.iacr.org/2017/633.pdf by L. Ducas, E. Kiltz, T. Lepoint, 
//  V. Lyubashevsky, P. Schwabe and G. Seiler, that reports an implementation of the 
//  approach.
//********************************************************************************** 
.global poly_mul_asm
poly_mul_asm:

// Forward NTT
  xor          rax, rax 
  xor          r11, r11 
  vmovdqa      ymm15, YMMWORD PTR [PARAM_Qx4+rip]
  vmovdqa      ymm14, YMMWORD PTR [PARAM_QINVx4+rip]
  vbroadcastss ymm12, DWORD PTR [reg_p3]              // Load twiddle factor W     
  mov          r10, 16                                
loop_ntt123:
// Round 1  
  vpmovsxdq    ymm4, XMMWORD PTR [reg_p2+rax+1024]    // a[j+k]     
  vpmovsxdq    ymm5, XMMWORD PTR [reg_p2+rax+1280]      
  vpmovsxdq    ymm6, XMMWORD PTR [reg_p2+rax+1536] 
  vpmovsxdq    ymm7, XMMWORD PTR [reg_p2+rax+1792]
  vpmovsxdq    ymm0, XMMWORD PTR [reg_p2+rax]         // a[j] 
  vpmovsxdq    ymm1, XMMWORD PTR [reg_p2+rax+256]  
  vpmovsxdq    ymm2, XMMWORD PTR [reg_p2+rax+512]
  vpmovsxdq    ymm3, XMMWORD PTR [reg_p2+rax+768] 
  vpmuldq      ymm4, ymm4, ymm12                      // W.a[j+k]
  vpmuldq      ymm5, ymm5, ymm12                    
  vpmuldq      ymm6, ymm6, ymm12                    
  vpmuldq      ymm7, ymm7, ymm12   
  vpmuldq      ymm8, ymm4, ymm14                      // temp = reduce(W.a[j+k])
  vpmuldq      ymm9, ymm5, ymm14                    
  vpmuldq      ymm10, ymm6, ymm14 
  vpmuldq      ymm11, ymm7, ymm14
  vpmuludq     ymm8, ymm8, ymm15  
  vpmuludq     ymm9, ymm9, ymm15 
  vpmuludq     ymm10, ymm10, ymm15                   
  vpmuludq     ymm11, ymm11, ymm15
  vpaddq       ymm4, ymm4, ymm8                      
  vpaddq       ymm5, ymm5, ymm9                     
  vpaddq       ymm6, ymm6, ymm10   
  vpsrlq       ymm8, ymm4, 32                        
  vpsrlq       ymm9, ymm5, 32                       
  vpsrlq       ymm10, ymm6, 32
  vpsubd       ymm4, ymm0, ymm8                       // a[j+k] = a[j] - temp
  vpsubd       ymm5, ymm1, ymm9                     
  vpsubd       ymm6, ymm2, ymm10
  vpaddd       ymm0, ymm0, ymm8                       // a[j] = a[j] + temp    
  vpaddd       ymm1, ymm1, ymm9                     
  vpaddd       ymm2, ymm2, ymm10  
  
  vbroadcastss ymm10, DWORD PTR [reg_p3+4]            // Load twiddle factor W
  vbroadcastss ymm13, DWORD PTR [reg_p3+8]                   
                                                                              
  vpaddq       ymm7, ymm7, ymm11                                     
  vpsrlq       ymm11, ymm7, 32 
  vpsubd       ymm7, ymm3, ymm11
  vpaddd       ymm3, ymm3, ymm11

// Round 2
  vpmuldq      ymm2, ymm2, ymm10                      // W.a[j+k]
  vpmuldq      ymm3, ymm3, ymm10                    
  vpmuldq      ymm6, ymm6, ymm13                    
  vpmuldq      ymm7, ymm7, ymm13
  vpmuldq      ymm8, ymm2, ymm14                      // temp = reduce(W.a[j+k])
  vpmuldq      ymm9, ymm3, ymm14                    
  vpmuldq      ymm10, ymm6, ymm14  
  vpmuldq      ymm11, ymm7, ymm14
  vpmuludq     ymm8, ymm8, ymm15 
  vpmuludq     ymm9, ymm9, ymm15 
  vpmuludq     ymm10, ymm10, ymm15                                 
  vpmuludq     ymm11, ymm11, ymm15   
  vpaddq       ymm2, ymm2, ymm8                      
  vpaddq       ymm3, ymm3, ymm9                     
  vpaddq       ymm6, ymm6, ymm10    
  vpsrlq       ymm8, ymm2, 32                        
  vpsrlq       ymm9, ymm3, 32                       
  vpsrlq       ymm10, ymm6, 32
  vpsubd       ymm2, ymm0, ymm8                       // a[j+k] = a[j] - temp 
  vpsubd       ymm3, ymm1, ymm9                    
  vpsubd       ymm6, ymm4, ymm10
  vpaddd       ymm0, ymm0, ymm8                       // a[j] = a[j] + temp 
  vpaddd       ymm1, ymm1, ymm9                     
  vpaddd       ymm4, ymm4, ymm10 

  vbroadcastss ymm8, DWORD PTR [reg_p3+12]            // Load twiddle factor W
  vbroadcastss ymm9, DWORD PTR [reg_p3+16]            
  vbroadcastss ymm10, DWORD PTR [reg_p3+20]         
  vbroadcastss ymm13, DWORD PTR [reg_p3+24] 
                                                                
  vpaddq       ymm7, ymm7, ymm11                                     
  vpsrlq       ymm11, ymm7, 32
  vpsubd       ymm7, ymm5, ymm11
  vpaddd       ymm5, ymm5, ymm11

// Round 3
  vpmuldq      ymm1, ymm1, ymm8                       // W.a[j+k]
  vpmuldq      ymm3, ymm3, ymm9                     
  vpmuldq      ymm5, ymm5, ymm10                    
  vpmuldq      ymm7, ymm7, ymm13
  vpmuldq      ymm8, ymm1, ymm14                      // temp = reduce(W.a[j+k])
  vpmuldq      ymm9, ymm3, ymm14                    
  vpmuldq      ymm10, ymm5, ymm14  
  vpmuldq      ymm11, ymm7, ymm14
  vpmuludq     ymm8, ymm8, ymm15
  vpmuludq     ymm9, ymm9, ymm15 
  vpmuludq     ymm10, ymm10, ymm15                             
  vpmuludq     ymm11, ymm11, ymm15
  vpaddq       ymm1, ymm1, ymm8                     
  vpaddq       ymm3, ymm3, ymm9                     
  vpaddq       ymm5, ymm5, ymm10                                     
  vpaddq       ymm7, ymm7, ymm11   
  vpsrlq       ymm8, ymm1, 32                           
  vpsrlq       ymm9, ymm3, 32                       
  vpsrlq       ymm10, ymm5, 32                                 
  vpsrlq       ymm11, ymm7, 32
  vpsubd       ymm1, ymm0, ymm8                       // a[j+k] = a[j] - temp
  vpsubd       ymm3, ymm2, ymm9                    
  vpsubd       ymm5, ymm4, ymm10
  vpsubd       ymm7, ymm6, ymm11
  vpaddd       ymm0, ymm0, ymm8                       // a[j] = a[j] + temp
  vpaddd       ymm2, ymm2, ymm9                      
  vpaddd       ymm4, ymm4, ymm10                               
  vpaddd       ymm6, ymm6, ymm11  
  vmovdqa      [reg_p4+r11+512], ymm1                 // Store in temporary storage
  vmovdqa      [reg_p4+r11+1536], ymm3
  vmovdqa      [reg_p4+r11+2560], ymm5
  vmovdqa      [reg_p4+r11+3584], ymm7
  vmovdqa      [reg_p4+r11], ymm0                     
  vmovdqa      [reg_p4+r11+1024], ymm2
  vmovdqa      [reg_p4+r11+2048], ymm4
  vmovdqa      [reg_p4+r11+3072], ymm6
  add          rax, 16
  add          r11, 32
  dec          r10
  jnz          loop_ntt123
                                                    
  xor          r11, r11 
  xor          rax, rax
round4_loop:
  vbroadcastss ymm12, DWORD PTR [reg_p3+rax+28]       // Load twiddle factor W     
  vbroadcastss ymm9, DWORD PTR [reg_p3+rax+32]                   
  vbroadcastss ymm10, DWORD PTR [reg_p3+rax+36]         
  vbroadcastss ymm11, DWORD PTR [reg_p3+rax+40] 
  mov          r10, 8                                
loop_ntt4:
// Round 4   
  vmovdqa      ymm4, YMMWORD PTR [reg_p4+r11+256]      
  vmovdqa      ymm5, YMMWORD PTR [reg_p4+r11+768]  
  vmovdqa      ymm6, YMMWORD PTR [reg_p4+r11+1280] 
  vmovdqa      ymm7, YMMWORD PTR [reg_p4+r11+1792]
  vmovdqa      ymm0, YMMWORD PTR [reg_p4+r11]         // a[j] 
  vmovdqa      ymm1, YMMWORD PTR [reg_p4+r11+512]      
  vmovdqa      ymm2, YMMWORD PTR [reg_p4+r11+1024]    // a[j+k]
  vmovdqa      ymm3, YMMWORD PTR [reg_p4+r11+1536] 
  vpmuldq      ymm4, ymm4, ymm12                      // W.a[j+k]
  vpmuldq      ymm5, ymm5, ymm9                     
  vpmuldq      ymm6, ymm6, ymm10                    
  vpmuldq      ymm7, ymm7, ymm11  

  vpmuldq      ymm8, ymm4, ymm14                      // temp = reduce(W.a[j+k])
  vpmuldq      ymm13, ymm5, ymm14 
  vpmuludq     ymm8, ymm8, ymm15  
  vpmuludq     ymm13, ymm13, ymm15 
  vpaddq       ymm4, ymm4, ymm8                     
  vpaddq       ymm5, ymm5, ymm13 
  vpsrlq       ymm8, ymm4, 32                         
  vpsrlq       ymm13, ymm5, 32 
  vpsubd       ymm4, ymm0, ymm8                       // a[j+k] = a[j] - temp
  vpsubd       ymm5, ymm1, ymm13 
  vpaddd       ymm0, ymm0, ymm8                       // a[j] = a[j] + temp   
  vpaddd       ymm1, ymm1, ymm13                     

  vpmuldq      ymm8, ymm6, ymm14                      // temp = reduce(W.a[j+k])
  vpmuldq      ymm13, ymm7, ymm14 
  vpmuludq     ymm8, ymm8, ymm15                             
  vpmuludq     ymm13, ymm13, ymm15 
  vpaddq       ymm6, ymm6, ymm8                                    
  vpaddq       ymm7, ymm7, ymm13 
  vpsrlq       ymm8, ymm6, 32                                      
  vpsrlq       ymm13, ymm7, 32 
  vpsubd       ymm6, ymm2, ymm8                       // a[j+k] = a[j] - temp
  vpsubd       ymm7, ymm3, ymm13
  vpaddd       ymm2, ymm2, ymm8                       // a[j] = a[j] + temp                     
  vpaddd       ymm3, ymm3, ymm13
  vmovdqa      [reg_p4+r11], ymm0                     // Store in temporary storage
  vmovdqa      [reg_p4+r11+256], ymm4
  vmovdqa      [reg_p4+r11+512], ymm1
  vmovdqa      [reg_p4+r11+768], ymm5
  vmovdqa      [reg_p4+r11+1024], ymm2
  vmovdqa      [reg_p4+r11+1280], ymm6
  vmovdqa      [reg_p4+r11+1536], ymm3
  vmovdqa      [reg_p4+r11+1792], ymm7
  add          r11, 32
  dec          r10
  jnz          loop_ntt4  
  add          rax, 16 
  mov          r11, 2048
  cmp          rax, 32
  jne          round4_loop

  xor          rax, rax               
  xor          r11, r11                            
  mov          r10, 16                               
loop_ntt_intt:
// Round 5
  vbroadcastss ymm12, DWORD PTR [reg_p3+rax+60]       // Load twiddle factor W
  vmovdqa      ymm0, YMMWORD PTR [reg_p4+r11]         // a[j] 
  vmovdqa      ymm4, YMMWORD PTR [reg_p4+r11+128]     // a[j+k]   
  vmovdqa      ymm1, YMMWORD PTR [reg_p4+r11+32]       
  vmovdqa      ymm5, YMMWORD PTR [reg_p4+r11+160] 
  vmovdqa      ymm2, YMMWORD PTR [reg_p4+r11+64]        
  vmovdqa      ymm6, YMMWORD PTR [reg_p4+r11+192] 
  vmovdqa      ymm3, YMMWORD PTR [reg_p4+r11+96] 
  vmovdqa      ymm7, YMMWORD PTR [reg_p4+r11+224]
  vpmuldq      ymm4, ymm4, ymm12                      // W.a[j+k]
  vpmuldq      ymm5, ymm5, ymm12                    
  vpmuldq      ymm6, ymm6, ymm12                    
  vpmuldq      ymm7, ymm7, ymm12
  vpmuldq      ymm8, ymm4, ymm14                      // temp = reduce(W.a[j+k])
  vpmuldq      ymm9, ymm5, ymm14                    
  vpmuldq      ymm10, ymm6, ymm14 
  vpmuldq      ymm11, ymm7, ymm14
  vpmuludq     ymm8, ymm8, ymm15   
  vpmuludq     ymm9, ymm9, ymm15  
  vpmuludq     ymm10, ymm10, ymm15                                                 
  vpmuludq     ymm11, ymm11, ymm15
  vpaddq       ymm4, ymm4, ymm8                     
  vpaddq       ymm5, ymm5, ymm9                     
  vpaddq       ymm6, ymm6, ymm10 
  vpsrlq       ymm8, ymm4, 32                        
  vpsrlq       ymm9, ymm5, 32                       
  vpsrlq       ymm10, ymm6, 32 
  vpsubd       ymm4, ymm0, ymm8                       // a[j+k] = a[j] - temp
  vpsubd       ymm5, ymm1, ymm9                     
  vpsubd       ymm6, ymm2, ymm10
  vpaddd       ymm0, ymm0, ymm8                       // a[j] = a[j] + temp
  vpaddd       ymm1, ymm1, ymm9                     
  vpaddd       ymm2, ymm2, ymm10  

  vbroadcastss ymm10, DWORD PTR [reg_p3+2*rax+124]    // Load twiddle factor W     
  vbroadcastss ymm13, DWORD PTR [reg_p3+2*rax+128]   
                                                 
  vpaddq       ymm7, ymm7, ymm11                                   
  vpsrlq       ymm11, ymm7, 32
  vpsubd       ymm7, ymm3, ymm11
  vpaddd       ymm3, ymm3, ymm11  
  
// Round 6 
  vpmuldq      ymm2, ymm2, ymm10                      // W.a[j+k]
  vpmuldq      ymm3, ymm3, ymm10                    
  vpmuldq      ymm6, ymm6, ymm13                    
  vpmuldq      ymm7, ymm7, ymm13 
  vpmuldq      ymm8, ymm2, ymm14                      // temp = reduce(W.a[j+k])
  vpmuldq      ymm9, ymm3, ymm14                    
  vpmuldq      ymm10, ymm6, ymm14  
  vpmuldq      ymm11, ymm7, ymm14 
  vpmuludq     ymm8, ymm8, ymm15  
  vpmuludq     ymm9, ymm9, ymm15
  vpmuludq     ymm10, ymm10, ymm15                                
  vpmuludq     ymm11, ymm11, ymm15 
  vpaddq       ymm2, ymm2, ymm8                       
  vpaddq       ymm3, ymm3, ymm9                     
  vpaddq       ymm6, ymm6, ymm10 
  vpsrlq       ymm8, ymm2, 32                        
  vpsrlq       ymm9, ymm3, 32                       
  vpsrlq       ymm10, ymm6, 32  
  vpsubd       ymm2, ymm0, ymm8                       // a[j+k] = a[j] - temp 
  vpsubd       ymm3, ymm1, ymm9                     
  vpsubd       ymm6, ymm4, ymm10
  vpaddd       ymm0, ymm0, ymm8                       // a[j] = a[j] + temp
  vpaddd       ymm1, ymm1, ymm9                     
  vpaddd       ymm4, ymm4, ymm10

  vbroadcastss ymm8, DWORD PTR [reg_p3+4*rax+252]     // Load twiddle factor W     
  vbroadcastss ymm9, DWORD PTR [reg_p3+4*rax+256]    
  vbroadcastss ymm10, DWORD PTR [reg_p3+4*rax+260]         
  vbroadcastss ymm13, DWORD PTR [reg_p3+4*rax+264] 
                                                               
  vpaddq       ymm7, ymm7, ymm11                                     
  vpsrlq       ymm11, ymm7, 32
  vpsubd       ymm7, ymm5, ymm11
  vpaddd       ymm5, ymm5, ymm11    
  
// Round 7
  vpmuldq      ymm1, ymm1, ymm8                       // W.a[j+k]
  vpmuldq      ymm3, ymm3, ymm9                     
  vpmuldq      ymm5, ymm5, ymm10                    
  vpmuldq      ymm7, ymm7, ymm13 
  vpmuldq      ymm8, ymm1, ymm14                      // temp = reduce(W.a[j+k])
  vpmuldq      ymm9, ymm3, ymm14                    
  vpmuldq      ymm10, ymm5, ymm14                   
  vpmuldq      ymm11, ymm7, ymm14 
  vpmuludq     ymm8, ymm8, ymm15                   
  vpmuludq     ymm9, ymm9, ymm15                   
  vpmuludq     ymm10, ymm10, ymm15                   
  vpmuludq     ymm11, ymm11, ymm15 
  vpaddq       ymm1, ymm1, ymm8                      
  vpaddq       ymm3, ymm3, ymm9                     
  vpaddq       ymm5, ymm5, ymm10 
  vpsrlq       ymm8, ymm1, 32                        
  vpsrlq       ymm9, ymm3, 32                       
  vpsrlq       ymm10, ymm5, 32 
  vpsubd       ymm1, ymm0, ymm8                       // a[j+k] = a[j] - temp 
  vpsubd       ymm3, ymm2, ymm9                     
  vpsubd       ymm5, ymm4, ymm10 
  vpaddd       ymm0, ymm0, ymm8                       // a[j] = a[j] + temp               
  vpaddd       ymm2, ymm2, ymm9                      
  vpaddd       ymm4, ymm4, ymm10
  
  vbroadcastss ymm8, DWORD PTR [reg_p3+8*rax+508]     // Load twiddle factor W     
  vbroadcastss ymm10, DWORD PTR [reg_p3+8*rax+512]  
  vbroadcastss ymm9, DWORD PTR [reg_p3+8*rax+516]  
  vbroadcastss ymm13, DWORD PTR [reg_p3+8*rax+520] 
  vbroadcastss ymm12, DWORD PTR [reg_p3+8*rax+524]
                    
  vpaddq       ymm7, ymm7, ymm11                                  
  vpsrlq       ymm11, ymm7, 32
  vpsubd       ymm7, ymm6, ymm11
  vpaddd       ymm6, ymm6, ymm11  

// Round 8      
  vpblendd     ymm8, ymm8, ymm10, 0xF0      
  vpblendd     ymm9, ymm9, ymm13, 0xF0      
  vbroadcastss ymm10, DWORD PTR [reg_p3+8*rax+528] 
  vbroadcastss ymm11, DWORD PTR [reg_p3+8*rax+532]
  vbroadcastss ymm13, DWORD PTR [reg_p3+8*rax+536] 
  vpblendd     ymm10, ymm12, ymm10, 0xF0 
  vpblendd     ymm11, ymm11, ymm13, 0xF0
  vperm2i128   ymm12, ymm0, ymm1, 0x20              
  vperm2i128   ymm0, ymm0, ymm1, 0x31               
  vperm2i128   ymm1, ymm2, ymm3, 0x20
  vperm2i128   ymm2, ymm2, ymm3, 0x31
  vperm2i128   ymm3, ymm4, ymm5, 0x20
  vperm2i128   ymm4, ymm4, ymm5, 0x31
  vperm2i128   ymm5, ymm6, ymm7, 0x20
  vperm2i128   ymm6, ymm6, ymm7, 0x31    
  vpmuldq      ymm0, ymm0, ymm8                       // W.a[j+k]
  vpmuldq      ymm2, ymm2, ymm9                     
  vpmuldq      ymm4, ymm4, ymm10                    
  vpmuldq      ymm6, ymm6, ymm11
  vpmuldq      ymm8, ymm0, ymm14                      // temp = reduce(W.a[j+k])
  vpmuldq      ymm9, ymm2, ymm14                    
  vpmuldq      ymm10, ymm4, ymm14                   
  vpmuldq      ymm11, ymm6, ymm14 
  vpmuludq     ymm8, ymm8, ymm15                
  vpmuludq     ymm9, ymm9, ymm15                   
  vpmuludq     ymm10, ymm10, ymm15                   
  vpmuludq     ymm11, ymm11, ymm15       
  vpaddq       ymm0, ymm0, ymm8                     
  vpaddq       ymm2, ymm2, ymm9                     
  vpaddq       ymm4, ymm4, ymm10
  vpsrlq       ymm8, ymm0, 32                       
  vpsrlq       ymm9, ymm2, 32                       
  vpsrlq       ymm10, ymm4, 32
  vpsubd       ymm0, ymm12, ymm8                      // a[j+k] = a[j] - temp
  vpsubd       ymm2, ymm1, ymm9                    
  vpsubd       ymm4, ymm3, ymm10
  vpaddd       ymm12, ymm12, ymm8                     // a[j] = a[j] + temp
  vpaddd       ymm1, ymm1, ymm9                     
  vpaddd       ymm3, ymm3, ymm10

  vpshufd      ymm8, ymm12, 0x4E
  vpshufd      ymm9, ymm0, 0x4E
  vpshufd      ymm10, ymm1, 0x4E
  vpshufd      ymm13, ymm2, 0x4E
                   
  vpaddq       ymm6, ymm6, ymm11                                     
  vpsrlq       ymm11, ymm6, 32
  vpsubd       ymm6, ymm5, ymm11
  vpaddd       ymm5, ymm5, ymm11   
  
// Round 9
  lea          r9, [reg_p3+8*rax+1020]
  vpblendd     ymm12, ymm12, ymm9, 0xCC
  vpblendd     ymm0, ymm8, ymm0, 0xCC
  vpblendd     ymm1, ymm1, ymm13, 0xCC
  vpblendd     ymm2, ymm10, ymm2, 0xCC
  vpshufd      ymm8, ymm3, 0x4E
  vpshufd      ymm9, ymm4, 0x4E
  vpshufd      ymm10, ymm5, 0x4E
  vpshufd      ymm11, ymm6, 0x4E
  vpblendd     ymm4, ymm8, ymm4, 0xCC
  vpblendd     ymm3, ymm3, ymm9, 0xCC
  vpblendd     ymm6, ymm10, ymm6, 0xCC
  vpblendd     ymm5, ymm5, ymm11, 0xCC
  vpmovzxdq    ymm8, XMMWORD PTR [r9+8*rax]           // Load twiddle factor W
  vpmovzxdq    ymm9, XMMWORD PTR [r9+8*rax+16]
  vpmovzxdq    ymm10, XMMWORD PTR [r9+8*rax+32]
  vpmovzxdq    ymm11, XMMWORD PTR [r9+8*rax+48]  
  vpmuldq      ymm0, ymm0, ymm8                       // W.a[j+k]
  vpmuldq      ymm2, ymm2, ymm9                     
  vpmuldq      ymm4, ymm4, ymm10                    
  vpmuldq      ymm6, ymm6, ymm11     
  vpmuldq      ymm8, ymm0, ymm14                      // temp = reduce(W.a[j+k])
  vpmuldq      ymm9, ymm2, ymm14                    
  vpmuldq      ymm10, ymm4, ymm14                   
  vpmuldq      ymm11, ymm6, ymm14  
  vpmuludq     ymm8, ymm8, ymm15                   
  vpmuludq     ymm9, ymm9, ymm15                   
  vpmuludq     ymm10, ymm10, ymm15                   
  vpmuludq     ymm11, ymm11, ymm15     
  vpaddq       ymm8, ymm0, ymm8                                   
  vpaddq       ymm9, ymm2, ymm9                     
  vpaddq       ymm10, ymm4, ymm10                   
  vpaddq       ymm11, ymm6, ymm11
  vpsrlq       ymm8, ymm8, 32 
  vpsrlq       ymm9, ymm9, 32  
  vpsrlq       ymm10, ymm10, 32  
  vpsrlq       ymm11, ymm11, 32
  vpsubd       ymm0, ymm12, ymm8                      // a[j+k] = a[j] - temp               
  vpsubd       ymm2, ymm1, ymm9                    
  vpsubd       ymm4, ymm3, ymm10
  vpsubd       ymm6, ymm5, ymm11                      
  vpaddd       ymm7, ymm5, ymm11                      // a[j] = a[j] + temp
  vpaddd       ymm5, ymm3, ymm10
  vpaddd       ymm3, ymm1, ymm9                     
  vpaddd       ymm1, ymm12, ymm8                     
//************************************************************************ END OF FORWARD NTT

// Pointwise multiplication                          
  vmovdqa      ymm8, YMMWORD PTR [reg_p5]
  vmovdqa      ymm9, YMMWORD PTR [reg_p5+32]
  vmovdqa      ymm10, YMMWORD PTR [reg_p5+64]
  vmovdqa      ymm11, YMMWORD PTR [reg_p5+96]
  vpmuldq      ymm1, ymm1, ymm8                       // a.b
  vpmuldq      ymm3, ymm3, ymm9 
  vpmuldq      ymm5, ymm5, ymm10
  vpmuldq      ymm7, ymm7, ymm11
  vpmuldq      ymm12, ymm1, ymm14                     // temp = reduce(a.b) 
  vpmuldq      ymm13, ymm3, ymm14                     
  vpmuludq     ymm12, ymm12, ymm15     
  vpmuludq     ymm13, ymm13, ymm15   
  vpaddq       ymm1, ymm1, ymm12                   
  vpaddq       ymm3, ymm3, ymm13                   
  vpmuldq      ymm12, ymm5, ymm14                     
  vpmuldq      ymm13, ymm7, ymm14                     
  vpmuludq     ymm12, ymm12, ymm15   
  vpmuludq     ymm13, ymm13, ymm15      
  vpaddq       ymm5, ymm5, ymm12                   
  vpaddq       ymm7, ymm7, ymm13   
  vpsrlq       ymm1, ymm1, 32                                       
  vpsrlq       ymm3, ymm3, 32                       
  vpsrlq       ymm5, ymm5, 32                   
  vpsrlq       ymm7, ymm7, 32
    
  vpsrlq       ymm8, ymm8, 32                                       
  vpsrlq       ymm9, ymm9, 32                       
  vpsrlq       ymm10, ymm10, 32                   
  vpsrlq       ymm11, ymm11, 32
  vpmuldq      ymm0, ymm0, ymm8                       // a.b
  vpmuldq      ymm2, ymm2, ymm9 
  vpmuldq      ymm4, ymm4, ymm10
  vpmuldq      ymm6, ymm6, ymm11
  vpmuldq      ymm8, ymm0, ymm14                      // temp = reduce(a.b) 
  vpmuldq      ymm9, ymm2, ymm14                      
  vpmuldq      ymm10, ymm4, ymm14                      
  vpmuldq      ymm11, ymm6, ymm14                       
  vpmuludq     ymm8, ymm8, ymm15       
  vpmuludq     ymm9, ymm9, ymm15        
  vpmuludq     ymm10, ymm10, ymm15       
  vpmuludq     ymm11, ymm11, ymm15       
  vpaddq       ymm0, ymm0, ymm8                   
  vpaddq       ymm2, ymm2, ymm9                   
  vpaddq       ymm4, ymm4, ymm10                   
  vpaddq       ymm6, ymm6, ymm11                   
  vpsrlq       ymm0, ymm0, 32 
  vpsrlq       ymm2, ymm2, 32  
  vpsrlq       ymm4, ymm4, 32  
  vpsrlq       ymm6, ymm6, 32
//************************************************************************ END OF POINTWISE MULTIPLICATION

// Inverse NTT                          
// Round 1   
  lea          r9, [reg_p3+8*rax+2048]                // Load twiddle factor W         
  vpsubd       ymm8, ymm1, ymm0                       // temp - a[j+k]
  vpsubd       ymm9, ymm3, ymm2
  vpsubd       ymm10, ymm5, ymm4
  vpsubd       ymm11, ymm7, ymm6
  vpaddd       ymm1, ymm1, ymm0                       // a[j] = temp + a[j+k] 
  vpaddd       ymm3, ymm3, ymm2                  
  vpaddd       ymm5, ymm5, ymm4                    
  vpaddd       ymm7, ymm7, ymm6                   
  vpmovzxdq    ymm0, XMMWORD PTR [r9+8*rax]
  vpmovzxdq    ymm2, XMMWORD PTR [r9+8*rax+16]
  vpmovzxdq    ymm4, XMMWORD PTR [r9+8*rax+32]
  vpmovzxdq    ymm6, XMMWORD PTR [r9+8*rax+48]  
  vpmuldq      ymm0, ymm0, ymm8                       // W.(temp - a[j+k])  
  vpmuldq      ymm2, ymm2, ymm9 
  vpmuldq      ymm4, ymm4, ymm10 
  vpmuldq      ymm6, ymm6, ymm11       
  vpmuldq      ymm8, ymm0, ymm14                      // temp = reduce(W.X)
  vpmuldq      ymm9, ymm2, ymm14                    
  vpmuldq      ymm10, ymm4, ymm14                   
  vpmuldq      ymm11, ymm6, ymm14  
  vpmuludq     ymm8, ymm8, ymm15                   
  vpmuludq     ymm9, ymm9, ymm15                   
  vpmuludq     ymm10, ymm10, ymm15                   
  vpmuludq     ymm11, ymm11, ymm15     
  vpaddq       ymm0, ymm0, ymm8                                   
  vpaddq       ymm2, ymm2, ymm9                     
  vpaddq       ymm4, ymm4, ymm10                   
  vpaddq       ymm6, ymm6, ymm11
  vpsrlq       ymm0, ymm0, 32                         // a[j+k]                    
  vpsrlq       ymm2, ymm2, 32                       
  vpsrlq       ymm4, ymm4, 32                   
  vpsrlq       ymm6, ymm6, 32   
  
// Round 2
  vpshufd      ymm8, ymm1, 0xC6
  vpshufd      ymm9, ymm0, 0xC6
  vpshufd      ymm10, ymm3, 0xC6
  vpshufd      ymm11, ymm2, 0xC6
  vpblendd     ymm1, ymm1, ymm9, 0xCC
  vpblendd     ymm8, ymm8, ymm0, 0xCC
  vpblendd     ymm3, ymm3, ymm11, 0xCC
  vpblendd     ymm9, ymm10, ymm2, 0xCC
  vpshufd      ymm0, ymm5, 0xC6
  vpshufd      ymm10, ymm4, 0xC6
  vpshufd      ymm2, ymm7, 0xC6
  vpshufd      ymm11, ymm6, 0xC6
  vpblendd     ymm5, ymm5, ymm10, 0xCC
  vpblendd     ymm10, ymm0, ymm4, 0xCC
  vpblendd     ymm7, ymm7, ymm11, 0xCC
  vpblendd     ymm11, ymm2, ymm6, 0xCC  
  vpaddd       ymm0, ymm1, ymm8                       // a[j] = temp + a[j+k] 
  vpaddd       ymm2, ymm3, ymm9                  
  vpaddd       ymm4, ymm5, ymm10                    
  vpaddd       ymm6, ymm7, ymm11                   
  vpsubd       ymm1, ymm1, ymm8                       // temp - a[j+k]
  vpsubd       ymm3, ymm3, ymm9
  vpsubd       ymm5, ymm5, ymm10
  vpsubd       ymm7, ymm7, ymm11       
  vbroadcastss ymm8, DWORD PTR [reg_p3+8*rax+2048+1024]    // Load twiddle factor W     
  vbroadcastss ymm10, DWORD PTR [reg_p3+8*rax+2048+1028]  
  vbroadcastss ymm9, DWORD PTR [reg_p3+8*rax+2048+1032]    
  vbroadcastss ymm11, DWORD PTR [reg_p3+8*rax+2048+1036] 
  vbroadcastss ymm12, DWORD PTR [reg_p3+8*rax+2048+1040] 
  vbroadcastss ymm13, DWORD PTR [reg_p3+8*rax+2048+1044]   
  vpblendd     ymm8, ymm8, ymm10, 0xF0
  vpblendd     ymm9, ymm9, ymm11, 0xF0
  vbroadcastss ymm11, DWORD PTR [reg_p3+8*rax+2048+1048]   
  vpblendd     ymm10, ymm12, ymm13, 0xF0      
  vbroadcastss ymm12, DWORD PTR [reg_p3+8*rax+2048+1052] 
  vpblendd     ymm11, ymm11, ymm12, 0xF0  
  vpmuldq      ymm1, ymm1, ymm8                       // W.(temp - a[j+k])  
  vpmuldq      ymm3, ymm3, ymm9 
  vpmuldq      ymm5, ymm5, ymm10 
  vpmuldq      ymm7, ymm7, ymm11        
  vpmuldq      ymm8, ymm1, ymm14                      // temp = reduce(W.X)
  vpmuldq      ymm9, ymm3, ymm14                    
  vpmuldq      ymm10, ymm5, ymm14                   
  vpmuldq      ymm11, ymm7, ymm14  
  vpmuludq     ymm8, ymm8, ymm15                   
  vpmuludq     ymm9, ymm9, ymm15                   
  vpmuludq     ymm10, ymm10, ymm15                   
  vpmuludq     ymm11, ymm11, ymm15     
  vpaddq       ymm1, ymm1, ymm8                                   
  vpaddq       ymm3, ymm3, ymm9                     
  vpaddq       ymm5, ymm5, ymm10                   
  vpaddq       ymm7, ymm7, ymm11
  vpsrlq       ymm1, ymm1, 32                                        
  vpsrlq       ymm3, ymm3, 32                       
  vpsrlq       ymm5, ymm5, 32                   
  vpsrlq       ymm7, ymm7, 32   
  
// Round 3
  vperm2i128   ymm12, ymm0, ymm1, 0x20              
  vperm2i128   ymm0, ymm0, ymm1, 0x31                
  vperm2i128   ymm1, ymm2, ymm3, 0x20
  vperm2i128   ymm2, ymm2, ymm3, 0x31
  vperm2i128   ymm3, ymm4, ymm5, 0x20
  vperm2i128   ymm4, ymm4, ymm5, 0x31
  vperm2i128   ymm5, ymm6, ymm7, 0x20
  vperm2i128   ymm6, ymm6, ymm7, 0x31  
  vpsubd       ymm8, ymm12, ymm0                      // temp - a[j+k]
  vpsubd       ymm9, ymm1, ymm2
  vpsubd       ymm10, ymm3, ymm4
  vpsubd       ymm11, ymm5, ymm6  
  vpaddd       ymm12, ymm12, ymm0                     // a[j] = temp + a[j+k] 
  vpaddd       ymm1, ymm1, ymm2                  
  vpaddd       ymm3, ymm3, ymm4                   
  vpaddd       ymm5, ymm5, ymm6                     
  vbroadcastss ymm0, DWORD PTR [reg_p3+4*rax+2048+1536]    // Load twiddle factor W     
  vbroadcastss ymm2, DWORD PTR [reg_p3+4*rax+2048+1540]   
  vbroadcastss ymm4, DWORD PTR [reg_p3+4*rax+2048+1544]         
  vbroadcastss ymm6, DWORD PTR [reg_p3+4*rax+2048+1548]  
  vpmuldq      ymm0, ymm0, ymm8                       // W.(temp - a[j+k])  
  vpmuldq      ymm2, ymm2, ymm9 
  vpmuldq      ymm4, ymm4, ymm10 
  vpmuldq      ymm6, ymm6, ymm11        
  vpmuldq      ymm8, ymm0, ymm14                      // temp = reduce(W.X)
  vpmuldq      ymm9, ymm2, ymm14                    
  vpmuldq      ymm10, ymm4, ymm14                   
  vpmuldq      ymm11, ymm6, ymm14  
  vpmuludq     ymm8, ymm8, ymm15                   
  vpmuludq     ymm9, ymm9, ymm15                   
  vpmuludq     ymm10, ymm10, ymm15                   
  vpmuludq     ymm11, ymm11, ymm15     
  vpaddq       ymm0, ymm0, ymm8                                  
  vpaddq       ymm2, ymm2, ymm9                     
  vpaddq       ymm4, ymm4, ymm10                   
  vpaddq       ymm6, ymm6, ymm11
  vpsrlq       ymm0, ymm0, 32                                       
  vpsrlq       ymm2, ymm2, 32                       
  vpsrlq       ymm4, ymm4, 32                   
  vpsrlq       ymm6, ymm6, 32   
  
// Round 4  
  vpsubd       ymm8, ymm12, ymm1                      // temp - a[j+k]
  vpsubd       ymm9, ymm0, ymm2
  vpsubd       ymm10, ymm3, ymm5
  vpsubd       ymm11, ymm4, ymm6 
  vpaddd       ymm12, ymm12, ymm1                     // a[j] = temp + a[j+k] 
  vpaddd       ymm0, ymm0, ymm2                  
  vpaddd       ymm3, ymm3, ymm5                   
  vpaddd       ymm4, ymm4, ymm6                   
  vbroadcastss ymm2, DWORD PTR [reg_p3+2*rax+2048+1792]   // Load twiddle factor W     
  vbroadcastss ymm6, DWORD PTR [reg_p3+2*rax+2048+1796]  
  vpmuldq      ymm1, ymm8, ymm2                      // W.(temp - a[j+k])  
  vpmuldq      ymm2, ymm9, ymm2
  vpmuldq      ymm5, ymm10, ymm6
  vpmuldq      ymm6, ymm11, ymm6       
  vpmuldq      ymm8, ymm1, ymm14                      // temp = reduce(W.X)
  vpmuldq      ymm9, ymm2, ymm14                    
  vpmuldq      ymm10, ymm5, ymm14                   
  vpmuldq      ymm11, ymm6, ymm14  
  vpmuludq     ymm8, ymm8, ymm15                   
  vpmuludq     ymm9, ymm9, ymm15                   
  vpmuludq     ymm10, ymm10, ymm15                   
  vpmuludq     ymm11, ymm11, ymm15     
  vpaddq       ymm1, ymm1, ymm8                                  
  vpaddq       ymm2, ymm2, ymm9                     
  vpaddq       ymm5, ymm5, ymm10                   
  vpaddq       ymm6, ymm6, ymm11
  vpsrlq       ymm1, ymm1, 32                                       
  vpsrlq       ymm2, ymm2, 32                       
  vpsrlq       ymm5, ymm5, 32                   
  vpsrlq       ymm6, ymm6, 32   
  
// Round 5  
  vbroadcastss ymm7, DWORD PTR [reg_p3+rax+2048+1920]      // Load twiddle factor W     
  vpsubd       ymm8, ymm12, ymm3                       // temp - a[j+k]
  vpsubd       ymm9, ymm0, ymm4
  vpsubd       ymm10, ymm1, ymm5
  vpsubd       ymm11, ymm2, ymm6
  vpaddd       ymm12, ymm12, ymm3                     // a[j] = temp + a[j+k] 
  vpaddd       ymm0, ymm0, ymm4                  
  vpaddd       ymm1, ymm1, ymm5                   
  vpaddd       ymm2, ymm2, ymm6 
  vpmuldq      ymm3, ymm8, ymm7                       // W.(temp - a[j+k])  
  vpmuldq      ymm4, ymm9, ymm7
  vpmuldq      ymm5, ymm10, ymm7 
  vpmuldq      ymm6, ymm11, ymm7        
  vpmuldq      ymm8, ymm3, ymm14                      // temp = reduce(W.X)
  vpmuldq      ymm9, ymm4, ymm14                    
  vpmuldq      ymm10, ymm5, ymm14                   
  vpmuldq      ymm11, ymm6, ymm14  
  vpmuludq     ymm8, ymm8, ymm15                   
  vpmuludq     ymm9, ymm9, ymm15                   
  vpmuludq     ymm10, ymm10, ymm15                   
  vpmuludq     ymm11, ymm11, ymm15     
  vpaddq       ymm3, ymm3, ymm8                                
  vpaddq       ymm4, ymm4, ymm9                     
  vpaddq       ymm5, ymm5, ymm10                   
  vpaddq       ymm6, ymm6, ymm11
  vpsrlq       ymm3, ymm3, 32                                    
  vpsrlq       ymm4, ymm4, 32                       
  vpsrlq       ymm5, ymm5, 32                   
  vpsrlq       ymm6, ymm6, 32
  vmovdqa      [reg_p4+r11], ymm12                    // Store in temporary storage
  vmovdqa      [reg_p4+r11+32], ymm0
  vmovdqa      [reg_p4+r11+64], ymm1
  vmovdqa      [reg_p4+r11+96], ymm2
  vmovdqa      [reg_p4+r11+128], ymm3                      
  vmovdqa      [reg_p4+r11+160], ymm4
  vmovdqa      [reg_p4+r11+192], ymm5
  vmovdqa      [reg_p4+r11+224], ymm6
  add          rax, 4
  add          r11, 256
  add          reg_p5, 128 
  dec          r10
  jnz          loop_ntt_intt  
                                                    
  xor          r11, r11 
  xor          rax, rax
round6_loop:
  vbroadcastss ymm9, DWORD PTR [reg_p3+rax+2048+1984]      // Load twiddle factor W
  vbroadcastss ymm10, DWORD PTR [reg_p3+rax+2048+1988]                   
  vbroadcastss ymm11, DWORD PTR [reg_p3+rax+2048+1992]         
  vbroadcastss ymm12, DWORD PTR [reg_p3+rax+2048+1996] 
  mov          r10, 8                                
loop_intt6:
// Round 6 
  vmovdqa      ymm0, YMMWORD PTR [reg_p4+r11]         // a[j]   
  vmovdqa      ymm4, YMMWORD PTR [reg_p4+r11+256]      
  vmovdqa      ymm1, YMMWORD PTR [reg_p4+r11+512]     
  vmovdqa      ymm5, YMMWORD PTR [reg_p4+r11+768] 
  vmovdqa      ymm2, YMMWORD PTR [reg_p4+r11+1024]    // a[j+k] 
  vmovdqa      ymm6, YMMWORD PTR [reg_p4+r11+1280] 
  vmovdqa      ymm3, YMMWORD PTR [reg_p4+r11+1536] 
  vmovdqa      ymm7, YMMWORD PTR [reg_p4+r11+1792]
  vpsubd       ymm8, ymm0, ymm4                       // temp - a[j+k]
  vpaddd       ymm0, ymm0, ymm4                       // a[j] = temp + a[j+k] 
  vpmuldq      ymm4, ymm8, ymm9                       // W.(temp - a[j+k]) 
  vpmuldq      ymm8, ymm4, ymm14                      // temp = reduce(W.X) 
  vpmuludq     ymm8, ymm8, ymm15 
  vpaddq       ymm4, ymm4, ymm8                    
  vpsrlq       ymm4, ymm4, 32                                
  
  vpsubd       ymm8, ymm1, ymm5
  vpaddd       ymm1, ymm1, ymm5                  
  vpmuldq      ymm5, ymm8, ymm10
  vpmuldq      ymm8, ymm5, ymm14                    
  vpmuludq     ymm8, ymm8, ymm15  
  vpaddq       ymm5, ymm5, ymm8                     
  vpsrlq       ymm5, ymm5, 32                       
  
  vpsubd       ymm8, ymm2, ymm6
  vpaddd       ymm2, ymm2, ymm6                    
  vpmuldq      ymm6, ymm8, ymm11
  vpmuldq      ymm8, ymm6, ymm14    
  vpmuludq     ymm8, ymm8, ymm15 
  vpaddq       ymm6, ymm6, ymm8 
  vpsrlq       ymm6, ymm6, 32     
  
  vpsubd       ymm8, ymm3, ymm7  
  vpaddd       ymm3, ymm3, ymm7                   
  vpmuldq      ymm7, ymm8, ymm12                         
  vpmuldq      ymm8, ymm7, ymm14                                                   
  vpmuludq     ymm8, ymm8, ymm15                                  
  vpaddq       ymm7, ymm7, ymm8                              
  vpsrlq       ymm7, ymm7, 32
  vmovdqa      [reg_p4+r11], ymm0                     // Store in temporary storage
  vmovdqa      [reg_p4+r11+256], ymm4
  vmovdqa      [reg_p4+r11+512], ymm1
  vmovdqa      [reg_p4+r11+768], ymm5
  vmovdqa      [reg_p4+r11+1024], ymm2
  vmovdqa      [reg_p4+r11+1280], ymm6
  vmovdqa      [reg_p4+r11+1536], ymm3
  vmovdqa      [reg_p4+r11+1792], ymm7
  add          r11, 32
  dec          r10
  jnz          loop_intt6  
  add          rax, 16 
  mov          r11, 2048
  cmp          rax, 32
  jne          round6_loop
    
  xor          rax, rax
  xor          r11, r11
  vmovdqa      ymm12, YMMWORD PTR [PERM_MASK+rip]
  mov          r10, 16                               
loop_intt789:
// Round 7
  vmovdqa      ymm0, YMMWORD PTR [reg_p4+r11]         // a[j]   
  vmovdqa      ymm4, YMMWORD PTR [reg_p4+r11+512]       
  vmovdqa      ymm1, YMMWORD PTR [reg_p4+r11+1024]       
  vmovdqa      ymm5, YMMWORD PTR [reg_p4+r11+1536] 
  vmovdqa      ymm2, YMMWORD PTR [reg_p4+r11+2048]    // a[j+k] 
  vmovdqa      ymm6, YMMWORD PTR [reg_p4+r11+2560] 
  vmovdqa      ymm3, YMMWORD PTR [reg_p4+r11+3072] 
  vmovdqa      ymm7, YMMWORD PTR [reg_p4+r11+3584]  
  vpsubd       ymm8, ymm0, ymm4                       // temp - a[j+k]
  vpsubd       ymm9, ymm1, ymm5
  vpsubd       ymm10, ymm2, ymm6
  vpsubd       ymm11, ymm3, ymm7
  vpaddd       ymm0, ymm0, ymm4                       // a[j] = temp + a[j+k] 
  vpaddd       ymm1, ymm1, ymm5                  
  vpaddd       ymm2, ymm2, ymm6                    
  vpaddd       ymm3, ymm3, ymm7
  vbroadcastss ymm4, DWORD PTR [reg_p3+2048+2016]     // Load twiddle factor W     
  vbroadcastss ymm5, DWORD PTR [reg_p3+2048+2020]                   
  vbroadcastss ymm6, DWORD PTR [reg_p3+2048+2024]         
  vbroadcastss ymm7, DWORD PTR [reg_p3+2048+2028]  
  vpmuldq      ymm4, ymm4, ymm8                       // W.(temp - a[j+k])  
  vpmuldq      ymm5, ymm5, ymm9
  vpmuldq      ymm6, ymm6, ymm10 
  vpmuldq      ymm7, ymm7, ymm11        
  vpmuldq      ymm8, ymm4, ymm14                      // temp = reduce(W.X)
  vpmuldq      ymm9, ymm5, ymm14                    
  vpmuldq      ymm10, ymm6, ymm14                   
  vpmuldq      ymm11, ymm7, ymm14  
  vpmuludq     ymm8, ymm8, ymm15                   
  vpmuludq     ymm9, ymm9, ymm15                   
  vpmuludq     ymm10, ymm10, ymm15                   
  vpmuludq     ymm11, ymm11, ymm15     
  vpaddq       ymm4, ymm4, ymm8                                   
  vpaddq       ymm5, ymm5, ymm9                     
  vpaddq       ymm6, ymm6, ymm10                   
  vpaddq       ymm7, ymm7, ymm11
  vpsrlq       ymm4, ymm4, 32                                       
  vpsrlq       ymm5, ymm5, 32                       
  vpsrlq       ymm6, ymm6, 32                   
  vpsrlq       ymm7, ymm7, 32
    
// Round 8   
  vpsubd       ymm8, ymm0, ymm1                       // temp - a[j+k]
  vpsubd       ymm9, ymm4, ymm5
  vpsubd       ymm10, ymm2, ymm3
  vpsubd       ymm11, ymm6, ymm7
  vpaddd       ymm0, ymm0, ymm1                       // a[j] = temp + a[j+k] 
  vpaddd       ymm4, ymm4, ymm5                  
  vpaddd       ymm2, ymm2, ymm3                    
  vpaddd       ymm6, ymm6, ymm7
  vbroadcastss ymm5, DWORD PTR [reg_p3+2048+2032]     // Load twiddle factor W
  vbroadcastss ymm7, DWORD PTR [reg_p3+2048+2036]                   
  vpmuldq      ymm1, ymm8, ymm5                       // W.(temp - a[j+k])  
  vpmuldq      ymm5, ymm9, ymm5
  vpmuldq      ymm3, ymm10, ymm7 
  vpmuldq      ymm7, ymm11, ymm7        
  vpmuldq      ymm8, ymm1, ymm14                      // temp = reduce(W.X)
  vpmuldq      ymm9, ymm5, ymm14                    
  vpmuldq      ymm10, ymm3, ymm14                   
  vpmuldq      ymm11, ymm7, ymm14  
  vpmuludq     ymm8, ymm8, ymm15                   
  vpmuludq     ymm9, ymm9, ymm15                   
  vpmuludq     ymm10, ymm10, ymm15                   
  vpmuludq     ymm11, ymm11, ymm15     
  vpaddq       ymm1, ymm1, ymm8                                   
  vpaddq       ymm5, ymm5, ymm9                     
  vpaddq       ymm3, ymm3, ymm10                   
  vpaddq       ymm7, ymm7, ymm11
  vpsrlq       ymm1, ymm1, 32                                       
  vpsrlq       ymm5, ymm5, 32                       
  vpsrlq       ymm3, ymm3, 32                   
  vpsrlq       ymm7, ymm7, 32
    
// Round 9   
  vbroadcastss ymm13, DWORD PTR [reg_p3+2048+2040]    // Load twiddle factor W
  vpsubd       ymm8, ymm0, ymm2                       // temp - a[j+k]
  vpsubd       ymm9, ymm4, ymm6
  vpsubd       ymm10, ymm1, ymm3
  vpsubd       ymm11, ymm5, ymm7
  vpaddd       ymm0, ymm0, ymm2                       // a[j] = temp + a[j+k] 
  vpaddd       ymm4, ymm4, ymm6                  
  vpaddd       ymm1, ymm1, ymm3                    
  vpaddd       ymm5, ymm5, ymm7
  vpmuldq      ymm2, ymm8, ymm13                      // W.(temp - a[j+k])  
  vpmuldq      ymm6, ymm9, ymm13
  vpmuldq      ymm3, ymm10, ymm13 
  vpmuldq      ymm7, ymm11, ymm13        
  vpmuldq      ymm8, ymm2, ymm14                      // temp = reduce(W.X)
  vpmuldq      ymm9, ymm6, ymm14                    
  vpmuldq      ymm10, ymm3, ymm14                   
  vpmuldq      ymm11, ymm7, ymm14  
  vpmuludq     ymm8, ymm8, ymm15                   
  vpmuludq     ymm9, ymm9, ymm15                   
  vpmuludq     ymm10, ymm10, ymm15                   
  vpmuludq     ymm11, ymm11, ymm15     
  vpaddq       ymm2, ymm2, ymm8                                
  vpaddq       ymm6, ymm6, ymm9                     
  vpaddq       ymm3, ymm3, ymm10                   
  vpaddq       ymm7, ymm7, ymm11
  vmovdqa      ymm8, YMMWORD PTR [PARAM_Rx4+rip]      // Loading PARAM_R                        
  vpermd       ymm2, ymm12, ymm2
  vpermd       ymm6, ymm12, ymm6
  vpermd       ymm3, ymm12, ymm3
  vpermd       ymm7, ymm12, ymm7
   
  vpmuldq      ymm0, ymm0, ymm8                       // a[j].PARAM_R  
  vpmuldq      ymm4, ymm4, ymm8
  vpmuldq      ymm1, ymm1, ymm8 
  vpmuldq      ymm5, ymm5, ymm8        
  vpmuldq      ymm8, ymm0, ymm14                      // reduce(a[j].PARAM_R)
  vpmuldq      ymm9, ymm4, ymm14                    
  vpmuldq      ymm10, ymm1, ymm14                   
  vpmuldq      ymm11, ymm5, ymm14  
  vpmuludq     ymm8, ymm8, ymm15                   
  vpmuludq     ymm9, ymm9, ymm15                   
  vpmuludq     ymm10, ymm10, ymm15                   
  vpmuludq     ymm11, ymm11, ymm15     
  vpaddq       ymm0, ymm0, ymm8                                   
  vpaddq       ymm4, ymm4, ymm9                     
  vpaddq       ymm1, ymm1, ymm10                   
  vpaddq       ymm5, ymm5, ymm11          
  vpermd       ymm0, ymm12, ymm0
  vpermd       ymm4, ymm12, ymm4
  vpermd       ymm1, ymm12, ymm1
  vpermd       ymm5, ymm12, ymm5
  vmovdqa      XMMWORD PTR [reg_p1+rax+1024], xmm2    // Store result
  vmovdqa      XMMWORD PTR [reg_p1+rax+1280], xmm6
  vmovdqa      XMMWORD PTR [reg_p1+rax+1536], xmm3
  vmovdqa      XMMWORD PTR [reg_p1+rax+1792], xmm7
  vmovdqa      XMMWORD PTR [reg_p1+rax], xmm0
  vmovdqa      XMMWORD PTR [reg_p1+rax+256], xmm4
  vmovdqa      XMMWORD PTR [reg_p1+rax+512], xmm1
  vmovdqa      XMMWORD PTR [reg_p1+rax+768], xmm5
  add          r11, 32
  add          rax, 16  
  dec          r10
  jnz          loop_intt789
ret