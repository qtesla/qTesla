//************************************************************************************
// qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
//
// Abstract: optimized polynomial sparse multiplication written in x64 assembly 
//           with AVX2 support for Linux 
//************************************************************************************

.intel_syntax noprefix 

// Registers that are used for parameter passing:
#define reg_p1  rdi
#define reg_p2  rsi
#define reg_p3  rdx
#define reg_p4  rcx
#define reg_p5  r8


.text
//***************************************************************************
//  Polynomial sparse multiplication 
//  Operation: c [reg_p1] = a [reg_p2] * b

//  b is a sparse polynomial defined by: 
//             pos_list [reg_p3]: list of indices of nonzero elements in b
//             sign_list [reg_p4]: list of signs of nonzero elements in b
//***************************************************************************
  .global sparse_mul16_asm
  sparse_mul16_asm:
  push         r12 
  push         r13 
  push         r14 
  push         r15  
  sub          rsp, 2
  mov          r15, QWORD PTR [H+rip]     // Loading PARAM_H 
  vmovdqa      ymm0, YMMWORD PTR [ZEROS+rip] 
  xor          rax, rax
first_loop:
  vmovdqa      YMMWORD PTR [reg_p1+rax], ymm0
  vmovdqa      YMMWORD PTR [reg_p1+rax+32], ymm0
  vmovdqa      YMMWORD PTR [reg_p1+rax+64], ymm0
  vmovdqa      YMMWORD PTR [reg_p1+rax+96], ymm0
  add          rax, 128
  cmp          rax, [Nx4+rip]
  jne          first_loop

outer_loop:
  xor          r8, r8
  xor          r10, r10
  xor          r9, r9
  mov          r8d, DWORD PTR [reg_p3]    // pos
  mov          r10w, WORD PTR [reg_p4]    // sign
  mov          rax, [N+rip]
  sub          rax, r8                    // N-pos
  shl          rax, 1                     // #bytes(N-pos)
  sar          r10w, 15                   // First mask:  1 -> 0...000, -1 -> 1...111
  mov          r11, r10
  not          r11w                       // Second mask: 1 -> 1...111, -1 -> 0...000 
  mov          WORD PTR [rsp], r10w
  vpbroadcastw ymm14, WORD PTR [rsp] 
  mov          WORD PTR [rsp], r11w
  vpbroadcastw ymm15, WORD PTR [rsp] 
  cmp          r8, 31
  jle          parallel1b
    
// Parallel section 
parallel1a:  
  vmovdqu      ymm1, YMMWORD PTR [reg_p2+rax] 
  vmovdqu      ymm6, YMMWORD PTR [reg_p2+rax+32] 
  vmovdqu      ymm0, YMMWORD PTR [reg_p1+r9]  
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+r9+32]  
  vpand        ymm3, ymm1, ymm14    
  vpand        ymm7, ymm6, ymm14    
  vpand        ymm4, ymm1, ymm15      
  vpand        ymm8, ymm6, ymm15            
  vpaddw       ymm0, ymm0, ymm3              
  vpaddw       ymm5, ymm5, ymm7             
  vpsubw       ymm0, ymm0, ymm4             
  vpsubw       ymm5, ymm5, ymm8 
  vmovdqu      YMMWORD PTR [reg_p1+r9], ymm0
  vmovdqu      YMMWORD PTR [reg_p1+r9+32], ymm5
  add          rax, 64 
  add          r9, 64
  sub          r8, 32
  cmp          r8, 31
  jg           parallel1a
parallel1b:  
  cmp          r8, 15
  jle          serial1
parallel_loop1b:
  vmovdqu      ymm1, YMMWORD PTR [reg_p2+rax] 
  vmovdqu      ymm0, YMMWORD PTR [reg_p1+r9]  
  vpand        ymm3, ymm1, ymm14   
  vpand        ymm4, ymm1, ymm15              
  vpaddw       ymm0, ymm0, ymm3              
  vpsubw       ymm0, ymm0, ymm4 
  vmovdqu      YMMWORD PTR [reg_p1+r9], ymm0
  add          rax, 32 
  add          r9, 32
  sub          r8, 16
  cmp          r8, 15
  jg           parallel_loop1b

// Serial section
serial1:
  cmp          r8, 0
  je           stage2
serial_loop1:
  mov          r13w, WORD PTR [reg_p2+rax]
  mov          r12w, WORD PTR [reg_p1+r9]
  mov          r14w, r13w
  and          r13w, r10w
  and          r14w, r11w
  add          r12w, r13w
  sub          r12w, r14w
  mov          WORD PTR [reg_p1+r9], r12w 
  add          rax, 2 
  add          r9, 2
  dec          r8
  jnz          serial_loop1

stage2:
  xor          rax, rax
  mov          r8, [N+rip]
  sub          r8d, DWORD PTR [reg_p3]    // N-pos
    
// Parallel section 
parallel2a: 
  cmp          r8, 31
  jle          parallel2b 
parallel_loop2a:  
  vmovdqu      ymm1, YMMWORD PTR [reg_p2+rax] 
  vmovdqu      ymm6, YMMWORD PTR [reg_p2+rax+32] 
  vmovdqu      ymm0, YMMWORD PTR [reg_p1+r9]  
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+r9+32]  
  vpand        ymm3, ymm1, ymm14    
  vpand        ymm7, ymm6, ymm14    
  vpand        ymm4, ymm1, ymm15      
  vpand        ymm8, ymm6, ymm15            
  vpsubw       ymm0, ymm0, ymm3              
  vpsubw       ymm5, ymm5, ymm7             
  vpaddw       ymm0, ymm0, ymm4             
  vpaddw       ymm5, ymm5, ymm8 
  vmovdqu      YMMWORD PTR [reg_p1+r9], ymm0
  vmovdqu      YMMWORD PTR [reg_p1+r9+32], ymm5
  add          rax, 64 
  add          r9, 64
  sub          r8, 32
  cmp          r8, 31
  jg           parallel2a
parallel2b:  
  cmp          r8, 15
  jle          serial2
parallel_loop2b:
  vmovdqu      ymm1, YMMWORD PTR [reg_p2+rax] 
  vmovdqu      ymm0, YMMWORD PTR [reg_p1+r9]  
  vpand        ymm3, ymm1, ymm14   
  vpand        ymm4, ymm1, ymm15              
  vpsubw       ymm0, ymm0, ymm3              
  vpaddw       ymm0, ymm0, ymm4 
  vmovdqu      YMMWORD PTR [reg_p1+r9], ymm0
  add          rax, 32 
  add          r9, 32
  sub          r8, 16
  cmp          r8, 15
  jg           parallel_loop2b

// Serial2 section
serial2:
  cmp          r8, 0
  je           out
serial_loop2:
  mov          r13w, WORD PTR [reg_p2+rax]
  mov          r12w, WORD PTR [reg_p1+r9]
  mov          r14w, r13w
  and          r13w, r10w
  and          r14w, r11w
  sub          r12w, r13w
  add          r12w, r14w
  mov          WORD PTR [reg_p1+r9], r12w 
  add          rax, 2 
  add          r9, 2
  dec          r8
  jnz          serial_loop2

out:
  add          reg_p3, 4          // Updating pointer to pos_list
  add          reg_p4, 2          // Updating pointer to sign_list
  dec          r15
  jnz          outer_loop
  
  mov          rax, [N2m64+rip]
  mov          r9, [N4m128+rip]
final_loop:
  vmovdqa      xmm0, XMMWORD PTR [reg_p1+rax]  
  vmovdqa      xmm1, XMMWORD PTR [reg_p1+rax+16]  
  vmovdqa      xmm2, XMMWORD PTR [reg_p1+rax+32]  
  vmovdqa      xmm3, XMMWORD PTR [reg_p1+rax+48]  
  vpmovsxwd    ymm4, xmm0   
  vpmovsxwd    ymm5, xmm1   
  vpmovsxwd    ymm6, xmm2   
  vpmovsxwd    ymm7, xmm3  
  vmovdqa      YMMWORD PTR [reg_p1+r9], ymm4
  vmovdqa      YMMWORD PTR [reg_p1+r9+32], ymm5
  vmovdqa      YMMWORD PTR [reg_p1+r9+64], ymm6
  vmovdqa      YMMWORD PTR [reg_p1+r9+96], ymm7
  sub          rax, 64
  sub          r9, 128
  cmp          r9, 0
  jge          final_loop
  
  add          rsp, 2
  pop          r15
  pop          r14
  pop          r13
  pop          r12
  ret