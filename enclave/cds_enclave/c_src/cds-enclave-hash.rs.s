	.text
	.file	"cds_enclave_hash.3a1fbbbh-cgu.0"
	.section	.rodata.cst32,"aM",@progbits,32
	.p2align	5
.LCPI0_0:
	.quad	0
	.quad	-3
	.quad	-2
	.quad	-1
.LCPI0_1:
	.quad	0
	.quad	-6
	.quad	-5
	.quad	-4
.LCPI0_2:
	.quad	0
	.quad	-9
	.quad	-8
	.quad	-7
.LCPI0_3:
	.quad	0
	.quad	-12
	.quad	-11
	.quad	-10
.LCPI0_4:
	.quad	0
	.quad	-1
	.quad	-1
	.quad	-1
	.section	.text.cds_hash_lookup,"ax",@progbits
	.globl	cds_hash_lookup
	.p2align	4, 0x90
	.type	cds_hash_lookup,@function
cds_hash_lookup:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%r15
	.cfi_def_cfa_offset 24
	pushq	%r14
	.cfi_def_cfa_offset 32
	pushq	%r13
	.cfi_def_cfa_offset 40
	pushq	%r12
	.cfi_def_cfa_offset 48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	subq	$408, %rsp
	.cfi_def_cfa_offset 464
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	%rcx, %r13
	movq	480(%rsp), %r14
	xorl	%ecx, %ecx
	popcntq	%r14, %rcx
	movl	$1, %eax
	cmpq	$1, %rcx
	jne	.LBB0_50
	movq	%r8, %r12
	movq	%rsi, %r8
	tzcntq	%r14, %rsi
	cmpl	$31, %esi
	ja	.LBB0_50
	movq	%r9, %r15
	rdrandq	%rcx
	jae	.LBB0_4
	rdrandq	%rbp
	jb	.LBB0_22
.LBB0_4:
	rdrandq	%rcx
	jae	.LBB0_6
	rdrandq	%rbp
	jb	.LBB0_22
.LBB0_6:
	rdrandq	%rcx
	jae	.LBB0_8
	rdrandq	%rbp
	jb	.LBB0_22
.LBB0_8:
	rdrandq	%rcx
	jae	.LBB0_10
	rdrandq	%rbp
	jb	.LBB0_22
.LBB0_10:
	rdrandq	%rcx
	jae	.LBB0_12
	rdrandq	%rbp
	jb	.LBB0_22
.LBB0_12:
	rdrandq	%rcx
	jae	.LBB0_14
	rdrandq	%rbp
	jb	.LBB0_22
.LBB0_14:
	rdrandq	%rcx
	jae	.LBB0_16
	rdrandq	%rbp
	jb	.LBB0_22
.LBB0_16:
	rdrandq	%rcx
	jae	.LBB0_18
	rdrandq	%rbp
	jb	.LBB0_22
.LBB0_18:
	rdrandq	%rcx
	jae	.LBB0_20
	rdrandq	%rbp
	jb	.LBB0_22
.LBB0_20:
	rdrandq	%rcx
	movl	$2, %eax
	jae	.LBB0_50
	rdrandq	%rbp
	jae	.LBB0_50
.LBB0_22:
	vmovq	%rcx, %xmm0
	vmovq	%rbp, %xmm1
	vpunpcklqdq	%xmm0, %xmm1, %xmm9
	vaeskeygenassist	$1, %xmm9, %xmm0
	vpslldq	$4, %xmm9, %xmm1
	vpxor	%xmm1, %xmm9, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm0, %xmm0
	vpxor	%xmm2, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm10
	vaeskeygenassist	$2, %xmm10, %xmm0
	vpslldq	$4, %xmm10, %xmm1
	vpxor	%xmm1, %xmm10, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm0, %xmm0
	vpxor	%xmm2, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm11
	vaeskeygenassist	$4, %xmm11, %xmm0
	vpslldq	$4, %xmm11, %xmm1
	vpxor	%xmm1, %xmm11, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm0, %xmm0
	vpxor	%xmm2, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm12
	vaeskeygenassist	$8, %xmm12, %xmm0
	vpslldq	$4, %xmm12, %xmm1
	vpxor	%xmm1, %xmm12, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm0, %xmm0
	vpxor	%xmm2, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm13
	vaeskeygenassist	$16, %xmm13, %xmm0
	vpslldq	$4, %xmm13, %xmm1
	vpxor	%xmm1, %xmm13, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm0, %xmm0
	vpxor	%xmm2, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm14
	vaeskeygenassist	$32, %xmm14, %xmm0
	vpslldq	$4, %xmm14, %xmm1
	vpxor	%xmm1, %xmm14, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm0, %xmm0
	vpxor	%xmm2, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm6
	vaeskeygenassist	$64, %xmm6, %xmm0
	vpslldq	$4, %xmm6, %xmm1
	vpxor	%xmm1, %xmm6, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm0, %xmm0
	vpxor	%xmm2, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm7
	vaeskeygenassist	$128, %xmm7, %xmm0
	vpslldq	$4, %xmm7, %xmm1
	vpxor	%xmm1, %xmm7, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm0, %xmm0
	vpxor	%xmm2, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm4
	vaeskeygenassist	$27, %xmm4, %xmm1
	vpslldq	$4, %xmm4, %xmm2
	vpxor	%xmm2, %xmm4, %xmm2
	vpslldq	$4, %xmm2, %xmm3
	vpxor	%xmm3, %xmm2, %xmm2
	vpslldq	$4, %xmm2, %xmm3
	vpshufd	$255, %xmm1, %xmm1
	vpxor	%xmm3, %xmm2, %xmm2
	vpxor	%xmm2, %xmm1, %xmm5
	vaeskeygenassist	$54, %xmm5, %xmm8
	movq	464(%rsp), %rbx
	vpslldq	$4, %xmm5, %xmm3
	vpxor	%xmm3, %xmm5, %xmm3
	vpslldq	$4, %xmm3, %xmm2
	vpxor	%xmm2, %xmm3, %xmm2
	vpslldq	$4, %xmm2, %xmm3
	vpshufd	$255, %xmm8, %xmm8
	vpxor	%xmm3, %xmm2, %xmm2
	vpxor	%xmm2, %xmm8, %xmm3
	vmovdqa	%xmm9, 224(%rsp)
	vmovdqa	%xmm10, 240(%rsp)
	vmovdqa	%xmm11, 256(%rsp)
	vmovdqa	%xmm12, 272(%rsp)
	vmovdqa	%xmm13, 288(%rsp)
	vmovdqa	%xmm14, 304(%rsp)
	vmovdqa	%xmm6, 320(%rsp)
	vmovdqa	%xmm7, 336(%rsp)
	vmovdqa	%xmm4, 352(%rsp)
	vmovdqa	%xmm5, 368(%rsp)
	vmovdqa	%xmm3, 384(%rsp)
	movq	%r14, %rbp
	shlq	$7, %rbp
	testq	%r14, %r14
	movq	%rbp, 64(%rsp)
	je	.LBB0_37
	leaq	(%rbx,%rbp), %r9
	testq	%r15, %r15
	je	.LBB0_29
	vmovdqa	%xmm14, %xmm1
	vmovdqa	%xmm13, 96(%rsp)
	vmovdqa	%xmm12, %xmm0
	vmovdqa	%xmm11, %xmm2
	vmovdqa	%xmm10, 112(%rsp)
	vmovdqa	%xmm9, 128(%rsp)
	movq	%r8, 32(%rsp)
	movq	%rdx, 40(%rsp)
	movq	%r12, 48(%rsp)
	movl	$-1, %eax
	shlxl	%esi, %eax, %ebp
	notl	%ebp
	movq	%r15, 56(%rsp)
	leaq	(,%r15,8), %rax
	xorl	%r10d, %r10d
	xorl	%ecx, %ecx
	movq	%rbx, %r11
	.p2align	4, 0x90
.LBB0_25:
	vmovdqa	%xmm5, 144(%rsp)
	vmovdqa	%xmm7, 160(%rsp)
	vmovdqa	%xmm3, 176(%rsp)
	vmovdqa	%xmm4, 192(%rsp)
	vmovdqa	%xmm6, 208(%rsp)
	leaq	128(%r11), %r8
	vpxor	%xmm11, %xmm11, %xmm11
	xorl	%r15d, %r15d
	vpxor	%xmm12, %xmm12, %xmm12
	vpxor	%xmm13, %xmm13, %xmm13
	vpxor	%xmm14, %xmm14, %xmm14
	movl	$0, %edx
	vmovapd	.LCPI0_3(%rip), %ymm15
	vmovapd	.LCPI0_2(%rip), %ymm8
	vmovapd	.LCPI0_1(%rip), %ymm9
	vmovapd	.LCPI0_0(%rip), %ymm10
	.p2align	4, 0x90
.LBB0_26:
	vpbroadcastq	(%r13,%r15), %ymm3
	vmovq	(%r13,%r15), %xmm4
	vpxor	128(%rsp), %xmm4, %xmm4
	vaesenc	112(%rsp), %xmm4, %xmm4
	vaesenc	%xmm2, %xmm4, %xmm4
	vaesenc	%xmm0, %xmm4, %xmm4
	vaesenc	96(%rsp), %xmm4, %xmm4
	vaesenc	%xmm1, %xmm4, %xmm4
	vaesenc	208(%rsp), %xmm4, %xmm4
	vaesenc	160(%rsp), %xmm4, %xmm4
	vaesenc	192(%rsp), %xmm4, %xmm4
	vaesenc	144(%rsp), %xmm4, %xmm4
	vaesenclast	176(%rsp), %xmm4, %xmm4
	vmovd	%xmm4, %r14d
	vpcmpeqq	%ymm14, %ymm3, %ymm4
	vpcmpeqq	%ymm13, %ymm3, %ymm5
	vpor	%ymm4, %ymm5, %ymm4
	vextracti128	$1, %ymm4, %xmm5
	vpackssdw	%xmm5, %xmm4, %xmm4
	vpcmpeqq	%ymm12, %ymm3, %ymm5
	vextracti128	$1, %ymm5, %xmm6
	vpackssdw	%xmm6, %xmm5, %xmm5
	vpcmpeqq	%ymm11, %ymm3, %ymm6
	vextracti128	$1, %ymm6, %xmm7
	vpackssdw	%xmm7, %xmm6, %xmm6
	vpor	%xmm6, %xmm5, %xmm5
	vpor	%xmm5, %xmm4, %xmm4
	andl	%ebp, %r14d
	xorq	%rcx, %r14
	decq	%r14
	shrq	$32, %r14
	vpmovsxdq	%xmm4, %ymm4
	xorl	%r12d, %r12d
	vtestpd	%ymm4, %ymm4
	sete	%r12b
	vblendvpd	%ymm10, %ymm3, %ymm14, %ymm14
	vblendvpd	%ymm9, %ymm3, %ymm13, %ymm13
	vblendvpd	%ymm8, %ymm3, %ymm12, %ymm12
	andl	%r12d, %r14d
	vblendvpd	%ymm15, %ymm3, %ymm11, %ymm11
	vmovd	%r14d, %xmm3
	vpbroadcastq	%xmm3, %ymm3
	vpaddq	%ymm10, %ymm3, %ymm10
	vpaddq	%ymm9, %ymm3, %ymm9
	vpaddq	%ymm8, %ymm3, %ymm8
	vpaddq	%ymm15, %ymm3, %ymm15
	addl	%r14d, %edx
	addq	$8, %r15
	cmpq	%r15, %rax
	jne	.LBB0_26
	vpcmpeqd	%ymm3, %ymm3, %ymm3
	vblendvpd	%ymm10, %ymm3, %ymm14, %ymm0
	vblendvpd	%ymm9, %ymm3, %ymm13, %ymm1
	vblendvpd	%ymm8, %ymm3, %ymm12, %ymm2
	vblendvpd	%ymm15, %ymm3, %ymm11, %ymm3
	vmovapd	%ymm0, (%r11)
	vmovapd	%ymm1, 32(%r11)
	vmovapd	%ymm2, 64(%r11)
	vmovapd	%ymm3, 96(%r11)
	cmpl	$16, %edx
	seta	%dl
	orb	%dl, %r10b
	cmpq	%r9, %r8
	je	.LBB0_36
	incq	%rcx
	vmovdqa	256(%rsp), %xmm2
	vmovdqa	272(%rsp), %xmm0
	vmovaps	288(%rsp), %xmm1
	vmovaps	%xmm1, 96(%rsp)
	vmovdqa	304(%rsp), %xmm1
	vmovdqa	320(%rsp), %xmm6
	vmovdqa	336(%rsp), %xmm7
	vmovdqa	352(%rsp), %xmm4
	vmovdqa	368(%rsp), %xmm5
	vmovdqa	384(%rsp), %xmm3
	movq	%r8, %r11
	jmp	.LBB0_25
.LBB0_36:
	movl	$3, %eax
	testb	$1, %r10b
	movq	480(%rsp), %r14
	movq	56(%rsp), %r15
	movq	48(%rsp), %r12
	movq	40(%rsp), %rdx
	movq	32(%rsp), %r8
	je	.LBB0_37
.LBB0_50:
	vzeroall
	jmp	.LBB0_51
.LBB0_29:
	leaq	-128(%rbp), %r10
	movl	%r10d, %ecx
	shrl	$7, %ecx
	incl	%ecx
	andq	$7, %rcx
	je	.LBB0_30
	negq	%rcx
	vmovdqa	.LCPI0_4(%rip), %ymm0
	movq	%rbx, %rax
	.p2align	4, 0x90
.LBB0_32:
	vmovdqa	%ymm0, (%rax)
	vmovdqa	%ymm0, 32(%rax)
	vmovdqa	%ymm0, 64(%rax)
	vmovdqa	%ymm0, 96(%rax)
	addq	$128, %rax
	incq	%rcx
	jne	.LBB0_32
	cmpq	$896, %r10
	jae	.LBB0_34
	jmp	.LBB0_37
.LBB0_30:
	movq	%rbx, %rax
	cmpq	$896, %r10
	jb	.LBB0_37
.LBB0_34:
	vmovdqa	.LCPI0_4(%rip), %ymm0
	.p2align	4, 0x90
.LBB0_35:
	vmovdqa	%ymm0, (%rax)
	vmovdqa	%ymm0, 32(%rax)
	vmovdqa	%ymm0, 64(%rax)
	vmovdqa	%ymm0, 96(%rax)
	vmovdqa	%ymm0, 128(%rax)
	vmovdqa	%ymm0, 160(%rax)
	vmovdqa	%ymm0, 192(%rax)
	vmovdqa	%ymm0, 224(%rax)
	vmovdqa	%ymm0, 256(%rax)
	vmovdqa	%ymm0, 288(%rax)
	vmovdqa	%ymm0, 320(%rax)
	vmovdqa	%ymm0, 352(%rax)
	vmovdqa	%ymm0, 384(%rax)
	vmovdqa	%ymm0, 416(%rax)
	vmovdqa	%ymm0, 448(%rax)
	vmovdqa	%ymm0, 480(%rax)
	vmovdqa	%ymm0, 512(%rax)
	vmovdqa	%ymm0, 544(%rax)
	vmovdqa	%ymm0, 576(%rax)
	vmovdqa	%ymm0, 608(%rax)
	vmovdqa	%ymm0, 640(%rax)
	vmovdqa	%ymm0, 672(%rax)
	vmovdqa	%ymm0, 704(%rax)
	vmovdqa	%ymm0, 736(%rax)
	vmovdqa	%ymm0, 768(%rax)
	vmovdqa	%ymm0, 800(%rax)
	vmovdqa	%ymm0, 832(%rax)
	vmovdqa	%ymm0, 864(%rax)
	vmovdqa	%ymm0, 896(%rax)
	vmovdqa	%ymm0, 928(%rax)
	vmovdqa	%ymm0, 960(%rax)
	vmovdqa	%ymm0, 992(%rax)
	addq	$1024, %rax
	cmpq	%r9, %rax
	jne	.LBB0_35
.LBB0_37:
	movq	472(%rsp), %rbp
	movq	%rdi, 72(%rsp)
	movq	%r8, 80(%rsp)
	movq	%rdx, 88(%rsp)
	movq	88(%rsp), %rax
	movq	%rax, 16(%rsp)
	vmovdqu	72(%rsp), %xmm0
	vmovdqu	%xmm0, (%rsp)
	leaq	224(%rsp), %rdi
	movq	%rbx, %rdx
	movq	%r14, %rcx
	movq	%rbp, %r8
	movq	%r14, %r9
	vzeroupper
	callq	*cds_contruct_hash@GOTPCREL(%rip)
	movb	$60, %al
	bzhiq	%rax, %r15, %rax
	cmpq	%r15, %rax
	cmovbq	%rax, %r15
	testq	%r15, %r15
	je	.LBB0_43
	testq	%r14, %r14
	je	.LBB0_47
	xorl	%eax, %eax
	vpxor	%xmm0, %xmm0, %xmm0
	.p2align	4, 0x90
.LBB0_40:
	vpbroadcastq	(%r13,%rax,8), %ymm1
	vpxor	%xmm2, %xmm2, %xmm2
	movl	$96, %ecx
	movq	%r14, %rdx
	.p2align	4, 0x90
.LBB0_41:
	vpblendd	$252, -96(%rbx,%rcx), %ymm0, %ymm3
	vpcmpeqq	%ymm3, %ymm1, %ymm3
	vpblendd	$252, -64(%rbx,%rcx), %ymm0, %ymm4
	vpcmpeqq	%ymm4, %ymm1, %ymm4
	vpblendd	$252, -32(%rbx,%rcx), %ymm0, %ymm5
	vpcmpeqq	%ymm5, %ymm1, %ymm5
	vpblendd	$252, (%rbx,%rcx), %ymm0, %ymm6
	vpcmpeqq	%ymm6, %ymm1, %ymm6
	vpand	-192(%rbp,%rcx,2), %ymm3, %ymm7
	vblendvpd	%ymm4, -128(%rbp,%rcx,2), %ymm7, %ymm7
	vblendvpd	%ymm5, -64(%rbp,%rcx,2), %ymm7, %ymm7
	vblendvpd	%ymm6, (%rbp,%rcx,2), %ymm7, %ymm7
	vpand	-160(%rbp,%rcx,2), %ymm3, %ymm3
	vblendvpd	%ymm4, -96(%rbp,%rcx,2), %ymm3, %ymm3
	vblendvpd	%ymm5, -32(%rbp,%rcx,2), %ymm3, %ymm3
	vblendvpd	%ymm6, 32(%rbp,%rcx,2), %ymm3, %ymm3
	vunpckhpd	%xmm3, %xmm7, %xmm4
	vorpd	%xmm2, %xmm4, %xmm2
	vunpcklpd	%xmm3, %xmm7, %xmm4
	vorpd	%xmm4, %xmm2, %xmm2
	vextractf128	$1, %ymm3, %xmm3
	vextractf128	$1, %ymm7, %xmm4
	vunpcklpd	%xmm3, %xmm4, %xmm5
	vorpd	%xmm5, %xmm2, %xmm2
	vunpckhpd	%xmm3, %xmm4, %xmm3
	vorpd	%xmm3, %xmm2, %xmm2
	subq	$-128, %rcx
	decq	%rdx
	jne	.LBB0_41
	movq	%rax, %rcx
	shlq	$4, %rcx
	incq	%rax
	vmovupd	%xmm2, (%r12,%rcx)
	cmpq	%r15, %rax
	jb	.LBB0_40
.LBB0_43:
	testq	%r14, %r14
	je	.LBB0_49
	shlq	$8, %r14
	addq	%rbp, %r14
	vpcmpeqd	%ymm0, %ymm0, %ymm0
	.p2align	4, 0x90
.LBB0_45:
	vpxor	(%rbp), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, (%rbp)
	vpxor	32(%rbp), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, 32(%rbp)
	vpxor	64(%rbp), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, 64(%rbp)
	vpxor	96(%rbp), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, 96(%rbp)
	vpxor	128(%rbp), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, 128(%rbp)
	vpxor	160(%rbp), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, 160(%rbp)
	vpxor	192(%rbp), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, 192(%rbp)
	vpxor	224(%rbp), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, 224(%rbp)
	addq	$256, %rbp
	cmpq	%r14, %rbp
	jne	.LBB0_45
	movq	%rbx, %rdi
	xorl	%esi, %esi
	movq	64(%rsp), %rdx
	jmp	.LBB0_48
.LBB0_47:
	shlq	$4, %r15
	movq	%r12, %rdi
	xorl	%esi, %esi
	movq	%r15, %rdx
.LBB0_48:
	vzeroupper
	callq	*memset@GOTPCREL(%rip)
.LBB0_49:
	vzeroall
	xorl	%eax, %eax
.LBB0_51:
	addq	$408, %rsp
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%r12
	.cfi_def_cfa_offset 40
	popq	%r13
	.cfi_def_cfa_offset 32
	popq	%r14
	.cfi_def_cfa_offset 24
	popq	%r15
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end0:
	.size	cds_hash_lookup, .Lfunc_end0-cds_hash_lookup
	.cfi_endproc

	.section	.text.cds_contruct_hash,"ax",@progbits
	.globl	cds_contruct_hash
	.p2align	4, 0x90
	.type	cds_contruct_hash,@function
cds_contruct_hash:
	.cfi_startproc
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%rbx
	.cfi_def_cfa_offset 32
	subq	$176, %rsp
	.cfi_def_cfa_offset 208
	.cfi_offset %rbx, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	lfence
	leaq	208(%rsp), %r9
	movq	224(%rsp), %r10
	lfence
	cmpq	$13, %r10
	jb	.LBB1_1
	movl	$-1, %eax
	lfence
	shlxl	%esi, %eax, %r11d
	notl	%r11d
	vmovaps	(%rdi), %xmm0
	vmovaps	%xmm0, 32(%rsp)
	vmovaps	16(%rdi), %xmm0
	vmovaps	%xmm0, 16(%rsp)
	vmovaps	32(%rdi), %xmm0
	vmovaps	%xmm0, 128(%rsp)
	vmovaps	48(%rdi), %xmm0
	vmovaps	%xmm0, 160(%rsp)
	vmovaps	64(%rdi), %xmm0
	vmovaps	%xmm0, (%rsp)
	vmovaps	80(%rdi), %xmm0
	vmovaps	%xmm0, 112(%rsp)
	vmovaps	96(%rdi), %xmm0
	vmovaps	%xmm0, 144(%rsp)
	vmovaps	112(%rdi), %xmm0
	vmovaps	%xmm0, 96(%rsp)
	vmovaps	128(%rdi), %xmm0
	vmovaps	%xmm0, 80(%rsp)
	vmovaps	144(%rdi), %xmm0
	vmovaps	%xmm0, 48(%rsp)
	vmovdqa	160(%rdi), %xmm0
	vmovdqa	%xmm0, 64(%rsp)
	movq	(%r9), %r14
	movq	8(%r9), %r15
	xorl	%eax, %eax
	movq	$-1, %rbx
	vmovq	%rbx, %xmm11
	.p2align	4, 0x90
.LBB1_7:
	prefetchnta	64(%r14,%rax,8)
	prefetchnta	128(%r15)
	prefetchnta	160(%r15)
	vpbroadcastq	(%r14,%rax,8), %ymm12
	vpor	%ymm11, %ymm12, %ymm12
	vmovq	(%r14,%rax,8), %xmm3
	vmovdqa	32(%rsp), %xmm0
	vpxor	%xmm3, %xmm0, %xmm3
	vmovdqa	%xmm0, %xmm13
	vaesenc	16(%rsp), %xmm3, %xmm3
	vmovdqa	128(%rsp), %xmm6
	vaesenc	%xmm6, %xmm3, %xmm3
	vmovdqa	160(%rsp), %xmm0
	vaesenc	%xmm0, %xmm3, %xmm3
	vmovdqa	%xmm0, %xmm7
	vaesenc	(%rsp), %xmm3, %xmm3
	vaesenc	112(%rsp), %xmm3, %xmm3
	vmovdqa	144(%rsp), %xmm0
	vaesenc	%xmm0, %xmm3, %xmm3
	vmovdqa	%xmm0, %xmm2
	vaesenc	96(%rsp), %xmm3, %xmm3
	vmovdqa	80(%rsp), %xmm5
	vaesenc	%xmm5, %xmm3, %xmm3
	vmovdqa	48(%rsp), %xmm0
	vaesenc	%xmm0, %xmm3, %xmm3
	vmovdqa	64(%rsp), %xmm1
	vaesenclast	%xmm1, %xmm3, %xmm3
	vmovd	%xmm3, %ebx
	andl	%r11d, %ebx
	movq	%rbx, %rcx
	shlq	$7, %rcx
	vpcmpeqq	(%rdx,%rcx), %ymm12, %ymm3
	vpcmpeqq	32(%rdx,%rcx), %ymm12, %ymm14
	vpcmpeqq	64(%rdx,%rcx), %ymm12, %ymm15
	vpcmpeqq	96(%rdx,%rcx), %ymm12, %ymm12
	vbroadcastsd	(%r15), %ymm8
	vbroadcastsd	8(%r15), %ymm9
	shlq	$8, %rbx
	vpxor	(%r8,%rbx), %ymm11, %ymm10
	vblendvpd	%ymm3, %ymm8, %ymm10, %ymm10
	vmovapd	%ymm10, (%r8,%rbx)
	vpxor	32(%r8,%rbx), %ymm11, %ymm10
	vblendvpd	%ymm3, %ymm9, %ymm10, %ymm3
	vmovapd	%ymm3, 32(%r8,%rbx)
	vpxor	64(%r8,%rbx), %ymm11, %ymm3
	vblendvpd	%ymm14, %ymm8, %ymm3, %ymm3
	vmovapd	%ymm3, 64(%r8,%rbx)
	vpxor	96(%r8,%rbx), %ymm11, %ymm3
	vblendvpd	%ymm14, %ymm9, %ymm3, %ymm3
	vmovapd	%ymm3, 96(%r8,%rbx)
	vpxor	128(%r8,%rbx), %ymm11, %ymm3
	vblendvpd	%ymm15, %ymm8, %ymm3, %ymm3
	vmovapd	%ymm3, 128(%r8,%rbx)
	vpxor	160(%r8,%rbx), %ymm11, %ymm3
	vblendvpd	%ymm15, %ymm9, %ymm3, %ymm3
	vmovapd	%ymm3, 160(%r8,%rbx)
	vpxor	192(%r8,%rbx), %ymm11, %ymm3
	vblendvpd	%ymm12, %ymm8, %ymm3, %ymm3
	vmovapd	%ymm3, 192(%r8,%rbx)
	vpxor	224(%r8,%rbx), %ymm11, %ymm3
	vblendvpd	%ymm12, %ymm9, %ymm3, %ymm3
	vmovapd	%ymm3, 224(%r8,%rbx)
	vpbroadcastq	8(%r14,%rax,8), %ymm3
	vpor	%ymm11, %ymm3, %ymm3
	vmovq	8(%r14,%rax,8), %xmm4
	vpxor	%xmm4, %xmm13, %xmm4
	vaesenc	16(%rsp), %xmm4, %xmm4
	vaesenc	%xmm6, %xmm4, %xmm4
	vaesenc	%xmm7, %xmm4, %xmm4
	vmovdqa	%xmm7, %xmm13
	vmovdqa	(%rsp), %xmm0
	vaesenc	%xmm0, %xmm4, %xmm4
	vmovdqa	112(%rsp), %xmm7
	vaesenc	%xmm7, %xmm4, %xmm4
	vaesenc	%xmm2, %xmm4, %xmm4
	vmovdqa	96(%rsp), %xmm15
	vaesenc	%xmm15, %xmm4, %xmm4
	vaesenc	%xmm5, %xmm4, %xmm4
	vaesenc	48(%rsp), %xmm4, %xmm4
	vaesenclast	%xmm1, %xmm4, %xmm4
	vmovd	%xmm4, %ebx
	andl	%r11d, %ebx
	movq	%rbx, %rcx
	shlq	$7, %rcx
	vpcmpeqq	(%rdx,%rcx), %ymm3, %ymm4
	vpcmpeqq	32(%rdx,%rcx), %ymm3, %ymm8
	vpcmpeqq	64(%rdx,%rcx), %ymm3, %ymm9
	vpcmpeqq	96(%rdx,%rcx), %ymm3, %ymm3
	vbroadcastsd	16(%r15), %ymm10
	vbroadcastsd	24(%r15), %ymm12
	shlq	$8, %rbx
	vpxor	(%r8,%rbx), %ymm11, %ymm14
	vblendvpd	%ymm4, %ymm10, %ymm14, %ymm14
	vmovapd	%ymm14, (%r8,%rbx)
	vpxor	32(%r8,%rbx), %ymm11, %ymm14
	vblendvpd	%ymm4, %ymm12, %ymm14, %ymm4
	vmovapd	%ymm4, 32(%r8,%rbx)
	vpxor	64(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm8, %ymm10, %ymm4, %ymm4
	vmovapd	%ymm4, 64(%r8,%rbx)
	vpxor	96(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm8, %ymm12, %ymm4, %ymm4
	vmovapd	%ymm4, 96(%r8,%rbx)
	vpxor	128(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm9, %ymm10, %ymm4, %ymm4
	vmovapd	%ymm4, 128(%r8,%rbx)
	vpxor	160(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm9, %ymm12, %ymm4, %ymm4
	vmovapd	%ymm4, 160(%r8,%rbx)
	vpxor	192(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm3, %ymm10, %ymm4, %ymm4
	vmovapd	%ymm4, 192(%r8,%rbx)
	vpxor	224(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm3, %ymm12, %ymm4, %ymm3
	vmovapd	%ymm3, 224(%r8,%rbx)
	vpbroadcastq	16(%r14,%rax,8), %ymm3
	vpor	%ymm11, %ymm3, %ymm3
	vmovq	16(%r14,%rax,8), %xmm4
	vpxor	32(%rsp), %xmm4, %xmm4
	vmovdqa	16(%rsp), %xmm5
	vaesenc	%xmm5, %xmm4, %xmm4
	vaesenc	%xmm6, %xmm4, %xmm4
	vaesenc	%xmm13, %xmm4, %xmm4
	vaesenc	%xmm0, %xmm4, %xmm4
	vmovdqa	%xmm7, %xmm1
	vaesenc	%xmm7, %xmm4, %xmm4
	vaesenc	%xmm2, %xmm4, %xmm4
	vmovdqa	%xmm2, %xmm7
	vaesenc	%xmm15, %xmm4, %xmm4
	vmovdqa	80(%rsp), %xmm0
	vaesenc	%xmm0, %xmm4, %xmm4
	vmovdqa	48(%rsp), %xmm6
	vaesenc	%xmm6, %xmm4, %xmm4
	vmovdqa	64(%rsp), %xmm2
	vaesenclast	%xmm2, %xmm4, %xmm4
	vmovd	%xmm4, %ebx
	andl	%r11d, %ebx
	movq	%rbx, %rcx
	shlq	$7, %rcx
	vpcmpeqq	(%rdx,%rcx), %ymm3, %ymm4
	vpcmpeqq	32(%rdx,%rcx), %ymm3, %ymm8
	vpcmpeqq	64(%rdx,%rcx), %ymm3, %ymm9
	vpcmpeqq	96(%rdx,%rcx), %ymm3, %ymm3
	vbroadcastsd	32(%r15), %ymm10
	vbroadcastsd	40(%r15), %ymm12
	shlq	$8, %rbx
	vpxor	(%r8,%rbx), %ymm11, %ymm14
	vblendvpd	%ymm4, %ymm10, %ymm14, %ymm14
	vmovapd	%ymm14, (%r8,%rbx)
	vpxor	32(%r8,%rbx), %ymm11, %ymm14
	vblendvpd	%ymm4, %ymm12, %ymm14, %ymm4
	vmovapd	%ymm4, 32(%r8,%rbx)
	vpxor	64(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm8, %ymm10, %ymm4, %ymm4
	vmovapd	%ymm4, 64(%r8,%rbx)
	vpxor	96(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm8, %ymm12, %ymm4, %ymm4
	vmovapd	%ymm4, 96(%r8,%rbx)
	vpxor	128(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm9, %ymm10, %ymm4, %ymm4
	vmovapd	%ymm4, 128(%r8,%rbx)
	vpxor	160(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm9, %ymm12, %ymm4, %ymm4
	vmovapd	%ymm4, 160(%r8,%rbx)
	vpxor	192(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm3, %ymm10, %ymm4, %ymm4
	vmovapd	%ymm4, 192(%r8,%rbx)
	vpxor	224(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm3, %ymm12, %ymm4, %ymm3
	vmovapd	%ymm3, 224(%r8,%rbx)
	vpbroadcastq	24(%r14,%rax,8), %ymm3
	vpor	%ymm11, %ymm3, %ymm3
	vmovq	24(%r14,%rax,8), %xmm4
	vpxor	32(%rsp), %xmm4, %xmm4
	vaesenc	%xmm5, %xmm4, %xmm4
	vaesenc	128(%rsp), %xmm4, %xmm4
	vaesenc	%xmm13, %xmm4, %xmm4
	vaesenc	(%rsp), %xmm4, %xmm4
	vaesenc	%xmm1, %xmm4, %xmm4
	vaesenc	%xmm7, %xmm4, %xmm4
	vaesenc	%xmm15, %xmm4, %xmm4
	vaesenc	%xmm0, %xmm4, %xmm4
	vaesenc	%xmm6, %xmm4, %xmm4
	vaesenclast	%xmm2, %xmm4, %xmm4
	vmovd	%xmm4, %ebx
	andl	%r11d, %ebx
	movq	%rbx, %rcx
	shlq	$7, %rcx
	vpcmpeqq	(%rdx,%rcx), %ymm3, %ymm4
	vpcmpeqq	32(%rdx,%rcx), %ymm3, %ymm8
	vpcmpeqq	64(%rdx,%rcx), %ymm3, %ymm9
	vpcmpeqq	96(%rdx,%rcx), %ymm3, %ymm3
	vbroadcastsd	48(%r15), %ymm10
	vbroadcastsd	56(%r15), %ymm12
	shlq	$8, %rbx
	vpxor	(%r8,%rbx), %ymm11, %ymm14
	vblendvpd	%ymm4, %ymm10, %ymm14, %ymm14
	vmovapd	%ymm14, (%r8,%rbx)
	vpxor	32(%r8,%rbx), %ymm11, %ymm14
	vblendvpd	%ymm4, %ymm12, %ymm14, %ymm4
	vmovapd	%ymm4, 32(%r8,%rbx)
	vpxor	64(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm8, %ymm10, %ymm4, %ymm4
	vmovapd	%ymm4, 64(%r8,%rbx)
	vpxor	96(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm8, %ymm12, %ymm4, %ymm4
	vmovapd	%ymm4, 96(%r8,%rbx)
	vpxor	128(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm9, %ymm10, %ymm4, %ymm4
	vmovapd	%ymm4, 128(%r8,%rbx)
	vpxor	160(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm9, %ymm12, %ymm4, %ymm4
	vmovapd	%ymm4, 160(%r8,%rbx)
	vpxor	192(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm3, %ymm10, %ymm4, %ymm4
	vmovapd	%ymm4, 192(%r8,%rbx)
	vpxor	224(%r8,%rbx), %ymm11, %ymm4
	vblendvpd	%ymm3, %ymm12, %ymm4, %ymm3
	vmovapd	%ymm3, 224(%r8,%rbx)
	addq	$64, %r15
	leaq	4(%rax), %rbx
	addq	$16, %rax
	cmpq	%r10, %rax
	movq	%rbx, %rax
	jb	.LBB1_7
	cmpq	%rbx, %r10
	jne	.LBB1_3
	jmp	.LBB1_5
.LBB1_1:
	xorl	%ebx, %ebx
	cmpq	%rbx, %r10
	je	.LBB1_5
.LBB1_3:
	movq	%rbx, %rax
	shlq	$4, %rax
	addq	8(%r9), %rax
	movq	(%r9), %r9
	movl	$-1, %ecx
	shlxl	%esi, %ecx, %esi
	notl	%esi
	vmovaps	(%rdi), %xmm0
	vmovaps	%xmm0, 32(%rsp)
	vmovaps	16(%rdi), %xmm0
	vmovaps	%xmm0, 16(%rsp)
	vmovaps	32(%rdi), %xmm0
	vmovaps	%xmm0, (%rsp)
	vmovdqa	48(%rdi), %xmm13
	lfence
	vmovdqa	64(%rdi), %xmm4
	lfence
	vmovdqa	80(%rdi), %xmm5
	lfence
	vmovdqa	96(%rdi), %xmm6
	lfence
	vmovdqa	112(%rdi), %xmm7
	lfence
	vmovdqa	128(%rdi), %xmm0
	lfence
	vmovdqa	144(%rdi), %xmm1
	lfence
	vmovdqa	160(%rdi), %xmm2
	lfence
	movq	$-1, %rcx
	vmovq	%rcx, %xmm11
	.p2align	4, 0x90
.LBB1_4:
	vpbroadcastq	(%r9,%rbx,8), %ymm12
	vmovq	(%r9,%rbx,8), %xmm3
	vpor	%ymm11, %ymm12, %ymm12
	vpxor	32(%rsp), %xmm3, %xmm3
	vaesenc	16(%rsp), %xmm3, %xmm3
	vaesenc	(%rsp), %xmm3, %xmm3
	vaesenc	%xmm13, %xmm3, %xmm3
	vaesenc	%xmm4, %xmm3, %xmm3
	vaesenc	%xmm5, %xmm3, %xmm3
	vaesenc	%xmm6, %xmm3, %xmm3
	vaesenc	%xmm7, %xmm3, %xmm3
	vaesenc	%xmm0, %xmm3, %xmm3
	vaesenc	%xmm1, %xmm3, %xmm3
	vaesenclast	%xmm2, %xmm3, %xmm3
	vmovd	%xmm3, %edi
	andl	%esi, %edi
	movq	%rdi, %rcx
	shlq	$7, %rcx
	vpcmpeqq	(%rdx,%rcx), %ymm12, %ymm3
	vpcmpeqq	32(%rdx,%rcx), %ymm12, %ymm14
	vbroadcastsd	(%rax), %ymm15
	vbroadcastsd	8(%rax), %ymm8
	shlq	$8, %rdi
	vpcmpeqq	64(%rdx,%rcx), %ymm12, %ymm9
	vpxor	(%r8,%rdi), %ymm11, %ymm10
	vblendvpd	%ymm3, %ymm15, %ymm10, %ymm10
	vpcmpeqq	96(%rdx,%rcx), %ymm12, %ymm12
	vmovapd	%ymm10, (%r8,%rdi)
	vpxor	32(%r8,%rdi), %ymm11, %ymm10
	vblendvpd	%ymm3, %ymm8, %ymm10, %ymm3
	vmovapd	%ymm3, 32(%r8,%rdi)
	vpxor	64(%r8,%rdi), %ymm11, %ymm3
	vblendvpd	%ymm14, %ymm15, %ymm3, %ymm3
	vmovapd	%ymm3, 64(%r8,%rdi)
	vpxor	96(%r8,%rdi), %ymm11, %ymm3
	vblendvpd	%ymm14, %ymm8, %ymm3, %ymm3
	vmovapd	%ymm3, 96(%r8,%rdi)
	vpxor	128(%r8,%rdi), %ymm11, %ymm3
	vblendvpd	%ymm9, %ymm15, %ymm3, %ymm3
	vmovapd	%ymm3, 128(%r8,%rdi)
	vpxor	160(%r8,%rdi), %ymm11, %ymm3
	vblendvpd	%ymm9, %ymm8, %ymm3, %ymm3
	vmovapd	%ymm3, 160(%r8,%rdi)
	vpxor	192(%r8,%rdi), %ymm11, %ymm3
	vblendvpd	%ymm12, %ymm15, %ymm3, %ymm3
	vmovapd	%ymm3, 192(%r8,%rdi)
	vpxor	224(%r8,%rdi), %ymm11, %ymm3
	vblendvpd	%ymm12, %ymm8, %ymm3, %ymm3
	vmovapd	%ymm3, 224(%r8,%rdi)
	incq	%rbx
	addq	$16, %rax
	cmpq	%rbx, %r10
	jne	.LBB1_4
.LBB1_5:
	addq	$176, %rsp
	.cfi_def_cfa_offset 32
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	vzeroupper
	popq	%rcx
	lfence
	jmpq	*%rcx

.Lfunc_end1:
	.size	cds_contruct_hash, .Lfunc_end1-cds_contruct_hash
	.cfi_endproc


	.section	".note.GNU-stack","",@progbits
