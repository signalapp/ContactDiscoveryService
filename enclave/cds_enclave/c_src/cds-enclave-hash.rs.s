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
	subq	$232, %rsp
	.cfi_def_cfa_offset 288
	.cfi_offset %rbx, -56
	.cfi_offset %r12, -48
	.cfi_offset %r13, -40
	.cfi_offset %r14, -32
	.cfi_offset %r15, -24
	.cfi_offset %rbp, -16
	movq	304(%rsp), %r10
	popcntq	%r10, %rax
	movl	$1, %ebp
	cmpq	$1, %rax
	jne	.LBB0_56
	tzcntq	%r10, %r14
	cmpl	$31, %r14d
	ja	.LBB0_56
	rdrandq	%rax
	jae	.LBB0_4
	rdrandq	%rbx
	jb	.LBB0_22
.LBB0_4:
	rdrandq	%rax
	jae	.LBB0_6
	rdrandq	%rbx
	jb	.LBB0_22
.LBB0_6:
	rdrandq	%rax
	jae	.LBB0_8
	rdrandq	%rbx
	jb	.LBB0_22
.LBB0_8:
	rdrandq	%rax
	jae	.LBB0_10
	rdrandq	%rbx
	jb	.LBB0_22
.LBB0_10:
	rdrandq	%rax
	jae	.LBB0_12
	rdrandq	%rbx
	jb	.LBB0_22
.LBB0_12:
	rdrandq	%rax
	jae	.LBB0_14
	rdrandq	%rbx
	jb	.LBB0_22
.LBB0_14:
	rdrandq	%rax
	jae	.LBB0_16
	rdrandq	%rbx
	jb	.LBB0_22
.LBB0_16:
	rdrandq	%rax
	jae	.LBB0_18
	rdrandq	%rbx
	jb	.LBB0_22
.LBB0_18:
	rdrandq	%rax
	jae	.LBB0_20
	rdrandq	%rbx
	jb	.LBB0_22
.LBB0_20:
	rdrandq	%rax
	movl	$2, %ebp
	jae	.LBB0_56
	rdrandq	%rbx
	jae	.LBB0_56
.LBB0_22:
	vmovq	%rax, %xmm0
	vmovq	%rbx, %xmm1
	vpunpcklqdq	%xmm0, %xmm1, %xmm12
	vaeskeygenassist	$1, %xmm12, %xmm0
	vpslldq	$4, %xmm12, %xmm1
	vpxor	%xmm1, %xmm12, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm0, %xmm0
	vpxor	%xmm2, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm9
	vaeskeygenassist	$2, %xmm9, %xmm0
	vpslldq	$4, %xmm9, %xmm1
	vpxor	%xmm1, %xmm9, %xmm1
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
	vpxor	%xmm1, %xmm0, %xmm7
	vaeskeygenassist	$8, %xmm7, %xmm0
	vpslldq	$4, %xmm7, %xmm1
	vpxor	%xmm1, %xmm7, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm0, %xmm0
	vpxor	%xmm2, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm2
	vaeskeygenassist	$16, %xmm2, %xmm0
	vpslldq	$4, %xmm2, %xmm1
	vmovdqa	%xmm2, 144(%rsp)
	vpxor	%xmm1, %xmm2, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm0, %xmm0
	vpxor	%xmm2, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm2
	vaeskeygenassist	$32, %xmm2, %xmm0
	vpslldq	$4, %xmm2, %xmm1
	vmovdqa	%xmm2, 112(%rsp)
	vpxor	%xmm1, %xmm2, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm0, %xmm0
	vpxor	%xmm2, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm2
	vaeskeygenassist	$64, %xmm2, %xmm0
	vpslldq	$4, %xmm2, %xmm1
	vmovdqa	%xmm2, 32(%rsp)
	vpxor	%xmm1, %xmm2, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm0, %xmm0
	vpxor	%xmm2, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm4
	vaeskeygenassist	$128, %xmm4, %xmm0
	vpslldq	$4, %xmm4, %xmm1
	vpxor	%xmm1, %xmm4, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpslldq	$4, %xmm1, %xmm2
	vpshufd	$255, %xmm0, %xmm0
	vpxor	%xmm2, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm5
	vaeskeygenassist	$27, %xmm5, %xmm1
	vpslldq	$4, %xmm5, %xmm2
	vpxor	%xmm2, %xmm5, %xmm2
	vpslldq	$4, %xmm2, %xmm3
	vpxor	%xmm3, %xmm2, %xmm2
	vpslldq	$4, %xmm2, %xmm3
	vpshufd	$255, %xmm1, %xmm1
	vpxor	%xmm3, %xmm2, %xmm2
	vpxor	%xmm2, %xmm1, %xmm6
	vaeskeygenassist	$54, %xmm6, %xmm8
	movq	288(%rsp), %r13
	vpslldq	$4, %xmm6, %xmm3
	vpxor	%xmm3, %xmm6, %xmm3
	vpslldq	$4, %xmm3, %xmm2
	vpxor	%xmm2, %xmm3, %xmm2
	vpslldq	$4, %xmm2, %xmm3
	vpshufd	$255, %xmm8, %xmm8
	vpxor	%xmm3, %xmm2, %xmm2
	vpxor	%xmm2, %xmm8, %xmm10
	movq	%r10, %r11
	shlq	$7, %r11
	testq	%r10, %r10
	movq	%r11, 200(%rsp)
	movq	%r14, 72(%rsp)
	vmovdqa	%xmm12, 160(%rsp)
	vmovdqa	%xmm4, 128(%rsp)
	vmovdqa	%xmm5, 96(%rsp)
	vmovdqa	%xmm6, 80(%rsp)
	vmovdqa	%xmm10, 48(%rsp)
	je	.LBB0_36
	leaq	(%r11,%r13), %r15
	testq	%r9, %r9
	je	.LBB0_29
	vmovdqa	%xmm7, (%rsp)
	vmovdqa	%xmm11, 16(%rsp)
	vmovdqa	%xmm9, 208(%rsp)
	movq	%r8, 184(%rsp)
	movl	$-1, %eax
	shlxl	%r14d, %eax, %ebp
	notl	%ebp
	movq	%r9, 192(%rsp)
	leaq	(,%r9,8), %r9
	xorl	%r12d, %r12d
	xorl	%eax, %eax
	movq	%r13, %r10
	vmovdqa	16(%rsp), %xmm2
	vmovdqa	112(%rsp), %xmm1
	.p2align	4, 0x90
.LBB0_25:
	vpxor	%xmm11, %xmm11, %xmm11
	xorl	%r11d, %r11d
	vpxor	%xmm12, %xmm12, %xmm12
	vpxor	%xmm13, %xmm13, %xmm13
	vpxor	%xmm14, %xmm14, %xmm14
	movl	$0, %r14d
	vmovapd	.LCPI0_3(%rip), %ymm15
	vmovapd	.LCPI0_2(%rip), %ymm8
	vmovapd	.LCPI0_1(%rip), %ymm9
	vmovapd	.LCPI0_0(%rip), %ymm10
	vmovdqa	(%rsp), %xmm0
	.p2align	4, 0x90
.LBB0_26:
	vpbroadcastq	(%rcx,%r11), %ymm3
	vmovq	(%rcx,%r11), %xmm4
	vpxor	160(%rsp), %xmm4, %xmm4
	vaesenc	208(%rsp), %xmm4, %xmm4
	vaesenc	%xmm2, %xmm4, %xmm4
	vaesenc	%xmm0, %xmm4, %xmm4
	vaesenc	144(%rsp), %xmm4, %xmm4
	vaesenc	%xmm1, %xmm4, %xmm4
	vaesenc	32(%rsp), %xmm4, %xmm4
	vaesenc	128(%rsp), %xmm4, %xmm4
	vaesenc	96(%rsp), %xmm4, %xmm4
	vaesenc	80(%rsp), %xmm4, %xmm4
	vaesenclast	48(%rsp), %xmm4, %xmm4
	vmovd	%xmm4, %r8d
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
	andl	%ebp, %r8d
	xorq	%rax, %r8
	decq	%r8
	shrq	$32, %r8
	vpmovsxdq	%xmm4, %ymm4
	xorl	%ebx, %ebx
	vtestpd	%ymm4, %ymm4
	sete	%bl
	vblendvpd	%ymm10, %ymm3, %ymm14, %ymm14
	vblendvpd	%ymm9, %ymm3, %ymm13, %ymm13
	vblendvpd	%ymm8, %ymm3, %ymm12, %ymm12
	andl	%ebx, %r8d
	vblendvpd	%ymm15, %ymm3, %ymm11, %ymm11
	vmovd	%r8d, %xmm3
	vpbroadcastq	%xmm3, %ymm3
	vpaddq	%ymm10, %ymm3, %ymm10
	vpaddq	%ymm9, %ymm3, %ymm9
	vpaddq	%ymm8, %ymm3, %ymm8
	vpaddq	%ymm15, %ymm3, %ymm15
	addl	%r8d, %r14d
	addq	$8, %r11
	cmpq	%r11, %r9
	jne	.LBB0_26
	incq	%rax
	vpcmpeqd	%ymm0, %ymm0, %ymm0
	vblendvpd	%ymm10, %ymm0, %ymm14, %ymm3
	vblendvpd	%ymm9, %ymm0, %ymm13, %ymm9
	vblendvpd	%ymm8, %ymm0, %ymm12, %ymm8
	vblendvpd	%ymm15, %ymm0, %ymm11, %ymm10
	vmovapd	%ymm3, (%r10)
	vmovapd	%ymm9, 32(%r10)
	vmovapd	%ymm8, 64(%r10)
	vmovapd	%ymm10, 96(%r10)
	addq	$128, %r10
	cmpl	$16, %r14d
	seta	%bl
	orb	%bl, %r12b
	cmpq	%r15, %r10
	jne	.LBB0_25
	movl	$3, %ebp
	testb	$1, %r12b
	movq	304(%rsp), %r10
	movq	192(%rsp), %r9
	movq	184(%rsp), %r8
	movq	72(%rsp), %r14
	vmovdqa	208(%rsp), %xmm9
	vmovdqa	16(%rsp), %xmm11
	vmovdqa	(%rsp), %xmm7
	je	.LBB0_36
	jmp	.LBB0_56
.LBB0_29:
	leaq	-128(%r11), %rbx
	movl	%ebx, %ebp
	shrl	$7, %ebp
	incl	%ebp
	andq	$7, %rbp
	je	.LBB0_30
	negq	%rbp
	vmovdqa	.LCPI0_4(%rip), %ymm3
	vmovdqa	.LCPI0_4(%rip), %ymm8
	movq	%r13, %rax
	.p2align	4, 0x90
.LBB0_32:
	vmovdqa	%ymm3, (%rax)
	vmovdqa	%ymm8, 32(%rax)
	vmovdqa	%ymm8, 64(%rax)
	vmovdqa	%ymm8, 96(%rax)
	addq	$128, %rax
	incq	%rbp
	jne	.LBB0_32
	cmpq	$896, %rbx
	jae	.LBB0_34
	jmp	.LBB0_36
.LBB0_30:
	movq	%r13, %rax
	cmpq	$896, %rbx
	jb	.LBB0_36
.LBB0_34:
	vmovdqa	.LCPI0_4(%rip), %ymm3
	vmovdqa	.LCPI0_4(%rip), %ymm8
	.p2align	4, 0x90
.LBB0_35:
	vmovdqa	%ymm3, (%rax)
	vmovdqa	%ymm8, 32(%rax)
	vmovdqa	%ymm8, 64(%rax)
	vmovdqa	%ymm8, 96(%rax)
	vmovdqa	%ymm3, 128(%rax)
	vmovdqa	%ymm8, 160(%rax)
	vmovdqa	%ymm8, 192(%rax)
	vmovdqa	%ymm8, 224(%rax)
	vmovdqa	%ymm3, 256(%rax)
	vmovdqa	%ymm8, 288(%rax)
	vmovdqa	%ymm8, 320(%rax)
	vmovdqa	%ymm8, 352(%rax)
	vmovdqa	%ymm3, 384(%rax)
	vmovdqa	%ymm8, 416(%rax)
	vmovdqa	%ymm8, 448(%rax)
	vmovdqa	%ymm8, 480(%rax)
	vmovdqa	%ymm3, 512(%rax)
	vmovdqa	%ymm8, 544(%rax)
	vmovdqa	%ymm8, 576(%rax)
	vmovdqa	%ymm8, 608(%rax)
	vmovdqa	%ymm3, 640(%rax)
	vmovdqa	%ymm8, 672(%rax)
	vmovdqa	%ymm8, 704(%rax)
	vmovdqa	%ymm8, 736(%rax)
	vmovdqa	%ymm3, 768(%rax)
	vmovdqa	%ymm8, 800(%rax)
	vmovdqa	%ymm8, 832(%rax)
	vmovdqa	%ymm8, 864(%rax)
	vmovdqa	%ymm3, 896(%rax)
	vmovdqa	%ymm8, 928(%rax)
	vmovdqa	%ymm8, 960(%rax)
	vmovdqa	%ymm8, 992(%rax)
	addq	$1024, %rax
	cmpq	%r15, %rax
	jne	.LBB0_35
.LBB0_36:
	movq	296(%rsp), %rbx
	cmpq	$13, %rdx
	jb	.LBB0_37
	movl	$-1, %eax
	shlxl	%r14d, %eax, %r15d
	notl	%r15d
	xorl	%r14d, %r14d
	movq	$-1, %rax
	vmovdqa	%xmm9, %xmm12
	vmovdqa	%xmm11, %xmm2
	vmovdqa	%xmm7, %xmm0
	vmovq	%rax, %xmm11
	movq	%rsi, %r12
	vmovdqa	%xmm2, 16(%rsp)
	vmovdqa	%xmm7, (%rsp)
	vmovdqa	160(%rsp), %xmm15
	vmovdqa	144(%rsp), %xmm13
	vmovdqa	112(%rsp), %xmm14
	vmovdqa	128(%rsp), %xmm10
	.p2align	4, 0x90
.LBB0_50:
	prefetchnta	64(%rdi,%r14,8)
	prefetchnta	128(%r12)
	prefetchnta	160(%r12)
	vpbroadcastq	(%rdi,%r14,8), %ymm3
	vpor	%ymm11, %ymm3, %ymm3
	vmovq	(%rdi,%r14,8), %xmm4
	vpxor	%xmm15, %xmm4, %xmm4
	vaesenc	%xmm12, %xmm4, %xmm4
	vaesenc	%xmm2, %xmm4, %xmm4
	vaesenc	(%rsp), %xmm4, %xmm4
	vaesenc	%xmm13, %xmm4, %xmm4
	vaesenc	%xmm14, %xmm4, %xmm4
	vaesenc	32(%rsp), %xmm4, %xmm4
	vaesenc	%xmm10, %xmm4, %xmm4
	vmovdqa	96(%rsp), %xmm1
	vaesenc	%xmm1, %xmm4, %xmm4
	vmovdqa	%xmm1, %xmm2
	vmovdqa	80(%rsp), %xmm1
	vaesenc	%xmm1, %xmm4, %xmm4
	vmovdqa	%xmm1, %xmm0
	vaesenclast	48(%rsp), %xmm4, %xmm4
	vmovd	%xmm4, %eax
	andl	%r15d, %eax
	movq	%rax, %rbp
	shlq	$7, %rbp
	vpcmpeqq	(%r13,%rbp), %ymm3, %ymm4
	vpcmpeqq	32(%r13,%rbp), %ymm3, %ymm5
	vpcmpeqq	64(%r13,%rbp), %ymm3, %ymm6
	vpcmpeqq	96(%r13,%rbp), %ymm3, %ymm3
	vbroadcastsd	(%r12), %ymm7
	vbroadcastsd	8(%r12), %ymm8
	shlq	$8, %rax
	vpxor	(%rbx,%rax), %ymm11, %ymm9
	vblendvpd	%ymm4, %ymm7, %ymm9, %ymm9
	vmovapd	%ymm9, (%rbx,%rax)
	vpxor	32(%rbx,%rax), %ymm11, %ymm9
	vblendvpd	%ymm4, %ymm8, %ymm9, %ymm4
	vmovapd	%ymm4, 32(%rbx,%rax)
	vpxor	64(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm5, %ymm7, %ymm4, %ymm4
	vmovapd	%ymm4, 64(%rbx,%rax)
	vpxor	96(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm5, %ymm8, %ymm4, %ymm4
	vmovapd	%ymm4, 96(%rbx,%rax)
	vpxor	128(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm6, %ymm7, %ymm4, %ymm4
	vmovapd	%ymm4, 128(%rbx,%rax)
	vpxor	160(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm6, %ymm8, %ymm4, %ymm4
	vmovapd	%ymm4, 160(%rbx,%rax)
	vpxor	192(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm3, %ymm7, %ymm4, %ymm4
	vmovapd	%ymm4, 192(%rbx,%rax)
	vpxor	224(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm3, %ymm8, %ymm4, %ymm3
	vmovapd	%ymm3, 224(%rbx,%rax)
	vpbroadcastq	8(%rdi,%r14,8), %ymm3
	vpor	%ymm11, %ymm3, %ymm3
	vmovq	8(%rdi,%r14,8), %xmm4
	vpxor	%xmm15, %xmm4, %xmm4
	vaesenc	%xmm12, %xmm4, %xmm4
	vaesenc	16(%rsp), %xmm4, %xmm4
	vaesenc	(%rsp), %xmm4, %xmm4
	vaesenc	%xmm13, %xmm4, %xmm4
	vaesenc	%xmm14, %xmm4, %xmm4
	vaesenc	32(%rsp), %xmm4, %xmm4
	vaesenc	%xmm10, %xmm4, %xmm4
	vaesenc	%xmm2, %xmm4, %xmm4
	vaesenc	%xmm1, %xmm4, %xmm4
	vmovdqa	48(%rsp), %xmm0
	vaesenclast	%xmm0, %xmm4, %xmm4
	vmovd	%xmm4, %eax
	andl	%r15d, %eax
	movq	%rax, %rbp
	shlq	$7, %rbp
	vpcmpeqq	(%r13,%rbp), %ymm3, %ymm4
	vpcmpeqq	32(%r13,%rbp), %ymm3, %ymm5
	vpcmpeqq	64(%r13,%rbp), %ymm3, %ymm6
	vpcmpeqq	96(%r13,%rbp), %ymm3, %ymm3
	vbroadcastsd	16(%r12), %ymm7
	vbroadcastsd	24(%r12), %ymm8
	shlq	$8, %rax
	vpxor	(%rbx,%rax), %ymm11, %ymm9
	vblendvpd	%ymm4, %ymm7, %ymm9, %ymm9
	vmovapd	%ymm9, (%rbx,%rax)
	vpxor	32(%rbx,%rax), %ymm11, %ymm9
	vblendvpd	%ymm4, %ymm8, %ymm9, %ymm4
	vmovapd	%ymm4, 32(%rbx,%rax)
	vpxor	64(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm5, %ymm7, %ymm4, %ymm4
	vmovapd	%ymm4, 64(%rbx,%rax)
	vpxor	96(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm5, %ymm8, %ymm4, %ymm4
	vmovapd	%ymm4, 96(%rbx,%rax)
	vpxor	128(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm6, %ymm7, %ymm4, %ymm4
	vmovapd	%ymm4, 128(%rbx,%rax)
	vpxor	160(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm6, %ymm8, %ymm4, %ymm4
	vmovapd	%ymm4, 160(%rbx,%rax)
	vpxor	192(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm3, %ymm7, %ymm4, %ymm4
	vmovapd	%ymm4, 192(%rbx,%rax)
	vpxor	224(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm3, %ymm8, %ymm4, %ymm3
	vmovapd	%ymm3, 224(%rbx,%rax)
	vpbroadcastq	16(%rdi,%r14,8), %ymm3
	vpor	%ymm11, %ymm3, %ymm3
	vmovq	16(%rdi,%r14,8), %xmm4
	vpxor	%xmm15, %xmm4, %xmm4
	vaesenc	%xmm12, %xmm4, %xmm4
	vaesenc	16(%rsp), %xmm4, %xmm4
	vaesenc	(%rsp), %xmm4, %xmm4
	vaesenc	%xmm13, %xmm4, %xmm4
	vaesenc	%xmm14, %xmm4, %xmm4
	vaesenc	32(%rsp), %xmm4, %xmm4
	vaesenc	%xmm10, %xmm4, %xmm4
	vaesenc	%xmm2, %xmm4, %xmm4
	vaesenc	%xmm1, %xmm4, %xmm4
	vaesenclast	%xmm0, %xmm4, %xmm4
	vmovd	%xmm4, %eax
	andl	%r15d, %eax
	movq	%rax, %rbp
	shlq	$7, %rbp
	vpcmpeqq	(%r13,%rbp), %ymm3, %ymm4
	vpcmpeqq	32(%r13,%rbp), %ymm3, %ymm5
	vpcmpeqq	64(%r13,%rbp), %ymm3, %ymm6
	vpcmpeqq	96(%r13,%rbp), %ymm3, %ymm3
	vbroadcastsd	32(%r12), %ymm7
	vbroadcastsd	40(%r12), %ymm8
	shlq	$8, %rax
	vpxor	(%rbx,%rax), %ymm11, %ymm9
	vblendvpd	%ymm4, %ymm7, %ymm9, %ymm9
	vmovapd	%ymm9, (%rbx,%rax)
	vpxor	32(%rbx,%rax), %ymm11, %ymm9
	vblendvpd	%ymm4, %ymm8, %ymm9, %ymm4
	vmovapd	%ymm4, 32(%rbx,%rax)
	vpxor	64(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm5, %ymm7, %ymm4, %ymm4
	vmovapd	%ymm4, 64(%rbx,%rax)
	vpxor	96(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm5, %ymm8, %ymm4, %ymm4
	vmovapd	%ymm4, 96(%rbx,%rax)
	vpxor	128(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm6, %ymm7, %ymm4, %ymm4
	vmovapd	%ymm4, 128(%rbx,%rax)
	vpxor	160(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm6, %ymm8, %ymm4, %ymm4
	vmovapd	%ymm4, 160(%rbx,%rax)
	vpxor	192(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm3, %ymm7, %ymm4, %ymm4
	vmovapd	%ymm4, 192(%rbx,%rax)
	vpxor	224(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm3, %ymm8, %ymm4, %ymm3
	vmovapd	%ymm3, 224(%rbx,%rax)
	vpbroadcastq	24(%rdi,%r14,8), %ymm3
	vpor	%ymm11, %ymm3, %ymm3
	vmovq	24(%rdi,%r14,8), %xmm4
	vpxor	%xmm15, %xmm4, %xmm4
	vmovdqa	(%rsp), %xmm0
	vaesenc	%xmm12, %xmm4, %xmm4
	vaesenc	16(%rsp), %xmm4, %xmm4
	vaesenc	%xmm0, %xmm4, %xmm4
	vaesenc	%xmm13, %xmm4, %xmm4
	vmovdqa	32(%rsp), %xmm1
	vaesenc	%xmm14, %xmm4, %xmm4
	vmovdqa	16(%rsp), %xmm2
	vaesenc	%xmm1, %xmm4, %xmm4
	vaesenc	%xmm10, %xmm4, %xmm4
	vaesenc	96(%rsp), %xmm4, %xmm4
	vaesenc	80(%rsp), %xmm4, %xmm4
	vaesenclast	48(%rsp), %xmm4, %xmm4
	vmovd	%xmm4, %eax
	andl	%r15d, %eax
	movq	%rax, %rbp
	shlq	$7, %rbp
	vpcmpeqq	(%r13,%rbp), %ymm3, %ymm4
	vpcmpeqq	32(%r13,%rbp), %ymm3, %ymm5
	vpcmpeqq	64(%r13,%rbp), %ymm3, %ymm6
	vpcmpeqq	96(%r13,%rbp), %ymm3, %ymm3
	vbroadcastsd	48(%r12), %ymm7
	vbroadcastsd	56(%r12), %ymm8
	shlq	$8, %rax
	vpxor	(%rbx,%rax), %ymm11, %ymm9
	vblendvpd	%ymm4, %ymm7, %ymm9, %ymm9
	vmovapd	%ymm9, (%rbx,%rax)
	vpxor	32(%rbx,%rax), %ymm11, %ymm9
	vblendvpd	%ymm4, %ymm8, %ymm9, %ymm4
	vmovapd	%ymm4, 32(%rbx,%rax)
	vpxor	64(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm5, %ymm7, %ymm4, %ymm4
	vmovapd	%ymm4, 64(%rbx,%rax)
	vpxor	96(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm5, %ymm8, %ymm4, %ymm4
	vmovapd	%ymm4, 96(%rbx,%rax)
	vpxor	128(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm6, %ymm7, %ymm4, %ymm4
	vmovapd	%ymm4, 128(%rbx,%rax)
	vpxor	160(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm6, %ymm8, %ymm4, %ymm4
	vmovapd	%ymm4, 160(%rbx,%rax)
	vpxor	192(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm3, %ymm7, %ymm4, %ymm4
	vmovapd	%ymm4, 192(%rbx,%rax)
	vpxor	224(%rbx,%rax), %ymm11, %ymm4
	vblendvpd	%ymm3, %ymm8, %ymm4, %ymm3
	vmovapd	%ymm3, 224(%rbx,%rax)
	leaq	4(%r14), %r11
	addq	$16, %r14
	addq	$64, %r12
	cmpq	%rdx, %r14
	movq	%r11, %r14
	jb	.LBB0_50
	jmp	.LBB0_38
.LBB0_37:
	xorl	%r11d, %r11d
	vmovdqa	32(%rsp), %xmm1
	vmovdqa	%xmm9, %xmm12
	vmovdqa	%xmm11, %xmm2
	vmovdqa	%xmm7, %xmm0
.LBB0_38:
	cmpq	%r11, %rdx
	vmovdqa	128(%rsp), %xmm15
	vmovdqa	96(%rsp), %xmm13
	vmovdqa	80(%rsp), %xmm14
	vmovdqa	48(%rsp), %xmm11
	je	.LBB0_41
	movq	%r11, %rax
	shlq	$4, %rax
	addq	%rax, %rsi
	movl	$-1, %eax
	movq	72(%rsp), %rbp
	shlxl	%ebp, %eax, %r14d
	notl	%r14d
	movq	$-1, %rax
	vmovq	%rax, %xmm8
	.p2align	4, 0x90
.LBB0_40:
	vpbroadcastq	(%rdi,%r11,8), %ymm3
	vmovq	(%rdi,%r11,8), %xmm4
	vpor	%ymm8, %ymm3, %ymm3
	vpxor	160(%rsp), %xmm4, %xmm4
	vaesenc	%xmm12, %xmm4, %xmm4
	vaesenc	%xmm2, %xmm4, %xmm4
	vaesenc	%xmm0, %xmm4, %xmm4
	vaesenc	144(%rsp), %xmm4, %xmm4
	vaesenc	112(%rsp), %xmm4, %xmm4
	vaesenc	%xmm1, %xmm4, %xmm4
	vaesenc	%xmm15, %xmm4, %xmm4
	vaesenc	%xmm13, %xmm4, %xmm4
	vaesenc	%xmm14, %xmm4, %xmm4
	vaesenclast	%xmm11, %xmm4, %xmm4
	vmovd	%xmm4, %ebp
	andl	%r14d, %ebp
	movq	%rbp, %rax
	shlq	$7, %rax
	vpcmpeqq	(%r13,%rax), %ymm3, %ymm4
	vpcmpeqq	32(%r13,%rax), %ymm3, %ymm5
	vbroadcastsd	(%rsi), %ymm6
	vbroadcastsd	8(%rsi), %ymm7
	shlq	$8, %rbp
	vpcmpeqq	64(%r13,%rax), %ymm3, %ymm9
	vpxor	(%rbx,%rbp), %ymm8, %ymm10
	vblendvpd	%ymm4, %ymm6, %ymm10, %ymm10
	vpcmpeqq	96(%r13,%rax), %ymm3, %ymm3
	vmovapd	%ymm10, (%rbx,%rbp)
	vpxor	32(%rbx,%rbp), %ymm8, %ymm10
	vblendvpd	%ymm4, %ymm7, %ymm10, %ymm4
	vmovapd	%ymm4, 32(%rbx,%rbp)
	vpxor	64(%rbx,%rbp), %ymm8, %ymm4
	vblendvpd	%ymm5, %ymm6, %ymm4, %ymm4
	vmovapd	%ymm4, 64(%rbx,%rbp)
	vpxor	96(%rbx,%rbp), %ymm8, %ymm4
	vblendvpd	%ymm5, %ymm7, %ymm4, %ymm4
	vmovapd	%ymm4, 96(%rbx,%rbp)
	vpxor	128(%rbx,%rbp), %ymm8, %ymm4
	vblendvpd	%ymm9, %ymm6, %ymm4, %ymm4
	vmovapd	%ymm4, 128(%rbx,%rbp)
	vpxor	160(%rbx,%rbp), %ymm8, %ymm4
	vblendvpd	%ymm9, %ymm7, %ymm4, %ymm4
	vmovapd	%ymm4, 160(%rbx,%rbp)
	vpxor	192(%rbx,%rbp), %ymm8, %ymm4
	vblendvpd	%ymm3, %ymm6, %ymm4, %ymm4
	vmovapd	%ymm4, 192(%rbx,%rbp)
	vpxor	224(%rbx,%rbp), %ymm8, %ymm4
	vblendvpd	%ymm3, %ymm7, %ymm4, %ymm3
	vmovapd	%ymm3, 224(%rbx,%rbp)
	incq	%r11
	addq	$16, %rsi
	cmpq	%r11, %rdx
	jne	.LBB0_40
.LBB0_41:
	movb	$60, %al
	bzhiq	%rax, %r9, %rax
	cmpq	%r9, %rax
	cmovbq	%rax, %r9
	testq	%r9, %r9
	movq	200(%rsp), %rdx
	je	.LBB0_47
	testq	%r10, %r10
	je	.LBB0_54
	xorl	%eax, %eax
	vpxor	%xmm0, %xmm0, %xmm0
	.p2align	4, 0x90
.LBB0_44:
	vpbroadcastq	(%rcx,%rax,8), %ymm1
	vpxor	%xmm2, %xmm2, %xmm2
	movl	$96, %edi
	movq	%r10, %rsi
	.p2align	4, 0x90
.LBB0_45:
	vpblendd	$252, -96(%r13,%rdi), %ymm0, %ymm3
	vpcmpeqq	%ymm3, %ymm1, %ymm3
	vpblendd	$252, -64(%r13,%rdi), %ymm0, %ymm4
	vpcmpeqq	%ymm4, %ymm1, %ymm4
	vpblendd	$252, -32(%r13,%rdi), %ymm0, %ymm5
	vpcmpeqq	%ymm5, %ymm1, %ymm5
	vpblendd	$252, (%r13,%rdi), %ymm0, %ymm6
	vpcmpeqq	%ymm6, %ymm1, %ymm6
	vpand	-192(%rbx,%rdi,2), %ymm3, %ymm7
	vblendvpd	%ymm4, -128(%rbx,%rdi,2), %ymm7, %ymm7
	vblendvpd	%ymm5, -64(%rbx,%rdi,2), %ymm7, %ymm7
	vblendvpd	%ymm6, (%rbx,%rdi,2), %ymm7, %ymm7
	vpand	-160(%rbx,%rdi,2), %ymm3, %ymm3
	vblendvpd	%ymm4, -96(%rbx,%rdi,2), %ymm3, %ymm3
	vblendvpd	%ymm5, -32(%rbx,%rdi,2), %ymm3, %ymm3
	vblendvpd	%ymm6, 32(%rbx,%rdi,2), %ymm3, %ymm3
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
	subq	$-128, %rdi
	decq	%rsi
	jne	.LBB0_45
	movq	%rax, %rsi
	shlq	$4, %rsi
	incq	%rax
	vmovupd	%xmm2, (%r8,%rsi)
	cmpq	%r9, %rax
	jb	.LBB0_44
.LBB0_47:
	testq	%r10, %r10
	je	.LBB0_48
	shlq	$8, %r10
	addq	%rbx, %r10
	vpcmpeqd	%ymm0, %ymm0, %ymm0
	.p2align	4, 0x90
.LBB0_52:
	vpxor	(%rbx), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, (%rbx)
	vpxor	32(%rbx), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, 32(%rbx)
	vpxor	64(%rbx), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, 64(%rbx)
	vpxor	96(%rbx), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, 96(%rbx)
	vpxor	128(%rbx), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, 128(%rbx)
	vpxor	160(%rbx), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, 160(%rbx)
	vpxor	192(%rbx), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, 192(%rbx)
	vpxor	224(%rbx), %ymm0, %ymm1
	vmovq	%xmm1, %xmm1
	vmovdqa	%ymm1, 224(%rbx)
	addq	$256, %rbx
	cmpq	%r10, %rbx
	jne	.LBB0_52
	xorl	%ebp, %ebp
	movq	%r13, %rdi
	xorl	%esi, %esi
	jmp	.LBB0_55
.LBB0_48:
	xorl	%ebp, %ebp
	jmp	.LBB0_56
.LBB0_54:
	shlq	$4, %r9
	xorl	%ebp, %ebp
	movq	%r8, %rdi
	xorl	%esi, %esi
	movq	%r9, %rdx
.LBB0_55:
	vzeroupper
	callq	*memset@GOTPCREL(%rip)
.LBB0_56:
	vzeroall
	movl	%ebp, %eax
	addq	$232, %rsp
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


	.section	".note.GNU-stack","",@progbits
