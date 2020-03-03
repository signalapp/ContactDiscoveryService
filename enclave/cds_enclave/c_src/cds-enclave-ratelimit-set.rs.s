	.text
	.file	"cds_enclave_ratelimit_set.3a1fbbbh-cgu.0"
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4
.LCPI0_0:
	.quad	40
	.quad	48
	.section	.text.cds_ratelimit_set_add,"ax",@progbits
	.globl	cds_ratelimit_set_add
	.p2align	4, 0x90
	.type	cds_ratelimit_set_add,@function
cds_ratelimit_set_add:
	.cfi_startproc
	pushq	%r15
	.cfi_def_cfa_offset 16
	pushq	%r14
	.cfi_def_cfa_offset 24
	pushq	%r12
	.cfi_def_cfa_offset 32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	.cfi_offset %rbx, -40
	.cfi_offset %r12, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	testq	%rcx, %rcx
	je	.LBB0_11
	andq	$-32, %rsi
	je	.LBB0_11
	leaq	(%rdx,%rcx,8), %r8
	leaq	-32(%rsi), %r10
	movl	%r10d, %r14d
	shrl	$5, %r14d
	incl	%r14d
	andl	$7, %r14d
	movq	%r14, %r9
	negq	%r9
	movq	%rsi, %r11
	negq	%r11
	movq	$-1, %rax
	vmovq	%rax, %xmm0
	vpxor	%xmm1, %xmm1, %xmm1
	vmovdqa	.LCPI0_0(%rip), %xmm2
	.p2align	4, 0x90
.LBB0_4:
	vpbroadcastq	(%rdx), %ymm3
	vpxor	%xmm4, %xmm4, %xmm4
	testq	%r14, %r14
	je	.LBB0_5
	movq	%r9, %rcx
	movq	%rsi, %rax
	movq	%rdi, %rbx
	.p2align	4, 0x90
.LBB0_7:
	addq	$-32, %rax
	vpcmpeqq	(%rbx), %ymm3, %ymm5
	addq	$32, %rbx
	vpor	%ymm5, %ymm4, %ymm4
	incq	%rcx
	jne	.LBB0_7
	cmpq	$224, %r10
	jb	.LBB0_9
	.p2align	4, 0x90
.LBB0_12:
	vpcmpeqq	(%rbx), %ymm3, %ymm5
	vpor	%ymm5, %ymm4, %ymm4
	vpcmpeqq	32(%rbx), %ymm3, %ymm5
	vpcmpeqq	64(%rbx), %ymm3, %ymm6
	vpor	%ymm6, %ymm5, %ymm5
	vpor	%ymm5, %ymm4, %ymm4
	vpcmpeqq	96(%rbx), %ymm3, %ymm5
	vpcmpeqq	128(%rbx), %ymm3, %ymm6
	vpor	%ymm6, %ymm5, %ymm5
	vpcmpeqq	160(%rbx), %ymm3, %ymm6
	vpor	%ymm6, %ymm5, %ymm5
	vpor	%ymm5, %ymm4, %ymm4
	vpcmpeqq	192(%rbx), %ymm3, %ymm5
	vpcmpeqq	224(%rbx), %ymm3, %ymm6
	addq	$256, %rbx
	vpor	%ymm6, %ymm5, %ymm5
	vpor	%ymm5, %ymm4, %ymm4
	addq	$-256, %rax
	jne	.LBB0_12
.LBB0_9:
	vpmovmskb	%ymm4, %eax
	cmpl	$1, %eax
	sbbb	%al, %al
	vmovd	%eax, %xmm4
	vpbroadcastb	%xmm4, %ymm4
	vpand	%ymm4, %ymm3, %ymm3
	movq	%r11, %r15
	movq	%rdi, %r12
	.p2align	4, 0x90
.LBB0_10:
	vmovdqu	(%r12), %ymm4
	vpxor	%ymm0, %ymm4, %ymm5
	vpor	%ymm0, %ymm4, %ymm4
	vpcmpeqq	%ymm1, %ymm4, %ymm4
	vpmovmskb	%ymm4, %ecx
	movslq	%ecx, %rbx
	movq	%rbx, %rcx
	shrq	$8, %rcx
	movq	%rbx, %rax
	shrq	$16, %rax
	orq	%rcx, %rax
	movq	%rbx, %rcx
	shrq	$24, %rcx
	orq	%rax, %rcx
	andnq	%rbx, %rcx, %rax
	movl	%eax, %ecx
	vmovq	%rax, %xmm4
	shlq	$63, %rax
	andl	$128, %ecx
	shlq	$56, %rcx
	vpbroadcastq	%xmm4, %xmm4
	vpsllvq	%xmm2, %xmm4, %xmm4
	vmovq	%rax, %xmm6
	vmovq	%rcx, %xmm7
	vpunpcklqdq	%xmm6, %xmm7, %xmm6
	vinserti128	$1, %xmm6, %ymm4, %ymm4
	vblendvpd	%ymm4, %ymm3, %ymm5, %ymm4
	vmovupd	%ymm4, (%r12)
	addq	$32, %r12
	cmpl	$1, %ebx
	sbbb	%al, %al
	vmovd	%eax, %xmm4
	vpbroadcastb	%xmm4, %ymm4
	vpand	%ymm4, %ymm3, %ymm3
	addq	$32, %r15
	jne	.LBB0_10
	addq	$8, %rdx
	cmpq	%r8, %rdx
	jne	.LBB0_4
	jmp	.LBB0_11
	.p2align	4, 0x90
.LBB0_5:
	movq	%rsi, %rax
	movq	%rdi, %rbx
	cmpq	$224, %r10
	jae	.LBB0_12
	jmp	.LBB0_9
.LBB0_11:
	popq	%rbx
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	vzeroupper
	retq
.Lfunc_end0:
	.size	cds_ratelimit_set_add, .Lfunc_end0-cds_ratelimit_set_add
	.cfi_endproc

	.section	.text.cds_ratelimit_set_size,"ax",@progbits
	.globl	cds_ratelimit_set_size
	.p2align	4, 0x90
	.type	cds_ratelimit_set_size,@function
cds_ratelimit_set_size:
	.cfi_startproc
	andq	$-32, %rsi
	je	.LBB1_1
	addq	$-32, %rsi
	movq	%rsi, %rdx
	shrq	$5, %rdx
	incq	%rdx
	movl	%edx, %r8d
	andl	$1, %r8d
	testq	%rsi, %rsi
	je	.LBB1_3
	subq	%r8, %rdx
	xorl	%eax, %eax
	movq	$-1, %rsi
	vmovq	%rsi, %xmm0
	vpxor	%xmm1, %xmm1, %xmm1
	.p2align	4, 0x90
.LBB1_5:
	vpor	(%rdi), %ymm0, %ymm2
	vpcmpeqq	%ymm1, %ymm2, %ymm2
	vpmovmskb	%ymm2, %esi
	movl	%esi, %ecx
	andl	$1, %ecx
	addl	%eax, %ecx
	movl	%esi, %eax
	shrl	$8, %eax
	andl	$1, %eax
	addl	%ecx, %eax
	movl	%esi, %ecx
	shrl	$16, %ecx
	andl	$1, %ecx
	addl	%eax, %ecx
	shrl	$24, %esi
	andl	$1, %esi
	addl	%ecx, %esi
	vpor	32(%rdi), %ymm0, %ymm2
	addq	$64, %rdi
	vpcmpeqq	%ymm1, %ymm2, %ymm2
	vpmovmskb	%ymm2, %eax
	movl	%eax, %ecx
	andl	$1, %ecx
	addl	%esi, %ecx
	movl	%eax, %esi
	shrl	$8, %esi
	andl	$1, %esi
	addl	%ecx, %esi
	movl	%eax, %ecx
	shrl	$16, %ecx
	andl	$1, %ecx
	addl	%esi, %ecx
	shrl	$24, %eax
	andl	$1, %eax
	addl	%ecx, %eax
	addq	$-2, %rdx
	jne	.LBB1_5
	testq	%r8, %r8
	jne	.LBB1_7
.LBB1_8:
	vzeroupper
	retq
.LBB1_1:
	xorl	%eax, %eax
	retq
.LBB1_3:
	xorl	%eax, %eax
	testq	%r8, %r8
	je	.LBB1_8
.LBB1_7:
	movq	$-1, %rcx
	vmovq	%rcx, %xmm0
	vpor	(%rdi), %ymm0, %ymm0
	vpxor	%xmm1, %xmm1, %xmm1
	vpcmpeqq	%ymm1, %ymm0, %ymm0
	vpmovmskb	%ymm0, %ecx
	movl	%ecx, %edx
	andl	$1, %edx
	addl	%eax, %edx
	movl	%ecx, %eax
	shrl	$8, %eax
	andl	$1, %eax
	addl	%edx, %eax
	movl	%ecx, %edx
	shrl	$16, %edx
	andl	$1, %edx
	addl	%eax, %edx
	shrl	$24, %ecx
	andl	$1, %ecx
	addl	%edx, %ecx
	movl	%ecx, %eax
	vzeroupper
	retq
.Lfunc_end1:
	.size	cds_ratelimit_set_size, .Lfunc_end1-cds_ratelimit_set_size
	.cfi_endproc


	.section	".note.GNU-stack","",@progbits
