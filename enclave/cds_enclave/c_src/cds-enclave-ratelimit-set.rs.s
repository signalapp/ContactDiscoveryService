	.text
	.file	"cds_enclave_ratelimit_set.3a1fbbbh-cgu.0"
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
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -32
	.cfi_offset %r14, -24
	.cfi_offset %r15, -16
	testq	%rcx, %rcx
	je	.LBB0_14
	andq	$-32, %rsi
	je	.LBB0_14
	leaq	(%rdx,%rcx,8), %r8
	leaq	-32(%rsi), %r15
	movq	%r15, %r14
	shrq	$5, %r14
	incq	%r14
	movl	%r14d, %r9d
	andl	$7, %r9d
	leaq	32(%rdi), %r10
	movq	%r9, %r11
	negq	%r11
	movq	$-1, %rax
	vmovq	%rax, %xmm0
	vpxor	%xmm1, %xmm1, %xmm1
	vpbroadcastq	(%rdx), %ymm2
	vpxor	%xmm3, %xmm3, %xmm3
	testq	%r9, %r9
	jne	.LBB0_6
	jmp	.LBB0_5
	.p2align	4, 0x90
.LBB0_3:
	addq	$8, %rdx
	cmpq	%r8, %rdx
	je	.LBB0_14
	vpbroadcastq	(%rdx), %ymm2
	vpxor	%xmm3, %xmm3, %xmm3
	testq	%r9, %r9
	je	.LBB0_5
.LBB0_6:
	movq	%r11, %rcx
	movq	%rsi, %rbx
	movq	%rdi, %rax
	.p2align	4, 0x90
.LBB0_7:
	addq	$-32, %rbx
	vpcmpeqq	(%rax), %ymm2, %ymm4
	addq	$32, %rax
	vpor	%ymm4, %ymm3, %ymm3
	incq	%rcx
	jne	.LBB0_7
	cmpq	$224, %r15
	jb	.LBB0_9
	.p2align	4, 0x90
.LBB0_15:
	vpcmpeqq	(%rax), %ymm2, %ymm4
	vpor	%ymm4, %ymm3, %ymm3
	vpcmpeqq	32(%rax), %ymm2, %ymm4
	vpcmpeqq	64(%rax), %ymm2, %ymm5
	vpor	%ymm5, %ymm4, %ymm4
	vpor	%ymm4, %ymm3, %ymm3
	vpcmpeqq	96(%rax), %ymm2, %ymm4
	vpcmpeqq	128(%rax), %ymm2, %ymm5
	vpor	%ymm5, %ymm4, %ymm4
	vpcmpeqq	160(%rax), %ymm2, %ymm5
	vpor	%ymm5, %ymm4, %ymm4
	vpor	%ymm4, %ymm3, %ymm3
	vpcmpeqq	192(%rax), %ymm2, %ymm4
	vpcmpeqq	224(%rax), %ymm2, %ymm5
	addq	$256, %rax
	vpor	%ymm5, %ymm4, %ymm4
	vpor	%ymm4, %ymm3, %ymm3
	addq	$-256, %rbx
	jne	.LBB0_15
.LBB0_9:
	vpmovmskb	%ymm3, %eax
	cmpl	$1, %eax
	sbbb	%al, %al
	vmovd	%eax, %xmm3
	vpbroadcastb	%xmm3, %ymm3
	vpand	%ymm3, %ymm2, %ymm2
	testb	$1, %r14b
	jne	.LBB0_11
	movq	%rsi, %rax
	movq	%rdi, %rbx
	testq	%r15, %r15
	jne	.LBB0_13
	jmp	.LBB0_3
	.p2align	4, 0x90
.LBB0_11:
	vmovdqu	(%rdi), %ymm3
	vpxor	%ymm0, %ymm3, %ymm4
	vpor	%ymm0, %ymm3, %ymm3
	vpcmpeqq	%ymm1, %ymm3, %ymm3
	vpermq	$144, %ymm3, %ymm5
	vpxor	%ymm3, %ymm5, %ymm3
	vpmovmskb	%ymm3, %eax
	vblendvpd	%ymm3, %ymm2, %ymm4, %ymm3
	vmovupd	%ymm3, (%rdi)
	cmpl	$1, %eax
	sbbb	%al, %al
	vmovd	%eax, %xmm3
	vpbroadcastb	%xmm3, %ymm3
	vpand	%ymm3, %ymm2, %ymm2
	movq	%r15, %rax
	movq	%r10, %rbx
	testq	%r15, %r15
	je	.LBB0_3
	.p2align	4, 0x90
.LBB0_13:
	vmovdqu	(%rbx), %ymm3
	vmovdqu	32(%rbx), %ymm4
	vpxor	%ymm0, %ymm3, %ymm5
	vpor	%ymm0, %ymm3, %ymm3
	vpcmpeqq	%ymm1, %ymm3, %ymm3
	vpermq	$144, %ymm3, %ymm6
	vpxor	%ymm3, %ymm6, %ymm3
	vpmovmskb	%ymm3, %ecx
	vblendvpd	%ymm3, %ymm2, %ymm5, %ymm3
	vmovupd	%ymm3, (%rbx)
	cmpl	$1, %ecx
	sbbb	%cl, %cl
	vmovd	%ecx, %xmm3
	vpbroadcastb	%xmm3, %ymm3
	vpand	%ymm3, %ymm2, %ymm2
	vpor	%ymm0, %ymm4, %ymm3
	vpcmpeqq	%ymm1, %ymm3, %ymm3
	vpermq	$144, %ymm3, %ymm5
	vpxor	%ymm3, %ymm5, %ymm3
	vpmovmskb	%ymm3, %ecx
	cmpl	$1, %ecx
	sbbb	%cl, %cl
	vpxor	%ymm0, %ymm4, %ymm4
	vblendvpd	%ymm3, %ymm2, %ymm4, %ymm3
	vmovupd	%ymm3, 32(%rbx)
	addq	$64, %rbx
	vmovd	%ecx, %xmm3
	vpbroadcastb	%xmm3, %ymm3
	vpand	%ymm3, %ymm2, %ymm2
	addq	$-64, %rax
	jne	.LBB0_13
	jmp	.LBB0_3
	.p2align	4, 0x90
.LBB0_5:
	movq	%rsi, %rbx
	movq	%rdi, %rax
	cmpq	$224, %r15
	jae	.LBB0_15
	jmp	.LBB0_9
.LBB0_14:
	popq	%rbx
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
	vpmovmskb	%ymm2, %ecx
	notl	%ecx
	movl	%ecx, %esi
	shrl	$8, %esi
	andl	$1, %esi
	addl	%eax, %esi
	movl	%ecx, %eax
	shrl	$16, %eax
	andl	$1, %eax
	addl	%esi, %eax
	shrl	$24, %ecx
	andl	$1, %ecx
	addl	%eax, %ecx
	vpor	32(%rdi), %ymm0, %ymm2
	addq	$64, %rdi
	vpcmpeqq	%ymm1, %ymm2, %ymm2
	vpmovmskb	%ymm2, %eax
	notl	%eax
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
	notl	%ecx
	movl	%ecx, %edx
	shrl	$8, %edx
	andl	$1, %edx
	addl	%eax, %edx
	movl	%ecx, %eax
	shrl	$16, %eax
	andl	$1, %eax
	addl	%edx, %eax
	shrl	$24, %ecx
	andl	$1, %ecx
	addl	%eax, %ecx
	movl	%ecx, %eax
	vzeroupper
	retq
.Lfunc_end1:
	.size	cds_ratelimit_set_size, .Lfunc_end1-cds_ratelimit_set_size
	.cfi_endproc


	.section	".note.GNU-stack","",@progbits
