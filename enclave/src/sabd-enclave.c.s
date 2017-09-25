	.file	"sabd-enclave.c"
# GNU C11 (Debian 6.3.0-18) version 6.3.0 20170516 (x86_64-linux-gnu)
#	compiled by GNU C version 6.3.0 20170516, GMP version 6.1.2, MPFR version 3.1.5, MPC version 1.0.3, isl version 0.15
# GGC heuristics: --param ggc-min-expand=100 --param ggc-min-heapsize=131072
# options passed:  -I include -I include/bearssl
# -I linux-sgx-sgx_1.9-6-gaa8e9755aaec/common/inc
# -I linux-sgx-sgx_1.9-6-gaa8e9755aaec/common/inc/tlibc
# -imultiarch x86_64-linux-gnu -D _FORTIFY_SOURCE=2 -D _DEFAULT_SOURCE
# src/sabd-enclave.c -m64 -march=skylake
# -auxbase-strip src/sabd-enclave.c.s -ggdb -ggdb0 -O2 -Wdate-time -Wall
# -Werror=all -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
# -std=c11 -fstack-protector -fvisibility=hidden -fpie -fverbose-asm
# options enabled:  -faggressive-loop-optimizations -falign-labels
# -fasynchronous-unwind-tables -fauto-inc-dec -fbranch-count-reg
# -fcaller-saves -fchkp-check-incomplete-type -fchkp-check-read
# -fchkp-check-write -fchkp-instrument-calls -fchkp-narrow-bounds
# -fchkp-optimize -fchkp-store-bounds -fchkp-use-static-bounds
# -fchkp-use-static-const-bounds -fchkp-use-wrappers
# -fcombine-stack-adjustments -fcommon -fcompare-elim -fcprop-registers
# -fcrossjumping -fcse-follow-jumps -fdefer-pop
# -fdelete-null-pointer-checks -fdevirtualize -fdevirtualize-speculatively
# -fdwarf2-cfi-asm -fearly-inlining -feliminate-unused-debug-types
# -fexpensive-optimizations -fforward-propagate -ffunction-cse -fgcse
# -fgcse-lm -fgnu-runtime -fgnu-unique -fguess-branch-probability
# -fhoist-adjacent-loads -fident -fif-conversion -fif-conversion2
# -findirect-inlining -finline -finline-atomics
# -finline-functions-called-once -finline-small-functions -fipa-cp
# -fipa-cp-alignment -fipa-icf -fipa-icf-functions -fipa-icf-variables
# -fipa-profile -fipa-pure-const -fipa-ra -fipa-reference -fipa-sra
# -fira-hoist-pressure -fira-share-save-slots -fira-share-spill-slots
# -fisolate-erroneous-paths-dereference -fivopts -fkeep-static-consts
# -fleading-underscore -flifetime-dse -flra-remat -flto-odr-type-merging
# -fmath-errno -fmerge-constants -fmerge-debug-strings
# -fmove-loop-invariants -fomit-frame-pointer -foptimize-sibling-calls
# -foptimize-strlen -fpartial-inlining -fpeephole -fpeephole2 -fpic -fpie
# -fplt -fprefetch-loop-arrays -free -freg-struct-return -freorder-blocks
# -freorder-functions -frerun-cse-after-loop
# -fsched-critical-path-heuristic -fsched-dep-count-heuristic
# -fsched-group-heuristic -fsched-interblock -fsched-last-insn-heuristic
# -fsched-rank-heuristic -fsched-spec -fsched-spec-insn-heuristic
# -fsched-stalled-insns-dep -fschedule-fusion -fschedule-insns2
# -fsemantic-interposition -fshow-column -fshrink-wrap -fsigned-zeros
# -fsplit-ivs-in-unroller -fsplit-wide-types -fssa-backprop -fssa-phiopt
# -fstack-protector -fstdarg-opt -fstrict-aliasing -fstrict-overflow
# -fstrict-volatile-bitfields -fsync-libcalls -fthread-jumps
# -ftoplevel-reorder -ftrapping-math -ftree-bit-ccp -ftree-builtin-call-dce
# -ftree-ccp -ftree-ch -ftree-coalesce-vars -ftree-copy-prop -ftree-cselim
# -ftree-dce -ftree-dominator-opts -ftree-dse -ftree-forwprop -ftree-fre
# -ftree-loop-if-convert -ftree-loop-im -ftree-loop-ivcanon
# -ftree-loop-optimize -ftree-parallelize-loops= -ftree-phiprop -ftree-pre
# -ftree-pta -ftree-reassoc -ftree-scev-cprop -ftree-sink -ftree-slsr
# -ftree-sra -ftree-switch-conversion -ftree-tail-merge -ftree-ter
# -ftree-vrp -funit-at-a-time -funwind-tables -fverbose-asm
# -fzero-initialized-in-bss -m128bit-long-double -m64 -m80387 -madx -maes
# -malign-stringops -mavx -mavx2 -mbmi -mbmi2 -mclflushopt -mcx16 -mf16c
# -mfancy-math-387 -mfma -mfp-ret-in-387 -mfsgsbase -mfxsr -mglibc -mhle
# -mieee-fp -mlong-double-80 -mlzcnt -mmmx -mmovbe -mpclmul -mpopcnt
# -mprfchw -mpush-args -mrdrnd -mrdseed -mred-zone -msahf -msse -msse2
# -msse3 -msse4 -msse4.1 -msse4.2 -mssse3 -mstv -mtls-direct-seg-refs
# -mvzeroupper -mxsave -mxsavec -mxsaveopt -mxsaves

	.text
	.p2align 4,,15
	.globl	sabd_lookup_hash
	.hidden	sabd_lookup_hash
	.type	sabd_lookup_hash, @function
sabd_lookup_hash:
.LFB4849:
	.cfi_startproc
	leaq	8(%rsp), %r10	#,
	.cfi_def_cfa 10, 0
	andq	$-32, %rsp	#,
	pushq	-8(%r10)	#
	pushq	%rbp	#
	.cfi_escape 0x10,0x6,0x2,0x76,0
	movq	%rsp, %rbp	#,
	pushq	%r15	#
	pushq	%r14	#
	pushq	%r13	#
	pushq	%r12	#
	pushq	%r10	#
	.cfi_escape 0xf,0x3,0x76,0x58,0x6
	.cfi_escape 0x10,0xf,0x2,0x76,0x78
	.cfi_escape 0x10,0xe,0x2,0x76,0x70
	.cfi_escape 0x10,0xd,0x2,0x76,0x68
	.cfi_escape 0x10,0xc,0x2,0x76,0x60
	pushq	%rbx	#
	subq	$256, %rsp	#,
	.cfi_escape 0x10,0x3,0x2,0x76,0x50
	cmpl	$1, %ecx	#, ab_jid_count
	jbe	.L2	#,
	leal	-1(%rcx), %ebx	#, tmp528
	bsrl	%ebx, %ebx	# tmp528, tmp527
	addl	$1, %ebx	#, iftmp.0_38
	cmpl	$13, %ebx	#, iftmp.0_38
	ja	.L25	#,
	movl	$12, %eax	#, tmp532
	movl	$1, %r14d	#, tmp530
	shlx	%ebx, %eax, %eax	# iftmp.0_38, tmp532, tmp533
	salq	$3, %rax	#, _622
	shlx	%ebx, %r14d, %r14d	# iftmp.0_38, tmp530, _616
	movq	%rax, -264(%rbp)	# _622, %sfp
.L23:
	movq	%rsi, -296(%rbp)	# in_jid_count, %sfp
	movq	-264(%rbp), %rsi	# %sfp,
	movl	%ecx, %r12d	# ab_jid_count, ab_jid_count
	movq	%rdx, %r13	# ab_jids, ab_jids
	movq	%rdi, -288(%rbp)	# in_jids, %sfp
	movl	$64, %edi	#,
	movq	%r8, -304(%rbp)	# in_ab_jids_result, %sfp
	call	memalign@PLT	#
	movq	%rax, %r15	#, hashed_ab_jids
	testq	%rax, %rax	# hashed_ab_jids
	je	.L26	#,
	movl	%r14d, %r9d	# _616, _616
	movl	$64, %edi	#,
	addq	%r9, %r9	# in_hashed_ab_jids_result_bits_size
	movq	%r9, %rsi	# in_hashed_ab_jids_result_bits_size,
	movq	%r9, -112(%rbp)	# in_hashed_ab_jids_result_bits_size, %sfp
	call	memalign@PLT	#
	movq	-112(%rbp), %r9	# %sfp, in_hashed_ab_jids_result_bits_size
	testq	%rax, %rax	# in_hashed_ab_jids_result_bits
	je	.L41	#,
	movq	%r9, %rcx	# in_hashed_ab_jids_result_bits_size,
	movq	%r9, %rsi	# in_hashed_ab_jids_result_bits_size,
	xorl	%edx, %edx	#
	movq	%rax, %rdi	# in_hashed_ab_jids_result_bits,
	movq	%rax, -112(%rbp)	# in_hashed_ab_jids_result_bits, %sfp
	call	memset_s@PLT	#
	movl	%r12d, %esi	# ab_jid_count, _67
	movl	$255, %edx	#,
	movq	-304(%rbp), %rdi	# %sfp,
	movq	%rsi, %rcx	# _67,
	call	memset_s@PLT	#
	movq	-264(%rbp), %rsi	# %sfp, _622
	movq	%r15, %rdi	# hashed_ab_jids,
	xorl	%edx, %edx	#
	movq	%rsi, %rcx	# _622,
	call	memset_s@PLT	#
	movl	$1, %eax	#, tmp535
	movq	-112(%rbp), %r8	# %sfp, in_hashed_ab_jids_result_bits
	movl	$128, -276(%rbp)	#, %sfp
	shlx	%ebx, %eax, %ebx	# iftmp.0_38, tmp535, _640
	leal	-1(%r12), %eax	#, tmp537
	subl	$1, %ebx	#, _659
	vmovapd	.LC6(%rip), %ymm11	#, tmp803
	leaq	8(%r13,%rax,8), %r9	#, _460
	vmovdqa	.LC0(%rip), %ymm14	#, chain_block_masks$0
	leaq	-64(%rbp), %rax	#, tmp791
	vmovdqa	.LC1(%rip), %ymm13	#, chain_block_masks$1
	vmovdqa	.LC2(%rip), %ymm12	#, chain_block_masks$2
	movq	%r8, -272(%rbp)	# in_hashed_ab_jids_result_bits, %sfp
	movq	%r13, %r8	# ab_jids, ab_jids
	movq	%r15, %r13	# hashed_ab_jids, hashed_ab_jids
	movl	%r12d, %r15d	# ab_jid_count, ab_jid_count
	movl	%ebx, %r12d	# _659, _659
	movq	%r9, %rbx	# _460, _460
	movq	%rax, %r9	# tmp791, tmp791
.L5:
	movl	$10, %ecx	#, ivtmp_301
	movl	$1, %edx	#, tmp542
.L7:
	rdrand	%rax	# tmp541
	movq	%rax, (%r9)	# tmp541,
	cmovc	%edx, %eax	# tmp541,, tmp542, _262
	testl	%eax, %eax	# _262
	je	.L10	#,
	rdrand	%rax	# tmp545
	movq	%rax, 8(%r9)	# tmp545,
	cmovc	%edx, %eax	# tmp545,, tmp542, _256
	testl	%eax, %eax	# _256
	je	.L10	#,
	vmovq	-56(%rbp), %xmm6	# MEM[(uint64_t *)&hash_salt_64 + 8B], tmp914
	movq	%r13, %r10	# hashed_ab_jids, ivtmp.114
	xorl	%edi, %edi	# hash_slot_idx
	xorl	%r11d, %r11d	# any_hash_slots_overflowed
	vpinsrq	$1, -64(%rbp), %xmm6, %xmm3	# MEM[(uint64_t *)&hash_salt_64], tmp914, tmp676
	vpslldq	$4, %xmm3, %xmm0	#, tmp916, tmp681
	vaeskeygenassist	$1, %xmm3, %xmm2	#, tmp676, tmp679
	vmovaps	%xmm3, -256(%rbp)	# tmp676, %sfp
	vpxor	%xmm3, %xmm0, %xmm0	# tmp676, tmp681, _367
	vpshufd	$255, %xmm2, %xmm2	#, tmp679, tmp687
	vpslldq	$4, %xmm0, %xmm1	#, _367, tmp683
	vpxor	%xmm1, %xmm0, %xmm0	# tmp683, _367, _371
	vpslldq	$4, %xmm0, %xmm1	#, _371, tmp685
	vpxor	%xmm2, %xmm1, %xmm1	# tmp687, tmp685, tmp689
	vpxor	%xmm0, %xmm1, %xmm10	# _371, tmp689, _380
	vpslldq	$4, %xmm10, %xmm0	#, _380, tmp692
	vaeskeygenassist	$2, %xmm10, %xmm2	#, _380, tmp690
	vpxor	%xmm0, %xmm10, %xmm0	# tmp692, _380, _384
	vpshufd	$255, %xmm2, %xmm2	#, tmp690, tmp698
	vpslldq	$4, %xmm0, %xmm1	#, _384, tmp694
	vpxor	%xmm1, %xmm0, %xmm0	# tmp694, _384, _388
	vpslldq	$4, %xmm0, %xmm1	#, _388, tmp696
	vpxor	%xmm2, %xmm1, %xmm1	# tmp698, tmp696, tmp700
	vpxor	%xmm0, %xmm1, %xmm3	# _388, tmp700, _397
	vpslldq	$4, %xmm3, %xmm0	#, tmp920, tmp703
	vaeskeygenassist	$4, %xmm3, %xmm2	#, _397, tmp701
	vmovaps	%xmm3, -112(%rbp)	# _397, %sfp
	vpxor	%xmm3, %xmm0, %xmm0	# _397, tmp703, _401
	vpshufd	$255, %xmm2, %xmm2	#, tmp701, tmp709
	vpslldq	$4, %xmm0, %xmm1	#, _401, tmp705
	vpxor	%xmm1, %xmm0, %xmm0	# tmp705, _401, _405
	vpslldq	$4, %xmm0, %xmm1	#, _405, tmp707
	vpxor	%xmm2, %xmm1, %xmm1	# tmp709, tmp707, tmp711
	vpxor	%xmm0, %xmm1, %xmm6	# _405, tmp711, _414
	vpslldq	$4, %xmm6, %xmm0	#, tmp924, tmp714
	vaeskeygenassist	$8, %xmm6, %xmm2	#, _414, tmp712
	vmovaps	%xmm6, -144(%rbp)	# _414, %sfp
	vpxor	%xmm6, %xmm0, %xmm0	# _414, tmp714, _418
	vpshufd	$255, %xmm2, %xmm2	#, tmp712, tmp720
	vpslldq	$4, %xmm0, %xmm1	#, _418, tmp716
	vpxor	%xmm1, %xmm0, %xmm0	# tmp716, _418, _422
	vpslldq	$4, %xmm0, %xmm1	#, _422, tmp718
	vpxor	%xmm2, %xmm1, %xmm1	# tmp720, tmp718, tmp722
	vpxor	%xmm0, %xmm1, %xmm3	# _422, tmp722, _431
	vpslldq	$4, %xmm3, %xmm0	#, tmp928, tmp725
	vaeskeygenassist	$16, %xmm3, %xmm2	#, _431, tmp723
	vmovaps	%xmm3, -176(%rbp)	# _431, %sfp
	vpxor	%xmm3, %xmm0, %xmm0	# _431, tmp725, _435
	vpshufd	$255, %xmm2, %xmm2	#, tmp723, tmp731
	vpslldq	$4, %xmm0, %xmm1	#, _435, tmp727
	vpxor	%xmm1, %xmm0, %xmm0	# tmp727, _435, _439
	vpslldq	$4, %xmm0, %xmm1	#, _439, tmp729
	vpxor	%xmm2, %xmm1, %xmm1	# tmp731, tmp729, tmp733
	vpxor	%xmm0, %xmm1, %xmm2	# _439, tmp733, _448
	vmovdqa	%xmm2, %xmm6	# _448, _448
	vmovaps	%xmm2, -208(%rbp)	# _448, %sfp
	vaeskeygenassist	$32, %xmm2, %xmm2	#, _448, tmp734
	vpslldq	$4, %xmm6, %xmm0	#, tmp932, tmp736
	vpshufd	$255, %xmm2, %xmm2	#, tmp734, tmp742
	vpxor	%xmm6, %xmm0, %xmm0	# _448, tmp736, _452
	vpslldq	$4, %xmm0, %xmm1	#, _452, tmp738
	vpxor	%xmm1, %xmm0, %xmm0	# tmp738, _452, _456
	vpslldq	$4, %xmm0, %xmm1	#, _456, tmp740
	vpxor	%xmm2, %xmm1, %xmm1	# tmp742, tmp740, tmp744
	vpxor	%xmm0, %xmm1, %xmm2	# _456, tmp744, _465
	vmovdqa	%xmm2, %xmm3	# _465, _465
	vmovaps	%xmm2, -80(%rbp)	# _465, %sfp
	vaeskeygenassist	$64, %xmm2, %xmm2	#, _465, tmp745
	vpslldq	$4, %xmm3, %xmm0	#, tmp936, tmp747
	vpshufd	$255, %xmm2, %xmm2	#, tmp745, tmp753
	vpxor	%xmm3, %xmm0, %xmm0	# _465, tmp747, _469
	vpslldq	$4, %xmm0, %xmm1	#, _469, tmp749
	vpxor	%xmm1, %xmm0, %xmm0	# tmp749, _469, _473
	vpslldq	$4, %xmm0, %xmm1	#, _473, tmp751
	vpxor	%xmm2, %xmm1, %xmm1	# tmp753, tmp751, tmp755
	vpxor	%xmm0, %xmm1, %xmm2	# _473, tmp755, _482
	vpslldq	$4, %xmm2, %xmm0	#, tmp940, tmp758
	vaeskeygenassist	$128, %xmm2, %xmm1	#, _482, tmp756
	vmovaps	%xmm2, -224(%rbp)	# _482, %sfp
	vpxor	%xmm2, %xmm0, %xmm0	# _482, tmp758, _486
	vpshufd	$255, %xmm1, %xmm1	#, tmp756, tmp764
	vpslldq	$4, %xmm0, %xmm8	#, _486, tmp760
	vpxor	%xmm8, %xmm0, %xmm0	# tmp760, _486, _490
	vpslldq	$4, %xmm0, %xmm8	#, _490, tmp762
	vpxor	%xmm1, %xmm8, %xmm8	# tmp764, tmp762, tmp766
	vpxor	%xmm0, %xmm8, %xmm8	# _490, tmp766, _499
	vpslldq	$4, %xmm8, %xmm0	#, _499, tmp769
	vaeskeygenassist	$27, %xmm8, %xmm1	#, _499, tmp767
	vpxor	%xmm0, %xmm8, %xmm0	# tmp769, _499, _503
	vpshufd	$255, %xmm1, %xmm1	#, tmp767, tmp775
	vpslldq	$4, %xmm0, %xmm9	#, _503, tmp771
	vpxor	%xmm9, %xmm0, %xmm0	# tmp771, _503, _507
	vpslldq	$4, %xmm0, %xmm9	#, _507, tmp773
	vpxor	%xmm1, %xmm9, %xmm9	# tmp775, tmp773, tmp777
	vpxor	%xmm0, %xmm9, %xmm9	# _507, tmp777, _516
	vpslldq	$4, %xmm9, %xmm0	#, _516, tmp780
	vaeskeygenassist	$54, %xmm9, %xmm2	#, _516, tmp778
	vpxor	%xmm0, %xmm9, %xmm0	# tmp780, _516, _520
	vpshufd	$255, %xmm2, %xmm2	#, tmp778, tmp786
	vpslldq	$4, %xmm0, %xmm1	#, _520, tmp782
	vpxor	%xmm1, %xmm0, %xmm0	# tmp782, _520, _524
	vpslldq	$4, %xmm0, %xmm1	#, _524, tmp784
	vpxor	%xmm2, %xmm1, %xmm1	# tmp786, tmp784, tmp788
	vpxor	%xmm0, %xmm1, %xmm2	# _524, tmp788, _533
	vmovaps	%xmm2, -240(%rbp)	# _533, %sfp
	.p2align 4,,10
	.p2align 3
.L24:
	testl	%r15d, %r15d	# ab_jid_count
	je	.L27	#,
	vpxor	%xmm6, %xmm6, %xmm6	# chain_blocks$0
	movq	%r8, %rcx	# ab_jids, ivtmp.109
	vmovdqa	%ymm14, %ymm3	# chain_block_masks$0, chain_block_masks$0
	xorl	%esi, %esi	# chain_idx
	vmovdqa	%ymm6, %ymm5	#, chain_blocks$1
	vmovdqa	%ymm6, %ymm4	# tmp26, chain_blocks$2
	vmovdqa	%ymm13, %ymm2	# chain_block_masks$1, chain_block_masks$1
	vmovdqa	%ymm12, %ymm1	# chain_block_masks$2, chain_block_masks$2
	.p2align 4,,10
	.p2align 3
.L11:
	vmovq	(%rcx), %xmm7	# MEM[base: _535, offset: 0B], tmp548
	vpxor	-256(%rbp), %xmm7, %xmm7	# %sfp, tmp548, tmp549
	xorl	%edx, %edx	# tmp570
	vpbroadcastq	(%rcx), %ymm0	# MEM[base: _535, offset: 0B], tmp547
	vaesenc	%xmm10, %xmm7, %xmm7	# _380, tmp549, tmp550
	vaesenc	-112(%rbp), %xmm7, %xmm7	# %sfp, tmp550, tmp551
	vpcmpeqq	%ymm5, %ymm0, %ymm15	# chain_blocks$1, tmp547, tmp563
	vaesenc	-144(%rbp), %xmm7, %xmm7	# %sfp, tmp551, tmp552
	vaesenc	-176(%rbp), %xmm7, %xmm7	# %sfp, tmp552, tmp553
	vaesenc	-208(%rbp), %xmm7, %xmm7	# %sfp, tmp553, tmp554
	vaesenc	-80(%rbp), %xmm7, %xmm7	# %sfp, tmp554, tmp555
	vaesenc	-224(%rbp), %xmm7, %xmm7	# %sfp, tmp555, tmp556
	vaesenc	%xmm8, %xmm7, %xmm7	# _499, tmp556, tmp557
	vaesenc	%xmm9, %xmm7, %xmm7	# _516, tmp557, tmp558
	vaesenclast	-240(%rbp), %xmm7, %xmm7	# %sfp, tmp558, tmp559
	vmovd	%xmm7, %eax	#, tmp561
	vpcmpeqq	%ymm6, %ymm0, %ymm7	# chain_blocks$0, tmp547, tmp565
	vpor	%ymm7, %ymm15, %ymm7	# tmp565, tmp563, tmp566
	vpcmpeqq	%ymm0, %ymm4, %ymm15	# tmp547, chain_blocks$2, tmp568
	vpor	%ymm15, %ymm7, %ymm7	# tmp568, tmp566, tmp569
	vblendvpd	%ymm3, %ymm0, %ymm6, %ymm15	# chain_block_masks$0, _139, chain_blocks$0, _152
	vtestpd	%ymm7, %ymm7	# tmp569, tmp569
	vblendvpd	%ymm2, %ymm0, %ymm5, %ymm7	# chain_block_masks$1, _139, chain_blocks$1, _153
	vmovdqa	%ymm15, %ymm6	# _152, chain_blocks$0
	vblendvpd	%ymm1, %ymm0, %ymm4, %ymm0	# chain_block_masks$2, _139, chain_blocks$2, _154
	sete	%dl	#, tmp570
	andl	%r12d, %eax	# _659, tmp571
	addq	$8, %rcx	#, ivtmp.109
	xorl	%edi, %eax	# hash_slot_idx, tmp573
	subq	$1, %rax	#, tmp574
	shrq	$32, %rax	#, tmp575
	andq	%rdx, %rax	# tmp570, should_insert_jid
	vmovq	%rax, %xmm5	# should_insert_jid, should_insert_jid
	addl	%eax, %esi	# should_insert_jid, chain_idx
	vpbroadcastq	%xmm5, %ymm4	# should_insert_jid, tmp590
	vmovdqa	%ymm7, %ymm5	# _153, chain_blocks$1
	vpaddq	%ymm4, %ymm1, %ymm1	# tmp590, chain_block_masks$2, chain_block_masks$2
	vpaddq	%ymm4, %ymm2, %ymm2	# tmp590, chain_block_masks$1, chain_block_masks$1
	vpaddq	%ymm4, %ymm3, %ymm3	# tmp590, chain_block_masks$0, chain_block_masks$0
	vmovdqa	%ymm0, %ymm4	# _154, chain_blocks$2
	cmpq	%rcx, %rbx	# ivtmp.109, _460
	jne	.L11	#,
	cmpl	$12, %esi	#, chain_idx
	seta	%al	#, _654
.L13:
	vblendvpd	%ymm3, %ymm11, %ymm15, %ymm3	# _642, tmp803, _152, tmp592
	addl	$1, %edi	#, hash_slot_idx
	orl	%eax, %r11d	# _654, any_hash_slots_overflowed
	addq	$96, %r10	#, ivtmp.114
	vblendvpd	%ymm2, %ymm11, %ymm7, %ymm2	# _646, tmp803, _153, tmp596
	vblendvpd	%ymm1, %ymm11, %ymm0, %ymm0	# _650, tmp803, _154, tmp600
	vmovdqa	%ymm3, -96(%r10)	# tmp592, MEM[base: _392, offset: 0B]
	vmovdqa	%ymm2, -64(%r10)	# tmp596, MEM[base: _392, offset: 32B]
	vmovdqa	%ymm0, -32(%r10)	# tmp600, MEM[base: _392, offset: 64B]
	cmpl	%r14d, %edi	# _616, hash_slot_idx
	jne	.L24	#,
	testb	%r11b, %r11b	# any_hash_slots_overflowed
	jne	.L42	#,
	movq	-288(%rbp), %rdi	# %sfp, ivtmp.104
	movq	-296(%rbp), %rax	# %sfp, in_jid_count
	movl	%r12d, %ebx	# _659, _659
	movl	%r15d, %r12d	# ab_jid_count, ab_jid_count
	movq	%r13, %r15	# hashed_ab_jids, hashed_ab_jids
	movq	%r8, %r13	# ab_jids, ab_jids
	movq	-272(%rbp), %r8	# %sfp, in_hashed_ab_jids_result_bits
	leaq	(%rdi,%rax,8), %rcx	#, _539
	testq	%rax, %rax	# in_jid_count
	je	.L20	#,
	vmovdqa	-112(%rbp), %xmm2	# %sfp, _397
	vmovdqa	-144(%rbp), %xmm3	# %sfp, _414
	vmovdqa	-176(%rbp), %xmm4	# %sfp, _431
	vmovdqa	-208(%rbp), %xmm5	# %sfp, _448
	vmovdqa	-80(%rbp), %xmm6	# %sfp, _465
	vmovdqa	-224(%rbp), %xmm7	# %sfp, _482
	vmovdqa	-240(%rbp), %xmm11	# %sfp, _533
	vmovdqa	-256(%rbp), %xmm12	# %sfp, tmp676
.L29:
	vmovq	(%rdi), %xmm0	# MEM[base: _542, offset: 0B], tmp606
	vpbroadcastq	(%rdi), %ymm1	# MEM[base: _542, offset: 0B], tmp605
	addq	$8, %rdi	#, ivtmp.104
	vpxor	%xmm12, %xmm0, %xmm0	# tmp676, tmp606, tmp607
	vaesenc	%xmm10, %xmm0, %xmm0	# _380, tmp607, tmp608
	vaesenc	%xmm2, %xmm0, %xmm0	# _397, tmp608, tmp609
	vaesenc	%xmm3, %xmm0, %xmm0	# _414, tmp609, tmp610
	vaesenc	%xmm4, %xmm0, %xmm0	# _431, tmp610, tmp611
	vaesenc	%xmm5, %xmm0, %xmm0	# _448, tmp611, tmp612
	vaesenc	%xmm6, %xmm0, %xmm0	# _465, tmp612, tmp613
	vaesenc	%xmm7, %xmm0, %xmm0	# _482, tmp613, tmp614
	vaesenc	%xmm8, %xmm0, %xmm0	# _499, tmp614, tmp615
	vaesenc	%xmm9, %xmm0, %xmm0	# _516, tmp615, tmp616
	vaesenclast	%xmm11, %xmm0, %xmm0	# _533, tmp616, tmp617
	vmovd	%xmm0, %eax	#, tmp619
	andl	%ebx, %eax	# _659, _346
	leal	(%rax,%rax,2), %edx	#, tmp622
	cltq
	sall	$2, %edx	#,
	leaq	(%r15,%rdx,8), %rsi	#, chain_blocks
	vmovdqa	(%rsi), %ymm0	# *chain_blocks_206, *chain_blocks_206
	vpcmpeqq	%ymm1, %ymm0, %ymm0	# tmp605, *chain_blocks_206, tmp629
	vmovmskpd	%ymm0, %edx	# tmp629, tmp626
	vmovdqa	32(%rsi), %ymm0	# MEM[(__m256i * {ref-all})chain_blocks_206 + 32B], MEM[(__m256i * {ref-all})chain_blocks_206 + 32B]
	vpcmpeqq	%ymm1, %ymm0, %ymm0	# tmp605, MEM[(__m256i * {ref-all})chain_blocks_206 + 32B], tmp634
	vmovmskpd	%ymm0, %r11d	# tmp634, tmp631
	vmovdqa	64(%rsi), %ymm0	# MEM[(__m256i * {ref-all})chain_blocks_206 + 64B], MEM[(__m256i * {ref-all})chain_blocks_206 + 64B]
	leaq	(%r8,%rax,2), %rsi	#, chain_result_bits
	movl	%r11d, %eax	# tmp631, tmp631
	movzwl	(%rsi), %r9d	# *chain_result_bits_228, _229
	vpcmpeqq	%ymm1, %ymm0, %ymm1	# tmp605, MEM[(__m256i * {ref-all})chain_blocks_206 + 64B], tmp639
	sall	$4, %eax	#, tmp631
	xorw	$-4096, %r9w	#, tmp647
	vmovmskpd	%ymm1, %r10d	# tmp639, tmp636
	sall	$8, %r10d	#, tmp644
	orl	%r10d, %eax	# tmp644, tmp645
	orl	%edx, %eax	# tmp626, chain_eq_mask
	orl	%r9d, %eax	# tmp647, _231
	movw	%ax, (%rsi)	# _231, *chain_result_bits_228
	cmpq	%rdi, %rcx	# ivtmp.104, _539
	jne	.L29	#,
.L20:
	testl	%r12d, %r12d	# ab_jid_count
	je	.L18	#,
	leal	-1(%r14), %eax	#, tmp649
	movq	-304(%rbp), %rdi	# %sfp, in_ab_jids_result
	xorl	%r11d, %r11d	# ivtmp.96
	leaq	2(%r8,%rax,2), %r10	#, _550
	.p2align 4,,10
	.p2align 3
.L22:
	vpbroadcastq	0(%r13,%r11,8), %ymm1	# MEM[base: ab_jids_111(D), index: ivtmp.96_549, step: 8, offset: 0B], _292
	movq	%r15, %rdx	# hashed_ab_jids, ivtmp.90
	movq	%r8, %rcx	# in_hashed_ab_jids_result_bits, ivtmp.91
	xorl	%esi, %esi	# ab_jid_result
	.p2align 4,,10
	.p2align 3
.L21:
	vmovdqa	(%rdx), %ymm0	# MEM[base: _85, offset: 0B], MEM[base: _85, offset: 0B]
	movzwl	(%rcx), %r9d	# *_271, _272
	addq	$2, %rcx	#, ivtmp.91
	addq	$96, %rdx	#, ivtmp.90
	vpcmpeqq	%ymm1, %ymm0, %ymm0	# _292, MEM[base: _85, offset: 0B], tmp656
	andw	$4095, %r9w	#, chain_result
	vmovmskpd	%ymm0, %ebx	# tmp656, tmp653
	vmovdqa	-64(%rdx), %ymm0	# MEM[base: _85, offset: 32B], MEM[base: _85, offset: 32B]
	vpcmpeqq	%ymm1, %ymm0, %ymm0	# _292, MEM[base: _85, offset: 32B], tmp661
	vmovmskpd	%ymm0, %eax	# tmp661, tmp658
	vmovdqa	-32(%rdx), %ymm0	# MEM[base: _85, offset: 64B], MEM[base: _85, offset: 64B]
	sall	$4, %eax	#, tmp668
	vpcmpeqq	%ymm1, %ymm0, %ymm0	# _292, MEM[base: _85, offset: 64B], tmp666
	vmovmskpd	%ymm0, %r14d	# tmp666, tmp663
	sall	$8, %r14d	#, tmp669
	orl	%r14d, %eax	# tmp669, tmp670
	orl	%ebx, %eax	# tmp653, chain_eq_mask
	andl	%r9d, %eax	# chain_result, tmp673
	orl	%eax, %esi	# tmp673, ab_jid_result
	cmpq	%rcx, %r10	# ivtmp.91, _550
	jne	.L21	#,
	testw	%si, %si	# ab_jid_result
	leaq	(%rdi,%r11), %rax	#, _547
	setne	%dl	#, tmp674
	addq	$1, %r11	#, ivtmp.96
	movb	%dl, (%rax)	# tmp674, *_547
	cmpl	%r11d, %r12d	# ivtmp.96, ab_jid_count
	ja	.L22	#,
.L18:
	movq	%r8, %rdi	# in_hashed_ab_jids_result_bits,
	vzeroupper
	call	free@PLT	#
	movq	%r15, %rdi	# hashed_ab_jids,
	call	free@PLT	#
	xorl	%eax, %eax	# <retval>
.L37:
	addq	$256, %rsp	#,
	popq	%rbx	#
	popq	%r10	#
	.cfi_remember_state
	.cfi_def_cfa 10, 0
	popq	%r12	#
	popq	%r13	#
	popq	%r14	#
	popq	%r15	#
	popq	%rbp	#
	leaq	-8(%r10), %rsp	#,
	.cfi_def_cfa 7, 8
	ret
.L42:
	.cfi_restore_state
	movq	-264(%rbp), %rsi	# %sfp, _622
	xorl	%edx, %edx	#
	movq	%r13, %rdi	# hashed_ab_jids,
	movq	%r9, -80(%rbp)	# tmp791, %sfp
	movq	%r8, -224(%rbp)	# ab_jids, %sfp
	movq	%rsi, %rcx	# _622,
	vmovdqa	%ymm12, -208(%rbp)	# chain_block_masks$2, %sfp
	vmovdqa	%ymm13, -176(%rbp)	# chain_block_masks$1, %sfp
	vmovdqa	%ymm14, -144(%rbp)	# chain_block_masks$0, %sfp
	vmovapd	%ymm11, -112(%rbp)	# tmp803, %sfp
	vzeroupper
	call	memset_s@PLT	#
	subl	$1, -276(%rbp)	#, %sfp
	vmovapd	-112(%rbp), %ymm11	# %sfp, tmp803
	vmovdqa	-144(%rbp), %ymm14	# %sfp, chain_block_masks$0
	vmovdqa	-176(%rbp), %ymm13	# %sfp, chain_block_masks$1
	vmovdqa	-208(%rbp), %ymm12	# %sfp, chain_block_masks$2
	movq	-80(%rbp), %r9	# %sfp, tmp791
	movq	-224(%rbp), %r8	# %sfp, ab_jids
	jne	.L5	#,
.L39:
	movq	-272(%rbp), %r8	# %sfp, in_hashed_ab_jids_result_bits
	movq	%r8, %rdi	# in_hashed_ab_jids_result_bits,
	vzeroupper
	call	free@PLT	#
	movq	%r13, %rdi	# hashed_ab_jids,
	call	free@PLT	#
	movl	$1, %eax	#, <retval>
	jmp	.L37	#
	.p2align 4,,10
	.p2align 3
.L27:
	vxorpd	%xmm0, %xmm0, %xmm0	# _154
	xorl	%eax, %eax	# _654
	vmovapd	.LC3(%rip), %ymm1	#, _650
	vmovapd	.LC4(%rip), %ymm2	#, _646
	vmovapd	%ymm0, %ymm7	#, _153
	vmovapd	%ymm0, %ymm15	#, _152
	vmovapd	.LC5(%rip), %ymm3	#, _642
	jmp	.L13	#
.L10:
	subl	$1, %ecx	#, ivtmp_301
	jne	.L7	#,
	jmp	.L39	#
.L2:
	testl	%ecx, %ecx	# ab_jid_count
	jne	.L43	#,
	xorl	%eax, %eax	# <retval>
	jmp	.L37	#
.L26:
	movl	$3, %eax	#, <retval>
	jmp	.L37	#
.L25:
	movl	$2, %eax	#, <retval>
	jmp	.L37	#
.L41:
	movq	%r15, %rdi	# hashed_ab_jids,
	call	free@PLT	#
	movl	$3, %eax	#, <retval>
	jmp	.L37	#
.L43:
	movq	$96, -264(%rbp)	#, %sfp
	movl	$1, %r14d	#, _616
	xorl	%ebx, %ebx	# iftmp.0_38
	jmp	.L23	#
	.cfi_endproc
.LFE4849:
	.size	sabd_lookup_hash, .-sabd_lookup_hash
	.p2align 4,,15
	.globl	sgxsd_enclave_server_init
	.hidden	sgxsd_enclave_server_init
	.type	sgxsd_enclave_server_init, @function
sgxsd_enclave_server_init:
.LFB4850:
	.cfi_startproc
	movl	$2, %eax	#, <retval>
	testq	%rdi, %rdi	# p_args
	je	.L55	#,
	pushq	%r13	#
	.cfi_def_cfa_offset 16
	.cfi_offset 13, -16
	movq	%rsi, %r13	# pp_state, pp_state
	pushq	%r12	#
	.cfi_def_cfa_offset 24
	.cfi_offset 12, -24
	pushq	%rbp	#
	.cfi_def_cfa_offset 32
	.cfi_offset 6, -32
	pushq	%rbx	#
	.cfi_def_cfa_offset 40
	.cfi_offset 3, -40
	movq	%rdi, %rbx	# p_args, p_args
	subq	$8, %rsp	#,
	.cfi_def_cfa_offset 48
	movl	(%rdi), %eax	# p_args_3(D)->max_ab_jids, p_args_3(D)->max_ab_jids
	movl	$64, %edi	#,
	leaq	64(,%rax,8), %r12	#, state_size
	movq	%r12, %rsi	# state_size,
	call	memalign@PLT	#
	movq	%rax, %rbp	#, p_state
	movl	$3, %eax	#, <retval>
	testq	%rbp, %rbp	# p_state
	je	.L50	#,
	movq	%r12, %rcx	# state_size,
	xorl	%edx, %edx	#
	movq	%r12, %rsi	# state_size,
	movq	%rbp, %rdi	# p_state,
	call	memset_s@PLT	#
	movl	(%rbx), %eax	# p_args_3(D)->max_ab_jids, _12
	movq	$0, 0(%rbp)	#, p_state_10->msgs
	movl	$0, 8(%rbp)	#, p_state_10->ab_jid_count
	movl	%eax, 12(%rbp)	# _12, p_state_10->max_ab_jids
	xorl	%eax, %eax	# <retval>
	movq	%rbp, 0(%r13)	# p_state, *pp_state_16(D)
.L50:
	addq	$8, %rsp	#,
	.cfi_def_cfa_offset 40
	popq	%rbx	#
	.cfi_restore 3
	.cfi_def_cfa_offset 32
	popq	%rbp	#
	.cfi_restore 6
	.cfi_def_cfa_offset 24
	popq	%r12	#
	.cfi_restore 12
	.cfi_def_cfa_offset 16
	popq	%r13	#
	.cfi_restore 13
	.cfi_def_cfa_offset 8
.L55:
	ret
	.cfi_endproc
.LFE4850:
	.size	sgxsd_enclave_server_init, .-sgxsd_enclave_server_init
	.p2align 4,,15
	.globl	sgxsd_enclave_server_handle_call
	.hidden	sgxsd_enclave_server_handle_call
	.type	sgxsd_enclave_server_handle_call, @function
sgxsd_enclave_server_handle_call:
.LFB4851:
	.cfi_startproc
	pushq	%r15	#
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	movl	$5, %eax	#, <retval>
	pushq	%r14	#
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	pushq	%r13	#
	.cfi_def_cfa_offset 32
	.cfi_offset 13, -32
	pushq	%r12	#
	.cfi_def_cfa_offset 40
	.cfi_offset 12, -40
	pushq	%rbp	#
	.cfi_def_cfa_offset 48
	.cfi_offset 6, -48
	pushq	%rbx	#
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	subq	$8, %rsp	#,
	.cfi_def_cfa_offset 64
	movq	(%rcx), %rbx	# *pp_state_4(D), p_state
	testq	%rbx, %rbx	# p_state
	je	.L69	#,
	movl	$2, %eax	#, <retval>
	testq	%rdi, %rdi	# p_args
	je	.L69	#,
	movl	(%rdi), %ecx	# p_args_7(D)->ab_jid_count, _8
	testl	%ecx, %ecx	# _8
	jne	.L71	#,
.L69:
	addq	$8, %rsp	#,
	.cfi_remember_state
	.cfi_def_cfa_offset 56
	popq	%rbx	#
	.cfi_def_cfa_offset 48
	popq	%rbp	#
	.cfi_def_cfa_offset 40
	popq	%r12	#
	.cfi_def_cfa_offset 32
	popq	%r13	#
	.cfi_def_cfa_offset 24
	popq	%r14	#
	.cfi_def_cfa_offset 16
	popq	%r15	#
	.cfi_def_cfa_offset 8
	ret
	.p2align 4,,10
	.p2align 3
.L71:
	.cfi_restore_state
	movl	8(%rbx), %r14d	# p_state_5->ab_jid_count,
	movl	12(%rbx), %r8d	# p_state_5->max_ab_jids, tmp114
	subl	%r14d, %r8d	# _10, tmp114
	cmpl	%r8d, %ecx	# tmp114, _8
	ja	.L69	#,
	testb	$7, %dl	#, msg
	jne	.L69	#,
	movl	%edx, %r8d	# msg, tmp117
	shrl	$3, %r8d	#, tmp117
	cmpl	%r8d, %ecx	# tmp117, _8
	jne	.L69	#,
	movq	%rdi, %rbp	# p_args, p_args
	movl	$56, %edi	#,
	movq	%rdx, %r12	# msg, msg
	movq	%rsi, %r13	# msg, msg
	call	malloc@PLT	#
	movq	%rax, %r15	#, tmp118
	movl	$3, %eax	#, <retval>
	testq	%r15, %r15	# tmp118
	je	.L69	#,
	movq	(%rbx), %rax	# p_state_5->msgs, _17
	movl	$10, %ecx	#, tmp121
	movq	%r15, %rdi	# tmp118, p_sabd_msg
	leaq	64(%rsp), %rsi	#, tmp120
	rep movsl
	movl	0(%rbp), %edx	# p_args_7(D)->ab_jid_count, _16
	leaq	64(%rbx,%r14,8), %rdi	#, tmp125
	movq	%r13, %rsi	# msg,
	movq	%rax, 48(%r15)	# _17, p_sabd_msg_15->prev
	movl	%edx, 40(%r15)	# _16, p_sabd_msg_15->ab_jid_count
	movl	%r12d, %edx	# msg, msg$size
	movq	%r15, (%rbx)	# tmp118, p_state_5->msgs
	call	memcpy@PLT	#
	movl	40(%r15), %eax	# p_sabd_msg_15->ab_jid_count, p_sabd_msg_15->ab_jid_count
	addl	%eax, 8(%rbx)	# p_sabd_msg_15->ab_jid_count, p_state_5->ab_jid_count
	xorl	%eax, %eax	# <retval>
	jmp	.L69	#
	.cfi_endproc
.LFE4851:
	.size	sgxsd_enclave_server_handle_call, .-sgxsd_enclave_server_handle_call
	.p2align 4,,15
	.globl	sgxsd_enclave_server_terminate
	.hidden	sgxsd_enclave_server_terminate
	.type	sgxsd_enclave_server_terminate, @function
sgxsd_enclave_server_terminate:
.LFB4852:
	.cfi_startproc
	pushq	%r15	#
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	pushq	%r14	#
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	pushq	%r13	#
	.cfi_def_cfa_offset 32
	.cfi_offset 13, -32
	pushq	%r12	#
	.cfi_def_cfa_offset 40
	.cfi_offset 12, -40
	pushq	%rbp	#
	.cfi_def_cfa_offset 48
	.cfi_offset 6, -48
	pushq	%rbx	#
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	movl	$5, %ebx	#, <retval>
	subq	$56, %rsp	#,
	.cfi_def_cfa_offset 112
	testq	%rsi, %rsi	# p_state
	je	.L93	#,
	movq	%rsi, %rbp	# p_state, p_state
	movq	%rdi, %rbx	# p_args, p_args
	testq	%rdi, %rdi	# p_args
	je	.L76	#,
	movabsq	$2305843009213693951, %rax	#, tmp107
	movq	8(%rdi), %r12	# p_args_19(D)->in_jid_count, _21
	cmpq	%rax, %r12	# tmp107, _21
	jbe	.L96	#,
.L76:
	movq	%rbp, %rdi	# p_state,
	movl	$2, %ebx	#, <retval>
	call	free@PLT	#
.L93:
	addq	$56, %rsp	#,
	.cfi_remember_state
	.cfi_def_cfa_offset 56
	movl	%ebx, %eax	# <retval>,
	popq	%rbx	#
	.cfi_def_cfa_offset 48
	popq	%rbp	#
	.cfi_def_cfa_offset 40
	popq	%r12	#
	.cfi_def_cfa_offset 32
	popq	%r13	#
	.cfi_def_cfa_offset 24
	popq	%r14	#
	.cfi_def_cfa_offset 16
	popq	%r15	#
	.cfi_def_cfa_offset 8
	ret
	.p2align 4,,10
	.p2align 3
.L96:
	.cfi_restore_state
	movq	(%rdi), %rdi	# p_args_19(D)->in_jids,
	leaq	0(,%r12,8), %rsi	#, in_jids_size
	call	sgx_is_outside_enclave@PLT	#
	cmpl	$1, %eax	#, _25
	jne	.L76	#,
	movl	8(%rbp), %r13d	# p_state_17(D)->ab_jid_count, ab_jid_idx
	testl	%r13d, %r13d	# ab_jid_idx
	jne	.L97	#,
	movq	%rbp, %rdi	# p_state,
	xorl	%ebx, %ebx	# <retval>
	call	free@PLT	#
	jmp	.L93	#
.L97:
	movl	%r13d, %edi	# ab_jid_idx, ab_jid_idx
	call	malloc@PLT	#
	movq	%rax, %r14	#, in_ab_jids_result
	testq	%rax, %rax	# in_ab_jids_result
	je	.L79	#,
	movq	(%rbx), %rdi	# p_args_19(D)->in_jids,
	leaq	64(%rbp), %rdx	#, tmp111
	movl	%r13d, %ecx	# ab_jid_idx,
	movq	%rax, %r8	# in_ab_jids_result,
	movq	%r12, %rsi	# _21,
	call	sabd_lookup_hash	#
	movq	0(%rbp), %rdx	# p_state_17(D)->msgs, p_msg
	movl	8(%rbp), %r13d	# p_state_17(D)->ab_jid_count, ab_jid_idx
	movl	%eax, %ebx	#, <retval>
	testq	%rdx, %rdx	# p_msg
	je	.L87	#,
.L84:
	xorl	%r15d, %r15d	# replies_res
	jmp	.L83	#
	.p2align 4,,10
	.p2align 3
.L81:
	movq	48(%rdx), %r12	# p_msg_66->prev, p_prev_msg
	movq	%rdx, %rdi	# p_msg,
	call	free@PLT	#
	movq	%r12, %rdx	# p_prev_msg, p_msg
	testq	%r12, %r12	# p_msg
	je	.L80	#,
.L83:
	testl	%ebx, %ebx	# <retval>
	jne	.L81	#,
	movl	40(%rdx), %eax	# p_msg_66->ab_jid_count, _37
	subq	$8, %rsp	#,
	.cfi_def_cfa_offset 120
	subl	%eax, %r13d	# _37, ab_jid_idx
	movl	%r13d, %ecx	# ab_jid_idx, ab_jid_idx
	addq	%r14, %rcx	# in_ab_jids_result, tmp126
	movq	%rcx, 24(%rsp)	# tmp126, %sfp
	vmovdqa	24(%rsp), %xmm1	# %sfp, tmp128
	vpinsrd	$2, %eax, %xmm1, %xmm0	#, _37, tmp128, tmp114
	vmovaps	%xmm0, 8(%rsp)	# tmp114, %sfp
	vmovdqa	8(%rsp), %xmm2	# %sfp, tmp129
	movq	16(%rsp), %rsi	# %sfp, tmp123
	vmovaps	%xmm2, 24(%rsp)	# tmp129, %sfp
	pushq	32(%rdx)	# p_msg_66->from
	.cfi_def_cfa_offset 128
	pushq	24(%rdx)	# p_msg_66->from
	.cfi_def_cfa_offset 136
	pushq	16(%rdx)	# p_msg_66->from
	.cfi_def_cfa_offset 144
	pushq	8(%rdx)	# p_msg_66->from
	.cfi_def_cfa_offset 152
	pushq	(%rdx)	# p_msg_66->from
	.cfi_def_cfa_offset 160
	movq	48(%rsp), %rdi	# %sfp,
	movq	%rdx, 88(%rsp)	# p_msg, %sfp
	call	sgxsd_enclave_server_reply@PLT	#
	addq	$48, %rsp	#,
	.cfi_def_cfa_offset 112
	testl	%r15d, %r15d	# replies_res
	movq	40(%rsp), %rdx	# %sfp, p_msg
	cmove	%eax, %r15d	# replies_res,, reply_res, replies_res
	jmp	.L81	#
.L87:
	xorl	%r15d, %r15d	# replies_res
.L80:
	movq	%r14, %rdi	# in_ab_jids_result,
	call	free@PLT	#
	movq	%rbp, %rdi	# p_state,
	call	free@PLT	#
	testl	%ebx, %ebx	# <retval>
	cmove	%r15d, %ebx	# <retval>,, replies_res, <retval>
	jmp	.L93	#
.L79:
	movq	0(%rbp), %rdx	# p_state_17(D)->msgs, p_msg
	movl	$3, %ebx	#, <retval>
	testq	%rdx, %rdx	# p_msg
	jne	.L84	#,
	movq	%rbp, %rdi	# p_state,
	call	free@PLT	#
	jmp	.L93	#
	.cfi_endproc
.LFE4852:
	.size	sgxsd_enclave_server_terminate, .-sgxsd_enclave_server_terminate
	.section	.rodata.cst32,"aM",@progbits,32
	.align 32
.LC0:
	.quad	-4
	.quad	-3
	.quad	-2
	.quad	-1
	.align 32
.LC1:
	.quad	-8
	.quad	-7
	.quad	-6
	.quad	-5
	.align 32
.LC2:
	.quad	-12
	.quad	-11
	.quad	-10
	.quad	-9
	.align 32
.LC3:
	.long	4294967284
	.long	-1
	.long	4294967285
	.long	-1
	.long	4294967286
	.long	-1
	.long	4294967287
	.long	-1
	.align 32
.LC4:
	.long	4294967288
	.long	-1
	.long	4294967289
	.long	-1
	.long	4294967290
	.long	-1
	.long	4294967291
	.long	-1
	.align 32
.LC5:
	.long	4294967292
	.long	-1
	.long	4294967293
	.long	-1
	.long	4294967294
	.long	-1
	.long	4294967295
	.long	-1
	.align 32
.LC6:
	.long	4294967295
	.long	-1
	.long	4294967295
	.long	-1
	.long	4294967295
	.long	-1
	.long	4294967295
	.long	-1
	.ident	"GCC: (Debian 6.3.0-18) 6.3.0 20170516"
	.section	.note.GNU-stack,"",@progbits
