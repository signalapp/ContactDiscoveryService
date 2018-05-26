	.file	"sabd-enclave.c"
# GNU C11 (Debian 6.3.0-18+deb9u1) version 6.3.0 20170516 (x86_64-linux-gnu)
#	compiled by GNU C version 6.3.0 20170516, GMP version 6.1.2, MPFR version 3.1.5, MPC version 1.0.3, isl version 0.15
# GGC heuristics: --param ggc-min-expand=100 --param ggc-min-heapsize=131072
# options passed:  -I include -I include/bearssl
# -I linux-sgx-sgx_2.1.3-g75dd558bdaff/common/inc
# -I linux-sgx-sgx_2.1.3-g75dd558bdaff/common/inc/tlibc
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
	leal	-1(%rcx), %ebx	#, tmp538
	bsrl	%ebx, %ebx	# tmp538, tmp537
	addl	$1, %ebx	#, iftmp.0_40
	cmpl	$13, %ebx	#, iftmp.0_40
	ja	.L27	#,
	movl	$12, %eax	#, tmp542
	movl	$1, %r13d	#, tmp540
	shlx	%ebx, %eax, %eax	# iftmp.0_40, tmp542, tmp543
	salq	$3, %rax	#, _642
	shlx	%ebx, %r13d, %r13d	# iftmp.0_40, tmp540, _636
	movq	%rax, -264(%rbp)	# _642, %sfp
.L24:
	movq	%rsi, -296(%rbp)	# in_jid_count, %sfp
	movq	-264(%rbp), %rsi	# %sfp,
	movl	%ecx, %r12d	# ab_jid_count, ab_jid_count
	movq	%rdx, %r14	# ab_jids, ab_jids
	movq	%rdi, -288(%rbp)	# in_jids, %sfp
	movl	$64, %edi	#,
	movq	%r8, -304(%rbp)	# in_ab_jids_result, %sfp
	call	memalign@PLT	#
	movq	%rax, %r15	#, hashed_ab_jids
	testq	%rax, %rax	# hashed_ab_jids
	je	.L28	#,
	movl	%r13d, %r9d	# _636, _636
	movl	$64, %edi	#,
	addq	%r9, %r9	# in_hashed_ab_jids_result_bits_size
	movq	%r9, %rsi	# in_hashed_ab_jids_result_bits_size,
	movq	%r9, -112(%rbp)	# in_hashed_ab_jids_result_bits_size, %sfp
	call	memalign@PLT	#
	movq	-112(%rbp), %r9	# %sfp, in_hashed_ab_jids_result_bits_size
	testq	%rax, %rax	# in_hashed_ab_jids_result_bits
	je	.L46	#,
	movq	%r9, %rcx	# in_hashed_ab_jids_result_bits_size,
	movq	%r9, %rsi	# in_hashed_ab_jids_result_bits_size,
	xorl	%edx, %edx	#
	movq	%rax, %rdi	# in_hashed_ab_jids_result_bits,
	movq	%rax, -112(%rbp)	# in_hashed_ab_jids_result_bits, %sfp
	call	memset_s@PLT	#
	movl	%r12d, %esi	# ab_jid_count, _70
	movl	$255, %edx	#,
	movq	-304(%rbp), %rdi	# %sfp,
	movq	%rsi, %rcx	# _70,
	call	memset_s@PLT	#
	movq	-264(%rbp), %rsi	# %sfp, _642
	movq	%r15, %rdi	# hashed_ab_jids,
	xorl	%edx, %edx	#
	movq	%rsi, %rcx	# _642,
	call	memset_s@PLT	#
	movl	$1, %eax	#, tmp545
	movq	-112(%rbp), %r8	# %sfp, in_hashed_ab_jids_result_bits
	movl	$128, -276(%rbp)	#, %sfp
	shlx	%ebx, %eax, %ebx	# iftmp.0_40, tmp545, _660
	leal	-1(%r12), %eax	#, tmp547
	subl	$1, %ebx	#, _679
	vmovapd	.LC6(%rip), %ymm11	#, tmp821
	leaq	8(%r14,%rax,8), %r9	#, _372
	vmovdqa	.LC0(%rip), %ymm14	#, chain_block_masks$0
	leaq	-64(%rbp), %rax	#, tmp811
	vmovdqa	.LC1(%rip), %ymm13	#, chain_block_masks$1
	vmovdqa	.LC2(%rip), %ymm12	#, chain_block_masks$2
	movq	%r8, -272(%rbp)	# in_hashed_ab_jids_result_bits, %sfp
	movq	%r14, %r8	# ab_jids, ab_jids
	movl	%r13d, %r14d	# _636, _636
	movq	%r15, %r13	# hashed_ab_jids, hashed_ab_jids
	movl	%r12d, %r15d	# ab_jid_count, ab_jid_count
	movl	%ebx, %r12d	# _679, _679
	movq	%r9, %rbx	# _372, _372
	movq	%rax, %r9	# tmp811, tmp811
.L5:
	movl	$10, %ecx	#, ivtmp_187
	movl	$1, %edx	#, tmp552
.L7:
	rdrand	%rax	# tmp551
	movq	%rax, (%r9)	# tmp551,
	cmovc	%edx, %eax	# tmp551,, tmp552, _295
	testl	%eax, %eax	# _295
	je	.L10	#,
	rdrand	%rax	# tmp555
	movq	%rax, 8(%r9)	# tmp555,
	cmovc	%edx, %eax	# tmp555,, tmp552, _292
	testl	%eax, %eax	# _292
	je	.L10	#,
	vmovq	-56(%rbp), %xmm6	# MEM[(uint64_t *)&hash_salt_64 + 8B], tmp938
	movq	%r13, %r10	# hashed_ab_jids, ivtmp.122
	xorl	%edi, %edi	# hash_slot_idx
	xorl	%r11d, %r11d	# any_hash_slots_overflowed
	vpinsrq	$1, -64(%rbp), %xmm6, %xmm3	# MEM[(uint64_t *)&hash_salt_64], tmp938, tmp693
	vpslldq	$4, %xmm3, %xmm0	#, tmp940, tmp698
	vaeskeygenassist	$1, %xmm3, %xmm2	#, tmp693, tmp696
	vmovaps	%xmm3, -256(%rbp)	# tmp693, %sfp
	vpxor	%xmm3, %xmm0, %xmm0	# tmp693, tmp698, _385
	vpshufd	$255, %xmm2, %xmm2	#, tmp696, tmp704
	vpslldq	$4, %xmm0, %xmm1	#, _385, tmp700
	vpxor	%xmm1, %xmm0, %xmm0	# tmp700, _385, _389
	vpslldq	$4, %xmm0, %xmm1	#, _389, tmp702
	vpxor	%xmm2, %xmm1, %xmm1	# tmp704, tmp702, tmp706
	vpxor	%xmm0, %xmm1, %xmm10	# _389, tmp706, _398
	vpslldq	$4, %xmm10, %xmm0	#, _398, tmp709
	vaeskeygenassist	$2, %xmm10, %xmm2	#, _398, tmp707
	vpxor	%xmm0, %xmm10, %xmm0	# tmp709, _398, _402
	vpshufd	$255, %xmm2, %xmm2	#, tmp707, tmp715
	vpslldq	$4, %xmm0, %xmm1	#, _402, tmp711
	vpxor	%xmm1, %xmm0, %xmm0	# tmp711, _402, _406
	vpslldq	$4, %xmm0, %xmm1	#, _406, tmp713
	vpxor	%xmm2, %xmm1, %xmm1	# tmp715, tmp713, tmp717
	vpxor	%xmm0, %xmm1, %xmm3	# _406, tmp717, _415
	vpslldq	$4, %xmm3, %xmm0	#, tmp944, tmp720
	vaeskeygenassist	$4, %xmm3, %xmm2	#, _415, tmp718
	vmovaps	%xmm3, -112(%rbp)	# _415, %sfp
	vpxor	%xmm3, %xmm0, %xmm0	# _415, tmp720, _419
	vpshufd	$255, %xmm2, %xmm2	#, tmp718, tmp726
	vpslldq	$4, %xmm0, %xmm1	#, _419, tmp722
	vpxor	%xmm1, %xmm0, %xmm0	# tmp722, _419, _423
	vpslldq	$4, %xmm0, %xmm1	#, _423, tmp724
	vpxor	%xmm2, %xmm1, %xmm1	# tmp726, tmp724, tmp728
	vpxor	%xmm0, %xmm1, %xmm6	# _423, tmp728, _432
	vpslldq	$4, %xmm6, %xmm0	#, tmp948, tmp731
	vaeskeygenassist	$8, %xmm6, %xmm2	#, _432, tmp729
	vmovaps	%xmm6, -144(%rbp)	# _432, %sfp
	vpxor	%xmm6, %xmm0, %xmm0	# _432, tmp731, _436
	vpshufd	$255, %xmm2, %xmm2	#, tmp729, tmp737
	vpslldq	$4, %xmm0, %xmm1	#, _436, tmp733
	vpxor	%xmm1, %xmm0, %xmm0	# tmp733, _436, _440
	vpslldq	$4, %xmm0, %xmm1	#, _440, tmp735
	vpxor	%xmm2, %xmm1, %xmm1	# tmp737, tmp735, tmp739
	vpxor	%xmm0, %xmm1, %xmm3	# _440, tmp739, _449
	vpslldq	$4, %xmm3, %xmm0	#, tmp952, tmp742
	vaeskeygenassist	$16, %xmm3, %xmm2	#, _449, tmp740
	vmovaps	%xmm3, -176(%rbp)	# _449, %sfp
	vpxor	%xmm3, %xmm0, %xmm0	# _449, tmp742, _453
	vpshufd	$255, %xmm2, %xmm2	#, tmp740, tmp748
	vpslldq	$4, %xmm0, %xmm1	#, _453, tmp744
	vpxor	%xmm1, %xmm0, %xmm0	# tmp744, _453, _457
	vpslldq	$4, %xmm0, %xmm1	#, _457, tmp746
	vpxor	%xmm2, %xmm1, %xmm1	# tmp748, tmp746, tmp750
	vpxor	%xmm0, %xmm1, %xmm2	# _457, tmp750, _466
	vmovdqa	%xmm2, %xmm6	# _466, _466
	vmovaps	%xmm2, -208(%rbp)	# _466, %sfp
	vaeskeygenassist	$32, %xmm2, %xmm2	#, _466, tmp751
	vpslldq	$4, %xmm6, %xmm0	#, tmp956, tmp753
	vpshufd	$255, %xmm2, %xmm2	#, tmp751, tmp759
	vpxor	%xmm6, %xmm0, %xmm0	# _466, tmp753, _470
	vpslldq	$4, %xmm0, %xmm1	#, _470, tmp755
	vpxor	%xmm1, %xmm0, %xmm0	# tmp755, _470, _474
	vpslldq	$4, %xmm0, %xmm1	#, _474, tmp757
	vpxor	%xmm2, %xmm1, %xmm1	# tmp759, tmp757, tmp761
	vpxor	%xmm0, %xmm1, %xmm2	# _474, tmp761, _483
	vmovdqa	%xmm2, %xmm3	# _483, _483
	vmovaps	%xmm2, -80(%rbp)	# _483, %sfp
	vaeskeygenassist	$64, %xmm2, %xmm2	#, _483, tmp762
	vpslldq	$4, %xmm3, %xmm0	#, tmp960, tmp764
	vpshufd	$255, %xmm2, %xmm2	#, tmp762, tmp770
	vpxor	%xmm3, %xmm0, %xmm0	# _483, tmp764, _487
	vpslldq	$4, %xmm0, %xmm1	#, _487, tmp766
	vpxor	%xmm1, %xmm0, %xmm0	# tmp766, _487, _491
	vpslldq	$4, %xmm0, %xmm1	#, _491, tmp768
	vpxor	%xmm2, %xmm1, %xmm1	# tmp770, tmp768, tmp772
	vpxor	%xmm0, %xmm1, %xmm2	# _491, tmp772, _500
	vpslldq	$4, %xmm2, %xmm0	#, tmp964, tmp775
	vaeskeygenassist	$128, %xmm2, %xmm1	#, _500, tmp773
	vmovaps	%xmm2, -224(%rbp)	# _500, %sfp
	vpxor	%xmm2, %xmm0, %xmm0	# _500, tmp775, _504
	vpshufd	$255, %xmm1, %xmm1	#, tmp773, tmp781
	vpslldq	$4, %xmm0, %xmm8	#, _504, tmp777
	vpxor	%xmm8, %xmm0, %xmm0	# tmp777, _504, _508
	vpslldq	$4, %xmm0, %xmm8	#, _508, tmp779
	vpxor	%xmm1, %xmm8, %xmm8	# tmp781, tmp779, tmp783
	vpxor	%xmm0, %xmm8, %xmm8	# _508, tmp783, _517
	vpslldq	$4, %xmm8, %xmm0	#, _517, tmp786
	vaeskeygenassist	$27, %xmm8, %xmm1	#, _517, tmp784
	vpxor	%xmm0, %xmm8, %xmm0	# tmp786, _517, _521
	vpshufd	$255, %xmm1, %xmm1	#, tmp784, tmp792
	vpslldq	$4, %xmm0, %xmm9	#, _521, tmp788
	vpxor	%xmm9, %xmm0, %xmm0	# tmp788, _521, _525
	vpslldq	$4, %xmm0, %xmm9	#, _525, tmp790
	vpxor	%xmm1, %xmm9, %xmm9	# tmp792, tmp790, tmp794
	vpxor	%xmm0, %xmm9, %xmm9	# _525, tmp794, _534
	vpslldq	$4, %xmm9, %xmm0	#, _534, tmp797
	vaeskeygenassist	$54, %xmm9, %xmm2	#, _534, tmp795
	vpxor	%xmm0, %xmm9, %xmm0	# tmp797, _534, _538
	vpshufd	$255, %xmm2, %xmm2	#, tmp795, tmp803
	vpslldq	$4, %xmm0, %xmm1	#, _538, tmp799
	vpxor	%xmm1, %xmm0, %xmm0	# tmp799, _538, _542
	vpslldq	$4, %xmm0, %xmm1	#, _542, tmp801
	vpxor	%xmm2, %xmm1, %xmm1	# tmp803, tmp801, tmp805
	vpxor	%xmm0, %xmm1, %xmm2	# _542, tmp805, _551
	vmovaps	%xmm2, -240(%rbp)	# _551, %sfp
	.p2align 4,,10
	.p2align 3
.L25:
	testl	%r15d, %r15d	# ab_jid_count
	je	.L29	#,
	vpxor	%xmm6, %xmm6, %xmm6	# chain_blocks$0
	movq	%r8, %rcx	# ab_jids, ivtmp.117
	vmovdqa	%ymm14, %ymm3	# chain_block_masks$0, chain_block_masks$0
	xorl	%esi, %esi	# chain_idx
	vmovdqa	%ymm6, %ymm5	#, chain_blocks$1
	vmovdqa	%ymm6, %ymm4	# tmp26, chain_blocks$2
	vmovdqa	%ymm13, %ymm2	# chain_block_masks$1, chain_block_masks$1
	vmovdqa	%ymm12, %ymm1	# chain_block_masks$2, chain_block_masks$2
	.p2align 4,,10
	.p2align 3
.L11:
	vmovq	(%rcx), %xmm7	# MEM[base: _427, offset: 0B], tmp558
	vpxor	-256(%rbp), %xmm7, %xmm7	# %sfp, tmp558, tmp559
	xorl	%edx, %edx	# tmp580
	vpbroadcastq	(%rcx), %ymm0	# MEM[base: _427, offset: 0B], tmp557
	vaesenc	%xmm10, %xmm7, %xmm7	# _398, tmp559, tmp560
	vaesenc	-112(%rbp), %xmm7, %xmm7	# %sfp, tmp560, tmp561
	vpcmpeqq	%ymm0, %ymm5, %ymm15	# tmp557, chain_blocks$1, tmp573
	vaesenc	-144(%rbp), %xmm7, %xmm7	# %sfp, tmp561, tmp562
	vaesenc	-176(%rbp), %xmm7, %xmm7	# %sfp, tmp562, tmp563
	vaesenc	-208(%rbp), %xmm7, %xmm7	# %sfp, tmp563, tmp564
	vaesenc	-80(%rbp), %xmm7, %xmm7	# %sfp, tmp564, tmp565
	vaesenc	-224(%rbp), %xmm7, %xmm7	# %sfp, tmp565, tmp566
	vaesenc	%xmm8, %xmm7, %xmm7	# _517, tmp566, tmp567
	vaesenc	%xmm9, %xmm7, %xmm7	# _534, tmp567, tmp568
	vaesenclast	-240(%rbp), %xmm7, %xmm7	# %sfp, tmp568, tmp569
	vmovd	%xmm7, %eax	#, tmp571
	vpcmpeqq	%ymm6, %ymm0, %ymm7	# chain_blocks$0, tmp557, tmp575
	vpor	%ymm7, %ymm15, %ymm7	# tmp575, tmp573, tmp576
	vpcmpeqq	%ymm4, %ymm0, %ymm15	# chain_blocks$2, tmp557, tmp578
	vpor	%ymm15, %ymm7, %ymm7	# tmp578, tmp576, tmp579
	vblendvpd	%ymm3, %ymm0, %ymm6, %ymm15	# chain_block_masks$0, _139, chain_blocks$0, _154
	vtestpd	%ymm7, %ymm7	# tmp579, tmp579
	vblendvpd	%ymm2, %ymm0, %ymm5, %ymm7	# chain_block_masks$1, _139, chain_blocks$1, _155
	vmovdqa	%ymm15, %ymm6	# _154, chain_blocks$0
	vblendvpd	%ymm1, %ymm0, %ymm4, %ymm0	# chain_block_masks$2, _139, chain_blocks$2, _157
	sete	%dl	#, tmp580
	andl	%r12d, %eax	# _679, tmp581
	addq	$8, %rcx	#, ivtmp.117
	xorl	%edi, %eax	# hash_slot_idx, tmp583
	subq	$1, %rax	#, tmp584
	shrq	$32, %rax	#, tmp585
	andq	%rdx, %rax	# tmp580, should_insert_jid
	vmovq	%rax, %xmm5	# should_insert_jid, should_insert_jid
	addl	%eax, %esi	# should_insert_jid, chain_idx
	vpbroadcastq	%xmm5, %ymm4	# should_insert_jid, tmp600
	vmovdqa	%ymm7, %ymm5	# _155, chain_blocks$1
	vpaddq	%ymm4, %ymm1, %ymm1	# tmp600, chain_block_masks$2, chain_block_masks$2
	vpaddq	%ymm4, %ymm2, %ymm2	# tmp600, chain_block_masks$1, chain_block_masks$1
	vpaddq	%ymm4, %ymm3, %ymm3	# tmp600, chain_block_masks$0, chain_block_masks$0
	vmovdqa	%ymm0, %ymm4	# _157, chain_blocks$2
	cmpq	%rcx, %rbx	# ivtmp.117, _372
	jne	.L11	#,
	cmpl	$12, %esi	#, chain_idx
	seta	%al	#, _674
.L13:
	vblendvpd	%ymm3, %ymm11, %ymm15, %ymm3	# _662, tmp821, _154, tmp602
	addl	$1, %edi	#, hash_slot_idx
	orl	%eax, %r11d	# _674, any_hash_slots_overflowed
	addq	$96, %r10	#, ivtmp.122
	vblendvpd	%ymm2, %ymm11, %ymm7, %ymm2	# _666, tmp821, _155, tmp606
	vblendvpd	%ymm1, %ymm11, %ymm0, %ymm0	# _670, tmp821, _157, tmp610
	vmovdqa	%ymm3, -96(%r10)	# tmp602, MEM[base: _335, offset: 0B]
	vmovdqa	%ymm2, -64(%r10)	# tmp606, MEM[base: _335, offset: 32B]
	vmovdqa	%ymm0, -32(%r10)	# tmp610, MEM[base: _335, offset: 64B]
	cmpl	%r14d, %edi	# _636, hash_slot_idx
	jne	.L25	#,
	testb	%r11b, %r11b	# any_hash_slots_overflowed
	jne	.L47	#,
	movq	-288(%rbp), %rdi	# %sfp, ivtmp.112
	movq	-296(%rbp), %rax	# %sfp, in_jid_count
	movl	%r12d, %ebx	# _679, _679
	movl	%r15d, %r12d	# ab_jid_count, ab_jid_count
	movq	%r13, %r15	# hashed_ab_jids, hashed_ab_jids
	movl	%r14d, %r13d	# _636, _636
	movq	%r8, %r14	# ab_jids, ab_jids
	movq	-272(%rbp), %r8	# %sfp, in_hashed_ab_jids_result_bits
	leaq	(%rdi,%rax,8), %rcx	#, _495
	testq	%rax, %rax	# in_jid_count
	je	.L17	#,
	vmovdqa	-112(%rbp), %xmm2	# %sfp, _415
	vmovdqa	-144(%rbp), %xmm3	# %sfp, _432
	vmovdqa	-176(%rbp), %xmm4	# %sfp, _449
	vmovdqa	-208(%rbp), %xmm5	# %sfp, _466
	vmovdqa	-80(%rbp), %xmm6	# %sfp, _483
	vmovdqa	-224(%rbp), %xmm7	# %sfp, _500
	vmovdqa	-240(%rbp), %xmm11	# %sfp, _551
	vmovdqa	-256(%rbp), %xmm12	# %sfp, tmp693
.L31:
	vmovq	(%rdi), %xmm0	# MEM[base: _546, offset: 0B], tmp616
	vpbroadcastq	(%rdi), %ymm1	# MEM[base: _546, offset: 0B], tmp615
	addq	$8, %rdi	#, ivtmp.112
	vpxor	%xmm12, %xmm0, %xmm0	# tmp693, tmp616, tmp617
	vaesenc	%xmm10, %xmm0, %xmm0	# _398, tmp617, tmp618
	vaesenc	%xmm2, %xmm0, %xmm0	# _415, tmp618, tmp619
	vaesenc	%xmm3, %xmm0, %xmm0	# _432, tmp619, tmp620
	vaesenc	%xmm4, %xmm0, %xmm0	# _449, tmp620, tmp621
	vaesenc	%xmm5, %xmm0, %xmm0	# _466, tmp621, tmp622
	vaesenc	%xmm6, %xmm0, %xmm0	# _483, tmp622, tmp623
	vaesenc	%xmm7, %xmm0, %xmm0	# _500, tmp623, tmp624
	vaesenc	%xmm8, %xmm0, %xmm0	# _517, tmp624, tmp625
	vaesenc	%xmm9, %xmm0, %xmm0	# _534, tmp625, tmp626
	vaesenclast	%xmm11, %xmm0, %xmm0	# _551, tmp626, tmp627
	vmovd	%xmm0, %eax	#, tmp629
	andl	%ebx, %eax	# _679, _365
	leal	(%rax,%rax,2), %edx	#, tmp632
	cltq
	sall	$2, %edx	#,
	leaq	(%r15,%rdx,8), %rsi	#, chain_blocks
	vmovdqa	(%rsi), %ymm0	# *chain_blocks_205, *chain_blocks_205
	vpcmpeqq	%ymm1, %ymm0, %ymm0	# tmp615, *chain_blocks_205, tmp639
	vmovmskpd	%ymm0, %edx	# tmp639, tmp636
	vmovdqa	32(%rsi), %ymm0	# MEM[(__m256i * {ref-all})chain_blocks_205 + 32B], MEM[(__m256i * {ref-all})chain_blocks_205 + 32B]
	vpcmpeqq	%ymm1, %ymm0, %ymm0	# tmp615, MEM[(__m256i * {ref-all})chain_blocks_205 + 32B], tmp644
	vmovmskpd	%ymm0, %r11d	# tmp644, tmp641
	vmovdqa	64(%rsi), %ymm0	# MEM[(__m256i * {ref-all})chain_blocks_205 + 64B], MEM[(__m256i * {ref-all})chain_blocks_205 + 64B]
	leaq	(%r8,%rax,2), %rsi	#, chain_result_bits
	movl	%r11d, %eax	# tmp641, tmp641
	movzwl	(%rsi), %r9d	# *chain_result_bits_227, _228
	vpcmpeqq	%ymm1, %ymm0, %ymm1	# tmp615, MEM[(__m256i * {ref-all})chain_blocks_205 + 64B], tmp649
	sall	$4, %eax	#, tmp641
	xorw	$-4096, %r9w	#, tmp657
	vmovmskpd	%ymm1, %r10d	# tmp649, tmp646
	sall	$8, %r10d	#, tmp654
	orl	%r10d, %eax	# tmp654, tmp655
	orl	%edx, %eax	# tmp636, chain_eq_mask
	orl	%r9d, %eax	# tmp657, _230
	movw	%ax, (%rsi)	# _230, *chain_result_bits_227
	cmpq	%rdi, %rcx	# ivtmp.112, _495
	jne	.L31	#,
.L17:
	testl	%r12d, %r12d	# ab_jid_count
	je	.L48	#,
	leal	-1(%r13), %eax	#,
	movq	-304(%rbp), %r13	# %sfp, in_ab_jids_result
	xorl	%ebx, %ebx	# ivtmp.104
	movl	%eax, -112(%rbp)	# tmp809, %sfp
	leaq	2(%r8,%rax,2), %r11	#, _559
	.p2align 4,,10
	.p2align 3
.L20:
	vpbroadcastq	(%r14,%rbx,8), %ymm1	# MEM[base: ab_jids_111(D), index: ivtmp.104_558, step: 8, offset: 0B], _310
	movq	%r15, %rsi	# hashed_ab_jids, ivtmp.99
	movq	%r8, %rdi	# in_hashed_ab_jids_result_bits, ivtmp.100
	xorl	%r10d, %r10d	# ab_jid_result
	.p2align 4,,10
	.p2align 3
.L19:
	vmovdqa	(%rsi), %ymm0	# MEM[base: _569, offset: 0B], MEM[base: _569, offset: 0B]
	movzwl	(%rdi), %r9d	# *_270, _271
	addq	$2, %rdi	#, ivtmp.100
	addq	$96, %rsi	#, ivtmp.99
	vpcmpeqq	%ymm1, %ymm0, %ymm0	# _310, MEM[base: _569, offset: 0B], tmp666
	andw	$4095, %r9w	#, chain_result
	vmovmskpd	%ymm0, %ecx	# tmp666, tmp663
	vmovdqa	-64(%rsi), %ymm0	# MEM[base: _569, offset: 32B], MEM[base: _569, offset: 32B]
	vpcmpeqq	%ymm1, %ymm0, %ymm0	# _310, MEM[base: _569, offset: 32B], tmp671
	vmovmskpd	%ymm0, %eax	# tmp671, tmp668
	vmovdqa	-32(%rsi), %ymm0	# MEM[base: _569, offset: 64B], MEM[base: _569, offset: 64B]
	sall	$4, %eax	#, tmp678
	vpcmpeqq	%ymm1, %ymm0, %ymm0	# _310, MEM[base: _569, offset: 64B], tmp676
	vmovmskpd	%ymm0, %edx	# tmp676, tmp673
	sall	$8, %edx	#, tmp679
	orl	%eax, %edx	# tmp678, tmp680
	orl	%edx, %ecx	# tmp680, chain_eq_mask
	andl	%ecx, %r9d	# chain_eq_mask, tmp683
	orl	%r9d, %r10d	# tmp683, ab_jid_result
	cmpq	%rdi, %r11	# ivtmp.100, _559
	jne	.L19	#,
	testw	%r10w, %r10w	# ab_jid_result
	leaq	0(%r13,%rbx), %rax	#, _556
	setne	%dl	#, tmp684
	addq	$1, %rbx	#, ivtmp.104
	movb	%dl, (%rax)	# tmp684, *_556
	cmpl	%ebx, %r12d	# ivtmp.104, ab_jid_count
	ja	.L20	#,
	movl	-112(%rbp), %r13d	# %sfp,
.L21:
	movq	%r8, %rdx	# in_hashed_ab_jids_result_bits, ivtmp.91
	leaq	2(%r8,%r13,2), %rcx	#, _577
	vpxor	%xmm0, %xmm0, %xmm0	# tmp689
	movq	%r15, %rax	# hashed_ab_jids, ivtmp.92
	.p2align 4,,10
	.p2align 3
.L22:
	movl	$-32768, %esi	#,
	addq	$2, %rdx	#, ivtmp.91
	addq	$96, %rax	#, ivtmp.92
	movw	%si, -2(%rdx)	#, *_286
	vmovdqa	%ymm0, -96(%rax)	# tmp689, *chain_blocks_291
	vmovdqa	%ymm0, -64(%rax)	# tmp689, MEM[(volatile __m256i * {ref-all})chain_blocks_291 + 32B]
	vmovdqa	%ymm0, -32(%rax)	# tmp689, MEM[(volatile __m256i * {ref-all})chain_blocks_291 + 64B]
	cmpq	%rdx, %rcx	# ivtmp.91, _577
	jne	.L22	#,
	movq	%r8, %rdi	# in_hashed_ab_jids_result_bits,
	vzeroupper
	call	free@PLT	#
	movq	%r15, %rdi	# hashed_ab_jids,
	call	free@PLT	#
	xorl	%eax, %eax	# <retval>
.L41:
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
.L47:
	.cfi_restore_state
	movq	-264(%rbp), %rsi	# %sfp, _642
	xorl	%edx, %edx	#
	movq	%r13, %rdi	# hashed_ab_jids,
	movq	%r9, -80(%rbp)	# tmp811, %sfp
	movq	%r8, -224(%rbp)	# ab_jids, %sfp
	movq	%rsi, %rcx	# _642,
	vmovdqa	%ymm12, -208(%rbp)	# chain_block_masks$2, %sfp
	vmovdqa	%ymm13, -176(%rbp)	# chain_block_masks$1, %sfp
	vmovdqa	%ymm14, -144(%rbp)	# chain_block_masks$0, %sfp
	vmovapd	%ymm11, -112(%rbp)	# tmp821, %sfp
	vzeroupper
	call	memset_s@PLT	#
	subl	$1, -276(%rbp)	#, %sfp
	vmovapd	-112(%rbp), %ymm11	# %sfp, tmp821
	vmovdqa	-144(%rbp), %ymm14	# %sfp, chain_block_masks$0
	vmovdqa	-176(%rbp), %ymm13	# %sfp, chain_block_masks$1
	vmovdqa	-208(%rbp), %ymm12	# %sfp, chain_block_masks$2
	movq	-80(%rbp), %r9	# %sfp, tmp811
	movq	-224(%rbp), %r8	# %sfp, ab_jids
	jne	.L5	#,
.L43:
	movq	-272(%rbp), %r8	# %sfp, in_hashed_ab_jids_result_bits
	movq	%r8, %rdi	# in_hashed_ab_jids_result_bits,
	vzeroupper
	call	free@PLT	#
	movq	%r13, %rdi	# hashed_ab_jids,
	call	free@PLT	#
	movl	$1, %eax	#, <retval>
	jmp	.L41	#
	.p2align 4,,10
	.p2align 3
.L29:
	vxorpd	%xmm0, %xmm0, %xmm0	# _157
	xorl	%eax, %eax	# _674
	vmovapd	.LC3(%rip), %ymm1	#, _670
	vmovapd	.LC4(%rip), %ymm2	#, _666
	vmovapd	%ymm0, %ymm7	#, _155
	vmovapd	%ymm0, %ymm15	#, _154
	vmovapd	.LC5(%rip), %ymm3	#, _662
	jmp	.L13	#
.L10:
	subl	$1, %ecx	#, ivtmp_187
	jne	.L7	#,
	jmp	.L43	#
.L2:
	testl	%ecx, %ecx	# ab_jid_count
	jne	.L49	#,
	xorl	%eax, %eax	# <retval>
	jmp	.L41	#
.L28:
	movl	$3, %eax	#, <retval>
	jmp	.L41	#
.L27:
	movl	$2, %eax	#, <retval>
	jmp	.L41	#
.L48:
	subl	$1, %r13d	#,
	jmp	.L21	#
.L46:
	movq	%r15, %rdi	# hashed_ab_jids,
	call	free@PLT	#
	movl	$3, %eax	#, <retval>
	jmp	.L41	#
.L49:
	movq	$96, -264(%rbp)	#, %sfp
	movl	$1, %r13d	#, _636
	xorl	%ebx, %ebx	# iftmp.0_40
	jmp	.L24	#
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
	je	.L61	#,
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
	je	.L56	#,
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
.L56:
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
.L61:
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
	pushq	%r14	#
	.cfi_def_cfa_offset 16
	.cfi_offset 14, -16
	movl	$5, %eax	#, <retval>
	pushq	%r13	#
	.cfi_def_cfa_offset 24
	.cfi_offset 13, -24
	pushq	%r12	#
	.cfi_def_cfa_offset 32
	.cfi_offset 12, -32
	pushq	%rbp	#
	.cfi_def_cfa_offset 40
	.cfi_offset 6, -40
	pushq	%rbx	#
	.cfi_def_cfa_offset 48
	.cfi_offset 3, -48
	movq	(%rcx), %rbx	# *pp_state_4(D), p_state
	testq	%rbx, %rbx	# p_state
	je	.L75	#,
	movl	$2, %eax	#, <retval>
	testq	%rdi, %rdi	# p_args
	je	.L75	#,
	movl	(%rdi), %ecx	# p_args_7(D)->ab_jid_count, _8
	testl	%ecx, %ecx	# _8
	jne	.L77	#,
.L75:
	popq	%rbx	#
	.cfi_remember_state
	.cfi_def_cfa_offset 40
	popq	%rbp	#
	.cfi_def_cfa_offset 32
	popq	%r12	#
	.cfi_def_cfa_offset 24
	popq	%r13	#
	.cfi_def_cfa_offset 16
	popq	%r14	#
	.cfi_def_cfa_offset 8
	ret
	.p2align 4,,10
	.p2align 3
.L77:
	.cfi_restore_state
	movl	12(%rbx), %r8d	# p_state_5->max_ab_jids, p_state_5->max_ab_jids
	subl	8(%rbx), %r8d	# p_state_5->ab_jid_count, tmp115
	cmpl	%r8d, %ecx	# tmp115, _8
	ja	.L75	#,
	testb	$7, %dl	#, msg
	jne	.L75	#,
	movl	%edx, %r8d	# msg, tmp118
	shrl	$3, %r8d	#, tmp118
	cmpl	%r8d, %ecx	# tmp118, _8
	jne	.L75	#,
	lfence
	movq	%rdi, %rbp	# p_args, p_args
	movl	$56, %edi	#,
	movq	%rdx, %r12	# msg, msg
	movq	%rsi, %r13	# msg, msg
	call	malloc@PLT	#
	movq	%rax, %r14	#, tmp119
	movl	$3, %eax	#, <retval>
	testq	%r14, %r14	# tmp119
	je	.L75	#,
	movq	(%rbx), %rax	# p_state_5->msgs, _18
	movl	$10, %ecx	#, tmp122
	movq	%r14, %rdi	# tmp119, p_sabd_msg
	leaq	48(%rsp), %rsi	#, tmp121
	rep movsl
	movl	0(%rbp), %edx	# p_args_7(D)->ab_jid_count, _17
	movq	%r13, %rsi	# msg,
	movq	%rax, 48(%r14)	# _18, p_sabd_msg_16->prev
	movl	8(%rbx), %eax	# p_state_5->ab_jid_count, p_state_5->ab_jid_count
	movl	%edx, 40(%r14)	# _17, p_sabd_msg_16->ab_jid_count
	movl	%r12d, %edx	# msg, msg$size
	movq	%r14, (%rbx)	# tmp119, p_state_5->msgs
	leaq	64(%rbx,%rax,8), %rdi	#, tmp126
	call	memcpy@PLT	#
	movl	40(%r14), %eax	# p_sabd_msg_16->ab_jid_count, p_sabd_msg_16->ab_jid_count
	addl	%eax, 8(%rbx)	# p_sabd_msg_16->ab_jid_count, p_state_5->ab_jid_count
	xorl	%edx, %edx	#
	movl	$40, %ecx	#,
	movl	$40, %esi	#,
	leaq	48(%rsp), %rdi	#,
	call	memset_s@PLT	#
	xorl	%eax, %eax	# <retval>
	jmp	.L75	#
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
	movl	$5, %ebp	#, <retval>
	pushq	%rbx	#
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	subq	$56, %rsp	#,
	.cfi_def_cfa_offset 112
	testq	%rsi, %rsi	# p_state
	je	.L105	#,
	movq	%rsi, %rbx	# p_state, p_state
	movq	%rdi, %rbp	# p_args, p_args
	testq	%rdi, %rdi	# p_args
	je	.L80	#,
	movabsq	$2305843009213693951, %rax	#, tmp125
	movq	8(%rdi), %r12	# p_args_21(D)->in_jid_count, _22
	cmpq	%rax, %r12	# tmp125, _22
	jbe	.L110	#,
.L80:
	movl	8(%rbx), %r13d	# p_state_19(D)->ab_jid_count, ab_jid_idx
	testl	%r13d, %r13d	# ab_jid_idx
	jne	.L111	#,
	movl	12(%rbx), %eax	# p_state_19(D)->max_ab_jids, p_state_19(D)->max_ab_jids
	xorl	%edx, %edx	#
	movq	%rbx, %rdi	# p_state,
	movl	$2, %ebp	#, <retval>
	leaq	64(,%rax,8), %rsi	#, state_size
	movq	%rsi, %rcx	# state_size,
	call	memset_s@PLT	#
	movq	%rbx, %rdi	# p_state,
	call	free@PLT	#
.L105:
	addq	$56, %rsp	#,
	.cfi_remember_state
	.cfi_def_cfa_offset 56
	movl	%ebp, %eax	# <retval>,
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
.L110:
	.cfi_restore_state
	movq	(%rdi), %rdi	# p_args_21(D)->in_jids,
	leaq	0(,%r12,8), %rsi	#, in_jids_size
	call	sgx_is_outside_enclave@PLT	#
	cmpl	$1, %eax	#, _26
	jne	.L80	#,
	movl	8(%rbx), %r13d	# p_state_19(D)->ab_jid_count, ab_jid_idx
	testl	%r13d, %r13d	# ab_jid_idx
	je	.L112	#,
	movl	%r13d, %edi	# ab_jid_idx, ab_jid_idx
	movl	$3, %r14d	#, lookup_res
	call	malloc@PLT	#
	movq	%rax, 40(%rsp)	# in_ab_jids_result, %sfp
	testq	%rax, %rax	# in_ab_jids_result
	je	.L88	#,
	lfence
	movl	8(%rbx), %ecx	# p_state_19(D)->ab_jid_count, p_state_19(D)->ab_jid_count
	leaq	64(%rbx), %rdx	#, tmp128
	movq	%r12, %rsi	# _22,
	movq	40(%rsp), %r8	# %sfp,
	movq	0(%rbp), %rdi	# p_args_21(D)->in_jids,
	call	sabd_lookup_hash	#
	movl	8(%rbx), %r13d	# p_state_19(D)->ab_jid_count, ab_jid_idx
	movl	%eax, %r14d	#, lookup_res
.L88:
	movq	(%rbx), %r15	# p_state_19(D)->msgs, p_msg
	testq	%r15, %r15	# p_msg
	je	.L83	#,
	xorl	%ebp, %ebp	# <retval>
	jmp	.L86	#
	.p2align 4,,10
	.p2align 3
.L84:
	movq	%r15, %rdi	# p_msg,
	movq	48(%r15), %r12	# p_msg_101->prev, p_prev_msg
	movl	$56, %ecx	#,
	xorl	%edx, %edx	#
	movl	$56, %esi	#,
	call	memset_s@PLT	#
	movq	%r15, %rdi	# p_msg,
	movq	%r12, %r15	# p_prev_msg, p_msg
	call	free@PLT	#
	testq	%r12, %r12	# p_msg
	je	.L113	#,
.L86:
	testl	%r14d, %r14d	# lookup_res
	jne	.L84	#,
	movl	40(%r15), %eax	# p_msg_101->ab_jid_count, _40
	subq	$8, %rsp	#,
	.cfi_def_cfa_offset 120
	subl	%eax, %r13d	# _40, ab_jid_idx
	movl	%r13d, %edx	# ab_jid_idx, ab_jid_idx
	addq	48(%rsp), %rdx	# %sfp, ab_jid_idx
	movq	%rdx, 24(%rsp)	# ab_jid_idx, %sfp
	vmovdqa	24(%rsp), %xmm1	# %sfp, tmp160
	vpinsrd	$2, %eax, %xmm1, %xmm0	#, _40, tmp160, tmp131
	vmovaps	%xmm0, 8(%rsp)	# tmp131, %sfp
	vmovdqa	8(%rsp), %xmm2	# %sfp, tmp161
	movq	16(%rsp), %rsi	# %sfp, tmp152
	vmovaps	%xmm2, 24(%rsp)	# tmp161, %sfp
	pushq	32(%r15)	# p_msg_101->from
	.cfi_def_cfa_offset 128
	pushq	24(%r15)	# p_msg_101->from
	.cfi_def_cfa_offset 136
	pushq	16(%r15)	# p_msg_101->from
	.cfi_def_cfa_offset 144
	pushq	8(%r15)	# p_msg_101->from
	.cfi_def_cfa_offset 152
	pushq	(%r15)	# p_msg_101->from
	.cfi_def_cfa_offset 160
	movq	48(%rsp), %rdi	# %sfp,
	call	sgxsd_enclave_server_reply@PLT	#
	addq	$48, %rsp	#,
	.cfi_def_cfa_offset 112
	testl	%ebp, %ebp	# <retval>
	cmove	%eax, %ebp	# reply_res,, <retval>
	jmp	.L84	#
	.p2align 4,,10
	.p2align 3
.L113:
	movq	40(%rsp), %rdi	# %sfp,
	call	free@PLT	#
	movl	12(%rbx), %eax	# p_state_19(D)->max_ab_jids, p_state_19(D)->max_ab_jids
	xorl	%edx, %edx	#
	movq	%rbx, %rdi	# p_state,
	leaq	64(,%rax,8), %rsi	#, state_size
	movq	%rsi, %rcx	# state_size,
	call	memset_s@PLT	#
	movq	%rbx, %rdi	# p_state,
	call	free@PLT	#
	testl	%r14d, %r14d	# lookup_res
	jne	.L107	#,
	cmpl	$2, %ebp	#, <retval>
	movl	$1, %eax	#, tmp153
	cmove	%eax, %ebp	# <retval>,, tmp153, <retval>
	jmp	.L105	#
	.p2align 4,,10
	.p2align 3
.L111:
	movl	%r13d, %edi	# ab_jid_idx, ab_jid_idx
	movl	$2, %r14d	#, lookup_res
	call	malloc@PLT	#
	movq	%rax, 40(%rsp)	#, %sfp
	jmp	.L88	#
.L83:
	movq	40(%rsp), %rdi	# %sfp,
	call	free@PLT	#
	movl	12(%rbx), %eax	# p_state_19(D)->max_ab_jids, p_state_19(D)->max_ab_jids
	movq	%rbx, %rdi	# p_state,
	xorl	%edx, %edx	#
	leaq	64(,%rax,8), %rsi	#, state_size
	movq	%rsi, %rcx	# state_size,
	call	memset_s@PLT	#
	movq	%rbx, %rdi	# p_state,
	call	free@PLT	#
.L107:
	movl	%r14d, %ebp	# lookup_res, <retval>
	jmp	.L105	#
.L112:
	movl	12(%rbx), %eax	# p_state_19(D)->max_ab_jids, p_state_19(D)->max_ab_jids
	xorl	%edx, %edx	#
	movq	%rbx, %rdi	# p_state,
	xorl	%ebp, %ebp	# <retval>
	leaq	64(,%rax,8), %rsi	#, state_size
	movq	%rsi, %rcx	# state_size,
	call	memset_s@PLT	#
	movq	%rbx, %rdi	# p_state,
	call	free@PLT	#
	jmp	.L105	#
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
	.ident	"GCC: (Debian 6.3.0-18+deb9u1) 6.3.0 20170516"
	.section	.note.GNU-stack,"",@progbits
