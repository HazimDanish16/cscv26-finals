# CRYPT03 (500, crypto) - HANDOFF NOTE
Target: nc 59.153.245.196 1338 | files: give_to_player.zip (aes.py, chall.py, core.c) copied here | public params in pub.txt
Status: CLAIMED in challs/INDEX.md. NOT solved. No flag. Nothing submitted. Nothing committed/pushed yet.
Working dir in WSL: ~/w/crypt03/dev (local key in key.txt, local test bitmap loc_0.bt 512MB, truth.txt). Copies of verify.c/gen.py/hist.c are in this folder.

## Challenge
6-round AES-128 (aes.py AES6), CTR flag: nonce 80e5faeca1828e3c, flag_ct 42 bytes = counters 0,1,2 (oracle rejects nonce||ctr<3). Key fixed per deployment.
Menu: 1 = encrypt any 16B block (except nonce||ctr 0..2); 2 = structure bitmap k in 0..5 (sends 512MB, ONE per connection, then server exits).
Bitmap = bit per 32-bit idx = parity of #plaintexts (of 2^32: base with bytes 0,5,10,15 = counter) whose ct gives
idx = c7<<24|c10<<16|c13<<8|c0. File: 16B header then 2^26+1 uint64 words, bit idx at word idx>>6, bit idx&63.
Bases are public (pub.txt), byte1 of each = nonce[1]^0xff (purpose unclear; maybe irrelevant).
Goal: recover key, then flag = crypt(flag_ct, key, nonce). Flag format CSCV2026{...}.

## Verified math (tested locally, ~27s per pass with verify.c on 16 threads)
- ct bytes 0,7,10,13 are all from column 0 of round-5 output X5 (rows 0,3,2,1): t_r = SB^-1(c_r ^ k6_r). Use idx byte r = row r: row0=c0 (bits0-7), row1=c13, row2=c10, row3=c7.
- w_j = (InvMixCol(t))_j ^ kappa_j, kappa = InvMixCol(k5 col0). u_j = SB^-1(w_j) is round-4-output diag byte, XOR-balanced over the 2^32 set.
- Test: H_j[y] = XOR of B[idx] over idx with (InvMC t)_j == y; candidate kappa valid iff XOR_y H_j[y]*SB^-1(y^kappa)==0.
- Confirmed: with the TRUE k6 bytes (rows0..3 = 90 fe fa 0a for local key) the true kappa (3d 2b 5c 0b) appears in the zero list for each j. (verify.c <bitmap> q0 q1 q2 q3)
- Round-4 diag byte marginals are NOT exactly uniform (only XOR-balanced), so no kappa-free all-zero-H check.
- Wrong k6 guesses also usually have SOME kappa with zero sum (~1 per j per base) -> need to intersect kappa sets across several bases (same k6, same kappa for all bases). Expect ~5-6 bases to kill false positives over 2^32 candidates.

## Plan / TODO
1. Write partial-sum solver for the 2^32 k6 search (4 bytes q0..q3). Idea: process k1 (permute rows), loop k0 with xor-shifted 256-bit row XORs, then k2, then k3 stages; ~2^40 AVX2 vector ops per (base,j) pass. Memory: bitmaps 512MB each, box has 7GB RAM, 16 threads, RTX 3050, 900GB disk. Test on local bitmaps (make more with gen.py: needs different base each, same key.txt) before touching the server.
2. Intersect surviving (q,kappa_j) across bases/j. Recovers k6 at 4 positions + k5 col0 (64 bits). 
3. OPEN PROBLEM: remaining ~64 key bits. Key schedule: w24=w20^Sub(Rot(w23))^rcon, w25=w21^w24, w26=w22^w25, w27=w23^w26. Known after step 2: w20 (full), w24[0],w25[3],w26[2],w27[1]. That gives w23[1] and 3 more relations but leaves ~64 free bits; 2^64 brute force is infeasible. Observation: once q,kappa known, the oracle gives the exact round-4 diag bytes u for ANY chosen plaintext (c -> t -> InvMC -> SB^-1), i.e. a 4-round AES with diag-only observation. Need an idea to get remaining bits from that (smaller chosen-plaintext sets via oracle, or further structure in the bitmaps). Not solved. Check also whether other info in the 6 bitmaps helps.
4. Then decrypt flag: aes.crypt(flag_ct, key, nonce). Verify with pt 00*16 -> ct 5d3d1ede1baef0f9beb46d8ea6256283. Beware decoys; do not submit without user's go-ahead (CLAUDE.md).

## Later local test (Codex, 16 Oct 2026)
Added `sat_local.py` to test whether Z3 can recover the remaining key from a known round-5 column, four diagonal round-6 bytes, and one full plaintext/ciphertext pair. It builds the AES-128 key schedule backward from round 5 and symbolically encrypts 6 rounds. The known local key `baede44713232645b9c881934ce63e7d` yielded `unknown` at the 60-second solver timeout. This is only a bounded negative benchmark, not proof that SAT is infeasible; no live bitmap was fetched and no flag was found.

## Rules reminders
- Only attack the given nc target; fetch bitmaps sparingly (1 per connection, 512MB each, live limits unknown). Don't touch jeo.cscv.vn.
- State runtime estimate before long runs (brute-force policy). Write writeup.md + solve.py and update INDEX.md once flag confirmed.
