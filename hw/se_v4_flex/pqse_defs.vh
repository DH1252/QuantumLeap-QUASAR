// pqse_defs.vh - shared localparams, included inside module bodies

localparam [11:0] Q = 12'd3329;

// ---- ML-KEM parameter set (k = polynomials per vector) ---------------------
// Host selects it in CONFIG[2:1] (pqse_host.v); DECAPS uses the loaded key's k.
// Buffer windows are sized for k = 4.
localparam [1:0] PS_768 = 2'd0, PS_512 = 2'd1, PS_1024 = 2'd2;   // CONFIG[2:1]
localparam integer KMAX = 4;

// ---- I/O buffer: 512 lanes x 64 bit (4 KB), lane addresses ------------------
// Host access enforced in pqse_host.v (R = host read, W = host write).
// ek = 48 k + 4 lanes (t^ in 48-lane parts, rho last 4); ciphertext = DU k + DV
// lanes (DU, DV = 40, 16 for k = 2, 3; 44, 20 for k = 4).
// ENCAPS writes the ciphertext over the peer ek in B_XIN (v computed first, rho
// copied to B_TMP), so one 196-lane window serves input and output.
// B_XIN is host-readable only after ENCAPS (or a raw dump), until the next
// command or host write.
localparam [8:0] B_EKOWN  = 9'd0;     // 196 lanes  own ek = t^ (48 k) || rho (4)    R, W in TEST/PERSO
localparam [8:0] B_HELP   = 9'd196;   //  16 lanes  PUF helper data (960 bits) + key check value  R W
localparam [8:0] B_XIN    = 9'd212;   // 196 lanes  peer ek / ciphertext in and out / s^ bytes /
                                      //            raw dumps                         W, R after ENCAPS
localparam [8:0] B_XOUT   = B_XIN;    //            alias of B_XIN (output window)
localparam [8:0] B_K      = 9'd408;   //   4 lanes  shared secret K (TEST/PERSO)   R
localparam [8:0] B_INJD   = 9'd412;   //   4 lanes  injected d (TEST only)          W
localparam [8:0] B_INJZ   = 9'd416;   //   4 lanes  injected z (TEST/PERSO)         W
localparam [8:0] B_INJM   = 9'd420;   //   4 lanes  injected m (TEST only)          W
localparam [8:0] B_INJH   = 9'd424;   //   4 lanes  injected H(ek) (TEST/PERSO)     W
localparam [8:0] B_BLOB   = 9'd428;   //  14 lanes  wrapped key: nonce 2 | ct 8 | tag 4   R W
localparam [8:0] B_SM     = 9'd444;   //  24 lanes  secure message: header 4 | msg 16 | tag 4  R W
                                      //            header = counter (lane 0), length 1..128
                                      //            bytes (lane 1, host-set), 0, 0
localparam [8:0] B_TMP    = 9'd468;   //   4 lanes  internal: rho of the key in use (XOF input),
                                      //            not host-visible
// LMS (PQSE_LMS): chain values y[i] at B_LMS_Y + 4 i (268 lanes, up to 479; overlay
// B_XIN .. B_TMP, scratch during LMS commands), plus a 16-lane LMS window
localparam [8:0] B_LMS_Y  = 9'd212;   // 268 lanes  y[0..66]                  R after LMSLEAF / LMSSIGN
localparam [8:0] B_LMS    = 9'd480;   //  16 lanes  LMS window                R W
localparam [8:0] B_LMS_Q  = 9'd480;   //   4 lanes  Q, the digest the signature signs
localparam [8:0] B_LMS_C  = 9'd484;   //   4 lanes  C, the randomizer (from the TRNG)
localparam [8:0] B_LMS_M  = 9'd488;   //   4 lanes  M, 32-byte message to sign (host's digest)
localparam [8:0] B_LMS_I  = 9'd492;   //   2 lanes  I, the key identifier
localparam [8:0] B_LMS_QN = 9'd494;   //   1 lane   q, the leaf (LMSLEAF: in, LMSSIGN: out)
localparam [8:0] B_LMS_N  = 9'd495;   //   1 lane   [31:0] signatures used, [39:32] H (LMSSIGN out)
localparam [8:0] B_LMS_X  = 9'd496;   //  16 lanes  internal (PQSE_LMS_HSS, LMSNEXT): Merkle stack,
                                      //            then the message the top tree signs
localparam [8:0] W_LMS_Y  = 9'd268;
// ML-DSA (PQSE_DSA): signature (-44 2,420 bytes, -65 3,309, -87 4,627) overlays
// B_HELP .. B_TMP (read first or unused by DSA commands). 8 KB buffer (1,024 lanes;
// host sees 512 at a time, CONFIG[3]); lanes 512.. only for pqse_dsa.v and the
// sponge's ML-DSA jobs (HASH J[1] / J[0] = part 1 / 2 address bit 9).
// Signing attempts write only B_DW1 / B_DHS; the signature is written once an
// attempt is accepted. Host (pqse_host.v): writes B_DSIG .. 1023, reads B_DSIG
// after DSASIGN, B_DPK after DSAGEN.
localparam [8:0] B_DSIG   = 9'd196;   // 303 / 414 / 579 lanes  signature c~ | z | h
localparam [8:0] B_DHINT  = 9'd488;   //  11 lanes  ML-DSA-44 hint part (B_DSIG + 292; -65 / -87:
                                      //            lane 602 / 764)
localparam [8:0] B_DPK    = 9'd212;   // 164 / 244 / 324 lanes  public key rho (4) | t1: DSAGEN out,
                                      //            DSAPK in (before the signature is written)
localparam [8:0] B_DHS    = 9'd308;   //  11 lanes  internal: the hint bytes of a signing attempt
localparam [8:0] B_DRHOS  = 9'd507;   //   4 lanes  internal (signing): rho for ExpandA
localparam [9:0] B_DMU    = 10'd776;  //   8 lanes  mu = H(tr || M', 64) (external mu, FIPS 204 6.2)
localparam [9:0] B_DRHO   = 10'd784;  //   4 lanes  internal (verification): rho for ExpandA
localparam [9:0] B_DW1    = 10'd788;  // 128 lanes  internal: w1Encode(w1) (signing), w1' (verification;
                                      //            96 / 96 / 128 lanes)
localparam [8:0] W_DSIG   = 9'd303;
localparam [8:0] W_DPK    = 9'd164;
localparam [8:0] W_EK     = 9'd196;   // window sizes (k = 4)
localparam [8:0] W_CT     = 9'd196;

localparam [8:0] B_HELP_CHK   = B_HELP + 9'd15;  // 64-bit PUF key check value
localparam [8:0] B_BLOB_NONCE = B_BLOB;
localparam [8:0] B_BLOB_CT    = B_BLOB + 9'd2;
localparam [8:0] B_BLOB_TAG   = B_BLOB + 9'd10;
localparam [8:0] B_SM_HDR     = B_SM;          // header: counter, length, 0, 0
localparam [8:0] B_SM_MSG     = B_SM + 9'd4;
localparam [8:0] B_SM_TAG     = B_SM + 9'd20;

// ---- polynomial slots (20 x 128 words x 24 bit), 5-bit physical numbers ------
// Even slots in RAM 0 (share 0, public), odd slots in RAM 1 (share 1): the
// two shares never share a RAM array, bit line or output register.
// 10 slots per RAM (1280 x 25).
//   0..7    long-term key: s^_j share 0 = 2j, share 1 = 2j + 1 (j < k)
//   8..15   y_j (Encrypt) or e_i / t_i (KeyGen): share 0 = 8 + 2j, share 1 = 9 + 2j
//   16 T (matrix entry / decoded public poly), 17 Z (all-zero, precharge reads
//   between share 0 and share 1), 18 / 19 ACC share 0 / 1
localparam [4:0] P_T = 5'd16, P_Z = 5'd17, P_ACC0 = 5'd18, P_ACC1 = 5'd19;
// PQSE_DSA: 16 rows (32 slots); ML-DSA polynomial d (256 words) = slots 2d, 2d + 1
// (pqse_dsa.v); ML-KEM slots are rows 0..9
`ifdef PQSE_DSA
localparam integer PM_WORDS = 2048;   // words per polynomial RAM
`else
localparam integer PM_WORDS = 1280;   // words per polynomial RAM
`endif

// Logical slot codes (microcode 4-bit slot fields); pqse_core.v maps them to
// physical slots using the loop counters i, j:
localparam [3:0] L_SJ0 = 4'd0, L_SJ1 = 4'd1,     // s^_j share 0 / 1
                 L_SI0 = 4'd2, L_SI1 = 4'd3,     // s^_i (i up to 9: any slot 2i / 2i + 1)
                 L_YJ0 = 4'd4, L_YJ1 = 4'd5,     // y_j
                 L_YI0 = 4'd6, L_YI1 = 4'd7,     // y_i
                 L_T   = 4'd8, L_Z   = 4'd9, L_ACC0 = 4'd10, L_ACC1 = 4'd11;
// aliases for the gadgets' fixed slot references
localparam [3:0] S_T = L_T, S_Z = L_Z, S_ACC0 = L_ACC0, S_ACC1 = L_ACC1;

// d codes (4-bit d fields): literal d, or the ciphertext widths for k
localparam [3:0] D_DU = 4'd13,         // du = 10 (k = 2, 3) or 11 (k = 4)
                 D_DV = 4'd14;         // dv = 4 or 5

// buffer address modes (IO: ins[57:55], MASK: ins[54:52]): ba + ...
localparam [2:0] AM_NONE = 3'd0, AM_48I = 3'd1, AM_48J = 3'd2, AM_48K = 3'd3,
                 AM_DUI  = 3'd4, AM_DUK = 3'd5;

// HASH index modes (ins[7:4], os2 field; os2 unused by the microcode's sinks)
localparam [3:0] HM_NONE  = 4'd0,
                 HM_XOF   = 4'd1,     // XOF(rho || j || i): A^[i][j]          (sfx := {i, j})
                 HM_XOFT  = 4'd2,     // XOF(rho || i || j): A^[j][i]          (sfx := {j, i})
                 HM_PI1   = 4'd3,     // PRF nonce sfx + i, eta1
                 HM_PKI1  = 4'd4,     // PRF nonce k + i, eta1                 (KeyGen e_i)
                 HM_PKI2  = 4'd5,     // PRF nonce k + i, eta2 = 2             (e1_i)
                 HM_P2K2  = 4'd6,     // PRF nonce 2k, eta2                    (e2)
                 HM_HEK   = 4'd7,     // part 1 length := 48 k + 4 lanes       (H(ek))
                 HM_GK    = 4'd8,     // suffix byte := k                      (G(d || k))
                 HM_JC    = 4'd9,     // part 2 length := ciphertext lanes     (J(z || c))
                 HM_KAP   = 4'd10;    // ML-DSA ExpandMask: sfx := kappa + i  (PQSE_DSA)

// ---- seed register entries (16 x 256 bit x 2 Boolean shares) -----------------
localparam [3:0] E_D    = 4'd0;   // d (KeyGen seed)
localparam [3:0] E_Z    = 4'd1;   // z (implicit-rejection key)
localparam [3:0] E_H    = 4'd2;   // H(ek) of the own key
localparam [3:0] E_M    = 4'd3;   // m (Encaps) / m' (Decaps)
localparam [3:0] E_MP   = 4'd3;
localparam [3:0] E_K1   = 4'd4;   // K' (Decaps) / K (Encaps)
localparam [3:0] E_R    = 4'd5;   // r' / r / sigma
localparam [3:0] E_KB   = 4'd6;   // K-bar = J(z || c)
localparam [3:0] E_RHO  = 4'd7;   // rho (KeyGen, until unmasked into the buffer)
localparam [3:0] E_SK   = 4'd8;   // session key (shared secret kept inside)
localparam [3:0] E_KEK  = 4'd9;   // key-encryption key from the PUF
localparam [3:0] E_PUF  = 4'd10;  // PUF key (180 bits in lanes 0..2)
localparam [3:0] E_TMP  = 4'd11;  // TRNG seed / nonce
localparam [3:0] E_PH   = 4'd12;  // H(ek) of a peer key (Encaps)
localparam [3:0] E_W0   = 4'd13;  // wrap scratch
localparam [3:0] E_W1   = 4'd14;  // wrap scratch
localparam [3:0] E_TAG  = 4'd15;  // tag scratch
// E_CBD: entries 10..15 (24 lanes) hold one PRF output (1024 bits eta 2, 1536
// eta 3, both shares) while M_CBD turns it into a polynomial in random word
// order. Free during PRFs (E_PUF, E_TMP wiped before KeyGen's PRFs, E_PH used
// by G before; wrap / SEAL / OPEN use 13..15 only outside sampling); wiped after.
localparam [3:0] E_CBD  = 4'd10;
localparam [3:0] E_NCBD = 4'd6;       // entries E_CBD .. E_CBD + 5
// ML-DSA commands (PQSE_DSA) clear the ML-KEM key, so 0..7 are free. xi in E_W0;
// blob via E_KEK / E_W0 / E_W1 / E_TAG as for ML-KEM
localparam [3:0] E_DRHO  = 4'd3;      // rho (H(xi || k || l) lanes 0..3), unmasked to B_DRHOS
localparam [3:0] E_DRHOP = 4'd4;      // rho' (64 bytes: entries 4, 5)
localparam [3:0] E_DK    = 4'd6;      // K
localparam [3:0] E_DRND  = 4'd7;      // rnd (signing; follows K: rho'' = H(K || rnd || mu))
localparam [3:0] E_DRHO2 = 4'd11;     // rho'' (64 bytes: entries 11, 12)
localparam [3:0] E_DCT   = 4'd14;     // c~ (32 bytes; verification of ML-DSA-65 / 87: 48 / 64 bytes,
localparam [3:0] E_DCT2  = 4'd15;     //   the rest in E_DCT2)

// ---- instruction format (96 bit) ----------------------------------------------
localparam [3:0] C_END  = 4'd0;
localparam [3:0] C_BR   = 4'd1;
localparam [3:0] C_HASH = 4'd2;
localparam [3:0] C_POLY = 4'd3;
localparam [3:0] C_IO   = 4'd4;
localparam [3:0] C_MASK = 4'd5;
localparam [3:0] C_PUF  = 4'd6;
localparam [3:0] C_SET  = 4'd7;
localparam [3:0] C_LMS  = 4'd9;       // [91:88] LMS operation (LO_*, pqse_lms.v)
localparam [3:0] C_DSA  = 4'd10;      // [91:88] ML-DSA operation (D_*, pqse_dsa.v; PQSE_DSA)
localparam [3:0] C_ST   = 4'd11;      // [91:88] record store operation (SO_*, pqse_store.v; PQSE_STORE)
localparam [3:0] C_AES  = 4'd12;      // [91:88] AES-GCM operation (AO_*, pqse_aes.v; PQSE_AES)
localparam [3:0] C_LOOP = 4'd8;       // [91] 0: i, 1: j; [90] limit: 0 = k, 1 = [77:74];
                                      // [87:78] target: cnt + 1 < limit ? (cnt++, jump) : (cnt := 0)

// HASH sources and sinks
localparam [1:0] SRC_NONE = 2'd0, SRC_SEED = 2'd1, SRC_BUF = 2'd2, SRC_TRNG = 2'd3;
localparam [2:0] SNK_SEED = 3'd0;   // write lanes to seed entries oe0 (lanes 0-3), oe1 (4-7),
                                    // then oe0 + 2 .. oe0 + 5 (lanes 8-23; PRF -> E_CBD)
localparam [2:0] SNK_SXOR = 3'd1;   // XOR lanes into seed entries
localparam [2:0] SNK_SNTT = 3'd2;   // SampleNTT into slot oslot (public)
localparam [2:0] SNK_CBD  = 3'd3;   // SamplePolyCBD_2 unmasked into slot oslot (reference build)
localparam [2:0] SNK_DSA  = 3'd3;   // PQSE_DSA, reuses SNK_CBD's code (SNK_CBD not built):
                                    // ML-DSA sampler (pqse_dsa.v), mode oe0[2:0],
                                    // polynomial os + {0, i, j}[oe1[1:0]]
localparam [2:0] SNK_MB2A = 3'd4;   // masked CBD: shares into oslot / oslot2 (acc: add)
localparam [2:0] SNK_MCMP = 3'd5;   // masked compare with a buffer tag (acc: 0 blob tag, 1 message tag)
localparam [2:0] SNK_BXOR = 3'd6;   // XOR (unmasked) into the message lanes B_SM_MSG (keystream)
localparam [2:0] SNK_BOUT = 3'd7;   // LMS jobs only (pqse_lms.v): lanes unmasked into the buffer
                                    // from lane J[46:38] (released chain values, Q)

// rates
localparam [1:0] RATE_168 = 2'd0, RATE_136 = 2'd1, RATE_72 = 2'd2;

// POLY ops
localparam [3:0] P_NTT = 4'd0, P_INTT = 4'd1, P_PWM = 4'd2, P_ADD = 4'd3,
                 P_SUB = 4'd4, P_MSPLIT = 4'd5, P_ZERO = 4'd6,
                 P_ZCHK = 4'd7;     // FAULT unless c + a = 0 (mod q) for every coefficient

// IO ops
localparam [3:0] IO_DEC = 4'd0, IO_ENC = 4'd1, IO_S2B = 4'd2, IO_B2S = 4'd3,
                 IO_S2S = 4'd4, IO_SZERO = 4'd5, IO_SREMASK = 4'd6, IO_SCMP = 4'd7,
                 IO_T2B = 4'd8,     // raw TRNG words -> buffer (TEST only, entropy assessment)
                 IO_CTRW = 4'd9,    // message header lanes 0, 2, 3 := counter, 0, 0     (SEAL)
                 IO_CTRC = 4'd10,   // BAD := header counter replayed / too old          (OPEN)
                 IO_SEQ  = 4'd11,   // FAULT := masked seed entries e, e2 differ (share-wise)
                 IO_TRUNC = 4'd12;  // BAD := length not 1..128, else zero message bytes >= L
localparam [1:0] DM_WR = 2'd0, DM_ADD = 2'd1, DM_RSUB = 2'd2, DM_CHK = 2'd3;

// MASK ops
localparam [3:0] M_CMPR1 = 4'd0;    // masked Compress_1 -> m' Boolean shares into a seed entry
localparam [3:0] M_CMPRC = 4'd1;    // masked Compress_d, compared bit by bit with the ciphertext
localparam [3:0] M_MU    = 4'd2;    // mu = Decompress_1(m) from a masked seed entry, added to the shares
localparam [3:0] M_SEL   = 4'd3;    // K = ok ? K' : K-bar (acc = 1: kept masked in seed entry s0 field)
localparam [3:0] M_OKINI = 4'd4;    // ok := 1 (both copies)
localparam [3:0] M_OKOUT = 4'd5;    // BAD := NOT ok (unmasks ok: tag checks only)
localparam [3:0] M_STRM  = 4'd6;    // bit stream from the sponge (HASH sinks MB2A / MCMP)
localparam [3:0] M_CMPRO = 4'd7;    // masked Compress_d, ciphertext bits written to the buffer
localparam [3:0] M_OKCHK = 4'd8;    // FAULT if the two ok copies differ
localparam [3:0] M_CBD   = 4'd9;    // masked CBD from a PRF output in seed entries e..e+3
                                    // (eta 2) or e..e+5 (eta 3), in random word order ->
                                    // slots s0 / s1 (acc: add)

// PUF ops: reconstruction with 1, 3 or 5 reads per response bit (majority);
// the microcode retries with more reads on a key check value mismatch
localparam [3:0] PF_ENROLL = 4'd0, PF_RECON = 4'd1, PF_RAW = 4'd2,
                 PF_RECON3 = 4'd3, PF_RECON5 = 4'd4;

// SET ops. ST_SKV / ST_SKVR: session key loaded as initiator / responder (selects the
//   secure-messaging direction: no reflection); both reset the message counters.
// ST_TXINC: send counter + 1 (SEAL). ST_RXACC: accept the received counter in the
//   64-message replay window (OPEN, after the tag check).
localparam [3:0] ST_KEYV = 4'd0, ST_KEYC = 4'd1, ST_BADC = 4'd2, ST_RESEED = 4'd3,
                 ST_SKV  = 4'd4, ST_SKC  = 4'd5, ST_SKVR = 4'd6, ST_TXINC = 4'd7,
                 ST_RXACC = 4'd8,
                 // PQSE_DSA: kappa (ExpandMask) := 0 / += l; ML-DSA public key
                 // loaded in polynomials 11..15 (DSAPK, DSAGEN) / cleared
                 ST_KAPZ = 4'd9, ST_KAPI = 4'd10, ST_PKV = 4'd11, ST_PKC = 4'd12;

// branch conditions (BR: [91:88] condition, [87:78] target pc)
localparam [3:0] BC_ALWAYS = 4'd0, BC_BAD = 4'd1, BC_NBAD = 4'd2, BC_INJ = 4'd3, BC_NOKEY = 4'd4,
                 BC_NINJ = 4'd5, BC_WRAP = 4'd6, BC_KEXP = 4'd7, BC_NOSK = 4'd8, BC_ROLE = 4'd9,
                 BC_KGEN = 4'd10,   // the command is KEYGEN / KGWRAP (not UNWRAP): run the PCT
                 BC_LMSG = 4'd11,   // the command is LMSGEN
                 BC_LMSS = 4'd12,   // the command is LMSSIGN
                 BC_LMS  = 4'd13,   // the command is LMSGEN, LMSLEAF, LMSSIGN (or LMSNEXT)
                 BC_LMSN = 4'd14,   // the command is LMSNEXT (PQSE_LMS_HSS)
                 BC_HSS  = 4'd15;   // the build has two-level LMS (PQSE_LMS_HSS): always / never
// 5-bit conditions: ins[77] is bit 4 (u_br5, pqse_ucode.v); PQSE_DSA
localparam [4:0] BC_DSA  = 5'd16,   // the command is DSAGEN or DSASIGN (the PUF return)
                 BC_DSAG = 5'd17,   // the command is DSAGEN
                 BC_DSAS = 5'd18,   // the command is DSASIGN
                 BC_NOPK = 5'd19,   // no ML-DSA public key is loaded
                 // PQSE_STORE
                 BC_ST   = 5'd20,   // the command is STREAD, STWRITE or STDEL (the PUF return)
                 BC_STR  = 5'd21,   // the command is STREAD
                 BC_STD  = 5'd22,   // the command is STDEL
                 // PQSE_AES
                 BC_AES  = 5'd23,   // the command is AESGEN, GCMENC or GCMDEC (the PUF return)
                 BC_AESG = 5'd24,   // the command is AESGEN
                 BC_GDEC = 5'd25,   // the command is GCMDEC
                 // PQSE_DSA_VER: the loaded ML-DSA public key's parameter set (DSAVER's program)
                 BC_DL65 = 5'd26,   // ML-DSA-65
                 BC_DL87 = 5'd27,   // ML-DSA-87
                 // PQSE_AES: SEAL / OPEN and the record store run on the GCM programs
                 BC_OPEN = 5'd28;   // the command is OPEN (BC_GDEC: GCMDEC, OPEN or STREAD)

// secure-messaging KMAC customization strings S (HASH J[1:0], pqse_sponge.v):
// keystream "E1" / "E2", tag "T1" / "T2"; 1 = initiator -> responder,
// 2 = responder -> initiator. Only without PQSE_AES; with it, SEAL / OPEN and the
// record store use AES-256-GCM and the sponge has no KMAC jobs.
localparam [1:0] KC_E1 = 2'd0, KC_E2 = 2'd1, KC_T1 = 2'd2, KC_T2 = 2'd3;

// microcode entry points (pqse_ucode.v); the ML-KEM programs (loops over k)
// fit in the first 512 ROM words, 0 .. 500 in use
localparam [9:0] EP_KEYGEN  = 10'd16,  EP_UNWRAP  = 10'd32,  EP_ENCAPS  = 10'd160,
                 EP_DECAPS  = 10'd240, EP_SEAL    = 10'd320, EP_OPEN    = 10'd352,
                 EP_IMPORT  = 10'd384, EP_ENROLL  = 10'd400, EP_PUFRAW  = 10'd408,
                 EP_TRNGRAW = 10'd410, EP_ZEROIZE = 10'd416,
                 EP_LMSGEN  = 10'd512, EP_LMSUSE  = 10'd528,   // LMS (PQSE_LMS)
                 EP_DSAPUF  = 10'd704,                         // DSAGEN, DSASIGN (PQSE_DSA)
                 EP_DSAPK   = 10'd712, EP_DSAVER  = 10'd720,
                 EP_ST      = 10'd896,                         // STREAD / STWRITE / STDEL (PQSE_STORE)
                 EP_AGEN    = 10'd952, EP_GCM = 10'd954;       // AESGEN, GCMENC / GCMDEC (PQSE_AES)

// result codes (STATUS[15:8])
localparam [7:0] R_OK = 8'd0, R_BADIN = 8'd1, R_DENIED = 8'd2, R_NOKEY = 8'd3,
                 R_BADBLOB = 8'd4, R_RNGFAIL = 8'd5, R_UNKNOWN = 8'd6, R_KILLED = 8'd7,
                 R_FAULT = 8'd8, R_BADTAG = 8'd9, R_NOSK = 8'd10, R_REPLAY = 8'd11,
                 R_PUF = 8'd12,    // the PUF key could not be reconstructed (check value)
                 R_LMSKEY = 8'd13, // LMSSIGN: the blob is not the key the signature counter belongs to
                 R_LMSEXH = 8'd14, // LMSSIGN: all 2^LMS_H signatures of the key are used
                                   // (PQSE_LMS_HSS: of the current bottom tree, LMSNEXT starts
                                   // the next one; LMSNEXT: every bottom tree is used)
                 R_BADSIG = 8'd15, // DSAVER: the signature is not valid (PQSE_DSA)
                 // record store (PQSE_STORE)
                 R_STEMPTY = 8'd16, // STREAD: the slot was never written, or deleted
                 R_STBAD   = 8'd17, // STREAD: the stored record is not the slot's current one
                                    // (modified, an older version, another slot or card)
                 R_STFULL  = 8'd18, // STWRITE / STDEL: the slot's version counter is used up
                 R_STERR   = 8'd19; // the store failed (no answer in time, a write that does
                                    // not read back, a counter that did not move)

// commands (CTRL[7:0]); CTRL[8] = use injected seeds (TEST only)
localparam [7:0] CMD_KEYGEN = 8'd1, CMD_ENCAPS = 8'd2, CMD_DECAPS = 8'd3,
                 CMD_IMPORT = 8'd4, CMD_ENROLL = 8'd5, CMD_KGWRAP = 8'd6,
                 CMD_UNWRAP = 8'd7, CMD_ZEROIZE = 8'd8, CMD_SEAL = 8'd9,
                 CMD_OPEN = 8'd10, CMD_PUFRAW = 8'd11, CMD_TRNGRAW = 8'd12;
`ifdef PQSE_LMS
localparam [7:0] CMD_LMSGEN = 8'd13, CMD_LMSLEAF = 8'd14, CMD_LMSSIGN = 8'd15;
localparam [7:0] CMD_LMSNEXT = 8'd16;      // PQSE_LMS_HSS only
`ifdef PQSE_LMS_HSS
localparam [7:0] CMD_LAST = 8'd16;
`else
localparam [7:0] CMD_LAST = 8'd15;
`endif
`else
localparam [7:0] CMD_LAST = 8'd12;
`endif
// ML-DSA-44 (PQSE_DSA): DSAGEN key pair (xi PUF-wrapped into the blob, pk out, key
// loaded for DSAVER); DSASIGN signs mu with the blob's key; DSAPK loads a public
// key; DSAVER verifies a signature of mu with the loaded key. 17..20 also without
// LMS (13..16 are then unknown)
localparam [7:0] CMD_DSAGEN = 8'd17, CMD_DSASIGN = 8'd18, CMD_DSAPK = 8'd19, CMD_DSAVER = 8'd20;
// record store (PQSE_STORE): STREAD / STWRITE / STDEL slot B_SM_HDR lane 2 [5:0], the
// 128-byte record in B_SM_MSG (pqse_store.v)
localparam [7:0] CMD_STREAD = 8'd21, CMD_STWRITE = 8'd22, CMD_STDEL = 8'd23;
// AES-256-GCM (PQSE_AES): AESGEN a new key, PUF-wrapped into the blob (TEST: injected from
// B_INJD); GCMENC / GCMDEC with the blob's key or one derived from the session key (pqse_aes.v)
localparam [7:0] CMD_AESGEN = 8'd24, CMD_GCMENC = 8'd25, CMD_GCMDEC = 8'd26;

// lifecycle states (forward only)
localparam [1:0] LC_TEST = 2'd0, LC_PERSO = 2'd1, LC_USER = 2'd2, LC_KILLED = 2'd3;

// PUF fuzzy extractor: Reed-Muller RM(1,5) [32, 6, 16] code offset.
// PUF_NB = blocks of 32 response bits (cells / 32), even: two blocks per 64-bit
// helper lane, raw dump writes whole lanes. Default 30: 960 cells, 180-bit key,
// 128 key bits need h >= 0.946. PQSE_PUF_NB overrides, e.g. 24 (768 cells,
// 144-bit key, h >= 0.979) for a smaller FPGA array if the measured h allows.
// PQSE_PUF_RM2: RM(2,5) [32, 16, 8]: per block 16 key bits, 16 helper bits
// leaked, 3 correctable errors (RM(1,5): 6, 26, 7; pqse_puf.v). Default 12
// blocks (384 cells, 192-bit key). PUF_KB x PUF_NB <= 192 (3 seed lanes).
`ifdef PQSE_PUF_RM2
localparam integer PUF_KB  = 16;            // key bits per block
`else
localparam integer PUF_KB  = 6;
`endif
`ifdef PQSE_PUF_NB
localparam integer PUF_NB  = `PQSE_PUF_NB;
`elsif PQSE_PUF_RM2
localparam integer PUF_NB  = 12;
`else
localparam integer PUF_NB  = 30;
`endif
localparam integer PUF_NR  = 32 * PUF_NB;   // response bits = helper bits (PUF_NB / 2 lanes, at most 15)

// ---- LMS (PQSE_LMS): stateful hash-based signatures, SP 800-208 / RFC 8554,
// SHAKE256: LMOTS_SHAKE_N32_W4 OTS (67 chains of 15 steps) under an
// LMS_SHAKE_M32_H<LMS_H> tree, 2^LMS_H signatures per key. The card holds the
// seed (PUF-wrapped blob) and the signature counter (pqse_lmsctr / board flash);
// the host builds the Merkle tree from LMSLEAF outputs and adds the
// authentication paths (scripts/pqse_lms.py). Commands: pqse_lms.v.
`ifdef PQSE_LMS_H
localparam integer LMS_H = `PQSE_LMS_H;     // 5, 10 or 15
`else
localparam integer LMS_H = 5;
`endif
localparam integer LMS_P = 67;              // chains (W = 4, N = 32: 64 + 3 checksum digits)
// PQSE_LMS_HSS: two-level HSS (RFC 8554 sec. 6), top tree (LMS_H = 5) signs bottom
// public keys, bottom height LMS_HB = 5; 1,024 signatures. Bottom tree p: SEED_p, I_p
// from top-key x_q[i] jobs, q = p, i = 126 / 127. Counter: one 64-bit block per tree p,
// bit 0 = p certified, bits 1..32 its leaves; LMSNEXT burns the rest of the block first.
`ifdef PQSE_LMS_HSS
localparam integer LMS_HSS = 1;
`else
localparam integer LMS_HSS = 0;
`endif
localparam integer LMS_HB  = 5;
// type codes of the bottom public key signed by the top tree (SP 800-208 Tables
// 2, 3): u32(LMS_SHAKE_M32_H5) || u32(LMOTS_SHAKE_N32_W4), big-endian, one lane
// (byte 0 in bits [7:0])
localparam [63:0] LMS_TYPES_H5 = 64'h0B000000_0F000000;
// LMS operations (C_LMS [91:88])
localparam [3:0] LO_BIND   = 4'd0,   // BAD := I (B_LMS_I lane 0) is not the counter's key
                 LO_BEGIN  = 4'd1,   // BAD := counter at 2^H; else q := counter, burn it (write-
                                     //   ahead, persisted before the next step), q -> B_LMS_QN
                 LO_QLD    = 4'd2,   // q := B_LMS_QN (BAD unless < 2^H)
                 LO_MSG    = 4'd3,   // Q := H(I || q || D_MESG || C || M) -> B_LMS_Q
                 LO_SIGN   = 4'd4,   // y[i] := chain i of leaf q to digit i of Q || checksum
                 LO_LEAF   = 4'd5,   // y[i] := chain i of leaf q to its end (the OTS public key)
                 LO_KEYRST = 4'd6,   // a new key: counter := 0, bound to I lane 0
                 LO_INFO   = 4'd7,   // B_LMS_N := {H, signatures used}
                 // PQSE_LMS_HSS
                 LO_DERIV  = 4'd8,   // bottom tree p: SEED -> E_W1, I -> E_PH (from SEED E_W0, I B_LMS_I)
                 LO_ROOT   = 4'd9,   // the root of bottom tree p -> B_LMS_M (all its leaves, treehash)
                 LO_PUB    = 4'd10,  // B_LMS_X + 4: type codes, + 7: the root (C at + 0, I at + 5:
                                     //   written by the microcode): C || the bottom public key
                 LO_NEXT   = 4'd11,  // BAD := no bottom tree left; else burn the rest of the current
                                     //   tree's block, then the next tree's top leaf p; p -> B_LMS_QN
                 LO_LVL    = 4'd12;  // the jobs that follow use the bottom tree (ins[87] = 1) or the top


// ---- ML-DSA-44 (PQSE_DSA): FIPS 204, k = l = 4, eta 2, tau 39, omega 80, external mu
// (sec. 6.2). Engine pqse_dsa.v: polynomial d (0..15) = 256 coefficients mod q = 8380417,
// one per word {d, w} of the 2048-word poly RAMs. Not masked, hiding only (pqse_dsa.v).
// C_DSA instruction (pqse_ucode.v u_dsa; fields resolved in pqse_core.v):
//   [91:88] operation  [87] acc  [86:81] c  [80:75] a  [74:69] b  (polynomials {mode, base}:
//   base + 0 / i / j)  [68:60] buffer lane  [59:57] lane mode (+ stride x i or j)  [56:54] mode
//   [53] shuffled (hiding on: words / butterflies in the sequencer's random order)
localparam [3:0] D_NTT   = 4'd0,     // c := NTT(c)                       (FIPS 204 Alg. 41)
                 D_INTT  = 4'd1,     // c := NTT^-1(c), the 1/256 included (Alg. 42)
                 D_PWM   = 4'd2,     // c := (acc ? c : 0) + a o b
                 D_ADD   = 4'd3,     // c := c + a
                 D_SUB   = 4'd4,     // c := c - a
                 D_ZERO  = 4'd5,     // c := 0
                 D_P2R   = 4'd6,     // c := Power2Round(c): mode 0 t0 mod q, mode 1 t1 2^13
                 D_ENC   = 4'd7,     // pack c into lanes from ba (mode DM_*); DM_Z with acc:
                                     //   the norm check only (BAD if |z| >= gamma1 - beta)
                 D_DEC   = 4'd8,     // unpack lanes from ba into c (mode DM_*)
                 D_HINT  = 4'd9,     // signing, polynomial i: c = w - c s2, a = c t0: BAD if
                                     //   |a| >= gamma2 or |LowBits(c)| >= gamma2 - beta or more
                                     //   than omega hints; the hint positions into the stream
                 D_HEND  = 4'd10,    // signing: zero bytes to omega, the k counts, 4 zero bytes
                 D_HCNT  = 4'd11,    // start the hint byte stream at lane ba; acc = 0
                                     //   (verification): load the counts from lane ba + 10
                 D_HDEC  = 4'd12,    // verification, polynomial i: its hints -> bit 23 of c's
                                     //   words; BAD if malformed (FIPS 204 Alg. 21)
                 D_HVEND = 4'd13,    // verification: BAD unless the unused position bytes are 0
                 D_T1X   = 4'd14;    // verification: row b of the loaded key's packed t1 (two
                                     //   10-bit coefficients a word, from polynomial a on) ->
                                     //   c as t1 2^13
// ML-DSA parameter sets (pqse_dsa.v input lv, CONFIG[5:4] for DSAPK): all three verify
// with PQSE_DSA_VER; signing (DSAGEN / DSASIGN) ML-DSA-44 only
localparam [1:0] DL_44 = 2'd0, DL_65 = 2'd1, DL_87 = 2'd2;
// D_ENC / D_DEC modes
localparam [2:0] DM_W1 = 3'd0,       // w1Encode: HighBits, 6 bits                  (ENC)
                 DM_UH = 3'd1,       // UseHint(bit 23, word), 6 bits                (ENC)
                 DM_Z  = 3'd2,       // gamma1 - z, 18 bits; BAD if |z| >= gamma1 - beta
                 DM_T1 = 3'd3,       // t1: ENC Power2Round's high part, DEC t1 2^13; 10 bits
                 DM_R8 = 3'd4,       // the low byte of words 0..31 (rho, 4 lanes)
                 DM_T1P = 3'd5;      // DEC: t1 two coefficients (20 bits) a word: two key rows
                                     //   (80 lanes) into polynomial c (the loaded key, DSAPK)
// samplers (HASH sink SNK_DSA, mode in oe0[2:0])
localparam [2:0] SM_A = 3'd0,        // RejNTTPoly (ExpandA): 3 bytes -> 23-bit candidate < q
                 SM_S = 3'd1,        // RejBoundedPoly, eta 2 (ExpandS): nibbles < 15
                 SM_Y = 3'd2,        // ExpandMask: 18 bits -> gamma1 - v
                 SM_C = 3'd3,        // SampleInBall (the polynomial must be zero first)
                 SM_K = 3'd4;        // ML-KEM SampleNTT (SNK_SNTT in PQSE_DSA builds)
// polynomial field modes (bits [5:4] of a 6-bit polynomial field), lane modes
localparam [1:0] DI_0 = 2'd0, DI_I = 2'd1, DI_J = 2'd2;
// lane modes: ba + stride x i (loop counter i); bit 2 = ML-DSA-65 / 87 strides (separate
// DSAVER programs; c~ length and hint part lane are in ba)
localparam [2:0] LM_0   = 3'd0,      // ba
                 LM_I24 = 3'd1,      // ba + 24 i (w1 of ML-DSA-44, 6 bits)
                 LM_I40 = 3'd2,      // ba + 40 i (t1, 10 bits; signing)
                 LM_I72 = 3'd3,      // ba + 72 i (z of ML-DSA-44, 18 bits)
                 LM_I16 = 3'd5,      // ba + 16 i (w1 of ML-DSA-65 / 87, 4 bits; PQSE_DSA_VER)
                 LM_I80 = 3'd7;      // ba + 80 i (z of ML-DSA-65 / 87, 20 bits; PQSE_DSA_VER)


// ---- record store (PQSE_STORE, pqse_store.v): 16 slots x 128 bytes (64: PQSE_NVM_EXT) ----
// Record: header 4 | data 16 | tag 4 lanes, sealed with the PUF KEK (PQSE_AES: GCM).
// Slot: two copies + count-up version counter, v in copy v mod 2; STWRITE writes the
// other copy, reads back, then counts up. C_ST: [91:88] operation, [87] flag (SO_HDR: deleted)
localparam [3:0] SO_SLOT = 4'd0,     // slot := B_SM_HDR lane 2 [5:0]; BAD unless [63:ST_SB] = 0
                 SO_CNT  = 4'd1,     // v := the slot's version counter (BAD: the store failed)
                 SO_CHKE = 4'd2,     // BAD := v = 0 (never written)
                 SO_CHKF = 4'd3,     // BAD := the counter is used up
                 SO_HDR  = 4'd4,     // header lane 2 := {ST_MAGIC, v + 1, 0, flag, slot}, lane 3 := 0
                 SO_HCHK = 4'd5,     // BAD unless header lane 2 = {ST_MAGIC, v, 0, *, slot}
                 SO_DCHK = 4'd6,     // BAD := header lane 2's deleted bit
                 SO_RD   = 4'd7,     // copy v mod 2 -> B_SM (24 lanes) (BAD: the store failed)
                 SO_WR   = 4'd8,     // B_SM -> copy (v + 1) mod 2: erase, program, read back
                                     //   (BAD: the store failed or the copy does not read back)
                 SO_INC  = 4'd9;     // the counter := v + 1, read back (BAD unless it shows v + 1)
`ifdef PQSE_NVM_EXT
localparam ST_SB = 6;                           // slot bits: 64 slots (the board's flash)
`else
localparam ST_SB = 4;                           // 16 slots (pqse_stmem: block RAM)
`endif
`ifdef PQSE_AES
// PQSE_AES: record sealed in the GCM windows (24 lanes in the store: IV 2 (B_GIV, nonce),
// header 2 (B_GAAD, AAD), data 16 (B_GMSG), tag 2 (B_GTAG), 2 unused lanes after the tag);
// header lane B_ST_HDR
localparam [8:0] B_ST_HDR  = 9'd220;            // = B_GAAD (defined below)
`else
localparam [8:0] B_ST_HDR  = B_SM + 9'd2;       // header lane 2 of the window
`endif
localparam [8:0] B_ST_SLOT = B_SM + 9'd2;       // header lane 2: host's slot number
localparam [31:0] ST_MAGIC = 32'h52535150;      // "PQSR" (header lane 2 bytes 4..7)
// store port (pqse_store.v): st_o = {tog, op, slot (6 bits), copy, lane, data} (80 bits),
// st_i = {tog, full, err, count, data}; a request toggles tog, the store echoes it to answer
localparam [2:0] SP_CNT = 3'd0,      // count := the slot's counter; full := at its maximum
                 SP_INC = 3'd1,      // the counter + 1 (err when full), count := the new value
                 SP_ERS = 3'd2,      // erase a copy
                 SP_RD  = 3'd3,      // data := lane of a copy
                 SP_WR  = 3'd4;      // program a lane of an erased copy


// ---- AES-256-GCM (PQSE_AES): pqse_aes.v, first-order masked ------------------------------------
// Buffer (in B_XIN): header lane = {payload bytes P [15:0] (<= 1024), AAD bytes A [31:16]
// (<= 256), key source [32]: 0 = SHA3-256(session key || "A"), 1 = PUF-wrapped key in
// B_BLOB}; 96-bit IV (lanes 213, 214 [31:0]); 128-bit tag; AAD; payload, en/decrypted in
// place. 96-bit IVs and full 128-bit tags only. GCMDEC checks the tag before decrypting
// (masked: SHA3-256 of the computed tag vs. SHA3-256 of the received one, in B_SM_TAG)
// and releases nothing on failure.
localparam [8:0] B_GHDR = 9'd212;     //   1 lane   header
localparam [8:0] B_GIV  = 9'd213;     //   2 lanes  IV
localparam [8:0] B_GTAG = 9'd215;     //   2 lanes  tag (GCMENC out, GCMDEC in)
localparam [8:0] B_GAAD = 9'd220;     //  32 lanes  AAD (256 bytes)
localparam [8:0] B_GMSG = 9'd252;     // 128 lanes  payload (1,024 bytes)
// C_AES instruction: [91:88] operation
localparam [3:0] AO_HDR  = 4'd0,      // the header: P, A, key source (BAD: out of range)
                 AO_KSRC = 4'd1,      // BAD := the header asks for the PUF-wrapped key
                 AO_KEXP = 4'd2,      // E_W0's key -> the 15 round keys (seed lanes 12..31, 36..45)
                 AO_H    = 4'd3,      // H = E(K, 0): share 0 -> seed lanes 48, 49 (RAM 0; RAM 1
                                      // side 0), share 1 -> lanes 50, 51 (RAM 1; RAM 0 side 0);
                                      // PQSE_AES_SMALL: share 0 stored as H0 x^-128
                 AO_J0   = 4'd4,      // E(K, IV || 1) -> seed lanes 54, 55 (masked)
                 AO_CTR  = 4'd5,      // the payload xor E(K, IV || i + 2), in place; the rest := 0
                 AO_GH   = 4'd6,      // GHASH(H, A, C) -> seed lanes 52, 53 (masked; PQSE_AES_SMALL:
                                      // kept in the engine until TAG)
                 AO_TAG  = 4'd7,      // T = E(K, J0) ^ GHASH -> seed lanes 52, 53 (E_W0 0, 1; masked)
                 AO_WIPE = 4'd8;      // seed lanes 12..31 and 36..55 (round keys, H, E(K, J0),
                                      // GHASH / T) and the engine := 0
