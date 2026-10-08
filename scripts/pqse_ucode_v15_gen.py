#!/usr/bin/env python3
"""PQSE microcode generator: writes the generated region of hw/se_v4_flex/pqse_ucode.v's case table.

  python3 scripts/pqse_ucode_v15_gen.py [ROOT]      (--lms accepted, no effect)
"""
import re
import sys

prog = []          # (addr, expr, comment, cond, alt). cond: "lms" PQSE_LMS,
                   # "hss" PQSE_LMS_HSS, "dsa" PQSE_DSA, "dsasign" PQSE_DSA and not
                   # PQSE_DSA_VER, "dsaver" PQSE_DSA_VER (same addresses as "dsasign"),
                   # "store" PQSE_STORE, "aes" PQSE_AES, "pret" any of PQSE_LMS / DSA /
                   # STORE / AES; DEF2 for two-level conds. alt: expression otherwise
labels = {}
pc = 0

def org(a):
    global pc
    assert a >= pc, (hex(a), hex(pc))
    pc = a

def reorg(a):
    """set pc back to a: alternative program at the same addresses (complementary
    conditions, e.g. "kmac" / "aes")"""
    global pc
    pc = a

def L(name):
    assert name not in labels, name
    labels[name] = pc

def I(expr, comment="", cond=None, alt=None):
    global pc
    prog.append((pc, expr, comment, cond, alt))
    pc += 1

def ref(name):
    return "{%s}" % name

def build(v4f):
    """build all programs; v4f: v4-flex set (LMS, ML-DSA, store, AES, L_PRET). Also used by pqse_dsa_check.py"""
    global prog, labels, pc
    prog, labels, pc = [], {}, 0
    # ---------------------------------------------------------------- failure exits
    org(0)
    for r in ["R_BADIN", "R_NOKEY", "R_BADBLOB", "R_DENIED", "R_BADTAG", "R_NOSK", "R_REPLAY", "R_PUF"]:
        I("u_end(%s)" % r)
    I("u_end(R_FAULT)", "X_KGF: a KeyGen recompute check failed")
    X = dict(X_BADIN=0, X_NOKEY=1, X_BADBLOB=2, X_DENIED=3, X_BADTAG=4, X_NOSK=5, X_REPLAY=6, X_PUF=7, X_KGF=8)
    labels.update(X)

    # ---------------------------------------------------------------- KEYGEN / KGWRAP (16)
    org(16); L("EP_KEYGEN")
    I("u_set(ST_RESEED)")
    I("u_br(BC_WRAP, %s)" % ref("L_PREC"), "KGWRAP: KEK first (no key yet if it fails)")
    L("L_KGSEED")
    I("u_br(BC_INJ, %s)" % ref("L_KGINJ"))
    I("h_trng(E_D)")
    I("h_trng(E_Z)")
    I("u_br(BC_ALWAYS, %s)" % ref("L_KG"))
    L("L_KGINJ")
    I("b2s(B_INJD, E_D, AM_NONE)", "TEST: injected d, z")
    I("sremask(E_D)")
    I("b2s(B_INJZ, E_Z, AM_NONE)")
    I("sremask(E_Z)")
    I("u_br(BC_ALWAYS, %s)" % ref("L_KG"))

    # ---------------------------------------------------------------- UNWRAP (32)
    org(32); L("EP_UNWRAP")
    I("u_set(ST_RESEED)")
    I("u_br(BC_ALWAYS, %s)" % ref("L_PREC"), "PUF key -> KEK, back to L_UWK")
    L("L_UWK")
    I("m_op(M_OKINI)")
    I("h_tag(SNK_MCMP)", "masked tag check")
    I("m_op(M_OKCHK)", "the two ok copies must agree")
    I("m_op(M_OKOUT)")
    I("u_br(BC_BAD, %s)" % ref("L_UWFAIL"))
    I("b2s(B_BLOB_CT, E_D, AM_NONE)")
    I("b2s(B_BLOB_CT + 9'd4, E_Z, AM_NONE)")
    I("h_ks(E_D, E_Z)", "d, z now masked plaintext")
    I("szero(E_KEK)")
    I("u_br(BC_ALWAYS, %s)" % ref("L_KG"))
    L("L_UWFAIL")
    I("szero(E_KEK)")
    I("u_br(BC_ALWAYS, %s)" % ref("X_BADBLOB"))

    # ---------------------------------------------------------------- PUF key -> KEK (48)
    org(48); L("L_PREC")
    I("u_puf(PF_RECON, E_PUF, B_HELP)", "one read per bit")
    I("h_kchk(E_PUF, E_TMP)")
    I("scmpn(E_TMP, B_HELP_CHK, 4'd1, AM_NONE)", "64-bit check value")
    I("u_br(BC_NBAD, %s)" % ref("L_PROK"))
    I("u_set(ST_BADC)")
    I("u_puf(PF_RECON3, E_PUF, B_HELP)", "retry: majority of 3 reads")
    I("h_kchk(E_PUF, E_TMP)")
    I("scmpn(E_TMP, B_HELP_CHK, 4'd1, AM_NONE)")
    I("u_br(BC_NBAD, %s)" % ref("L_PROK"))
    # v4-flex: two more 5-read attempts (fresh reads give cells near 50/50 another
    # chance); fits the 32 words from 48 to KeyGen at 80
    for n in range(3 if v4f else 1):
        I("u_set(ST_BADC)")
        I("u_puf(PF_RECON5, E_PUF, B_HELP)",
          "retry: majority of 5 reads" + (" (again)" if n else ""))
        I("h_kchk(E_PUF, E_TMP)")
        I("scmpn(E_TMP, B_HELP_CHK, 4'd1, AM_NONE)")
        if n < (2 if v4f else 0):
            I("u_br(BC_NBAD, %s)" % ref("L_PROK"))
        else:
            I("u_br(BC_BAD, %s)" % ref("L_PFAIL"))
    L("L_PROK")
    I("szero(E_TMP)")
    I("h_kek(1'b0)")
    I("szero(E_PUF)")
    I("u_br(BC_WRAP, %s)" % ref("L_KGSEED"), "KGWRAP: on to KeyGen")
    if v4f:
        I("u_br(BC_ALWAYS, %s)" % ref("L_PRET"), "UNWRAP / LMS / ML-DSA / store / AES: on to L_PRET",
          cond="pret", alt="u_br(BC_ALWAYS, %s)" % ref("L_UWK"))
    else:
        I("u_br(BC_ALWAYS, %s)" % ref("L_UWK"), "UNWRAP: on to the tag check")
    L("L_PFAIL")
    I("szero(E_PUF)")
    I("szero(E_TMP)")
    I("u_br(BC_ALWAYS, %s)" % ref("X_PUF"))

    # ---------------------------------------------------------------- KeyGen core (80)
    org(80); L("L_KG")
    I("h_gk(SNK_SEED)", "(rho, sigma) = G(d || k) -> E_RHO, E_R")
    I("s2b(E_RHO, B_EKOWN, AM_48K)", "rho is public: after t^ in the own ek")
    I("s2b(E_RHO, B_TMP, AM_NONE)", "... and where the XOF reads it")
    I("szero(E_KB)", "all-zero reference entry (G check)")
    I("scmpn(E_RHO, B_EKOWN, 4'd0, AM_48K)", "rho in the buffer = rho of G (public)")
    I("u_br(BC_BAD, %s)" % ref("X_KGF"))
    # s_i, computed twice and compared
    L("L_KGS")
    I("h_prf(E_R, 8'd0, HM_PI1)", "s_i: PRF(sigma, i), eta1")
    I("cbd(L_SI0, L_SI1, 1'b0, 1'b1)", "copy 1 (shares)")
    I("h_prf(E_R, 8'd0, HM_PI1)", "the PRF again")
    I("cbd(L_ACC0, L_ACC1, 1'b0, 1'b1)", "copy 2: fresh masks, own order")
    I("ntt(L_SI0)"); I("ntt(L_SI1)"); I("ntt(L_ACC0)"); I("ntt(L_ACC1)")
    I("psub(L_ACC0, L_SI0)", "share 0: y0 - x0")
    I("psub(L_ACC1, L_SI1)", "share 1: y1 - x1")
    I("pzchk(L_ACC0, L_ACC1)", "sum 0 everywhere, else FAULT")
    I("u_loop(1'b0, %s)" % ref("L_KGS"), "next i < k")
    L("L_KGE")
    I("h_prf(E_R, 8'd0, HM_PKI1)", "e_i: PRF(sigma, k + i), eta1")
    I("cbd(L_YI0, L_YI1, 1'b0, 1'b1)")
    I("h_prf(E_R, 8'd0, HM_PKI1)")
    I("cbd(L_ACC0, L_ACC1, 1'b0, 1'b1)")
    I("ntt(L_YI0)"); I("ntt(L_YI1)"); I("ntt(L_ACC0)"); I("ntt(L_ACC1)")
    I("psub(L_ACC0, L_YI0)")
    I("psub(L_ACC1, L_YI1)")
    I("pzchk(L_ACC0, L_ACC1)")
    I("u_loop(1'b0, %s)" % ref("L_KGE"))
    I("h_gk(SNK_SXOR)", "G(d || k) again, XORed into rho, sigma")
    I("seq(E_RHO, E_KB)")
    I("seq(E_R, E_KB)", "(sigma is not needed after the PRFs)")
    # t^_i = e^_i + sum_j A^[i][j] o s^_j, per share
    L("L_KGA")
    I("h_xof(B_TMP, HM_XOF, L_T)", "A^[i][j] = SampleNTT(rho || j || i)")
    I("pwm(1'b1, L_YI0, L_T, L_SJ0)")
    I("pwm(1'b1, L_YI1, L_T, L_SJ1)")
    I("u_loop(1'b1, %s)" % ref("L_KGA"), "next j < k")
    I("padd(L_YI0, L_YI1)", "t^_i is public: unmask")
    I("enc12(L_YI0, B_EKOWN, AM_48I)")
    I("u_loop(1'b0, %s)" % ref("L_KGA"), "next i < k")
    I("h_hek(B_EKOWN, E_H)", "H(ek), 48 k + 4 lanes")
    I("u_br(BC_KGEN, %s)" % ref("L_PCT"), "KEYGEN / KGWRAP: PCT first")
    L("L_KGV")
    I("u_set(ST_KEYV)", "s^ and z stay masked; key_k := k")
    I("u_br(BC_WRAP, %s)" % ref("L_WRAP"))
    I("u_br(BC_ALWAYS, %s)" % ref("L_KGEND"))
    L("L_WRAP")
    I("h_trng(E_TMP)")
    I("s2bn(E_TMP, B_BLOB_NONCE, 4'd2)", "nonce (2 lanes)")
    I("s2s(E_D, E_W0)")
    I("s2s(E_Z, E_W1)")
    I("h_ks(E_W0, E_W1)")
    I("s2b(E_W0, B_BLOB_CT, AM_NONE)", "ciphertext is public")
    I("s2b(E_W1, B_BLOB_CT + 9'd4, AM_NONE)")
    I("h_tag(SNK_SEED)")
    I("s2b(E_TAG, B_BLOB_TAG, AM_NONE)")
    I("szero(E_W0)")
    I("szero(E_W1)")
    I("szero(E_KEK)")
    L("L_KGEND")
    I("szero(E_D)"); I("szero(E_R)"); I("szero(E_RHO)")
    for k in range(6):
        I("szero(E_CBD + 4'd%d)" % k, "PRF scratch (E_PUF, E_TMP, E_PH, E_W0, E_W1, E_TAG)" if k == 0 else "")
    I("pzero(L_T)"); I("pzero(L_ACC0)"); I("pzero(L_ACC1)")
    L("L_KGZ")
    I("pzero(L_YI0)"); I("pzero(L_YI1)")
    I("u_loop(1'b0, %s)" % ref("L_KGZ"))
    I("u_end(R_OK)")

    def y_loop(tag):
        L(tag)
        I("h_prf(E_R, 8'd0, HM_PI1)", "y_i: PRF(r, i), eta1")
        I("cbd(L_YI0, L_YI1, 1'b0, 1'b1)")
        I("ntt(L_YI0)")
        I("ntt(L_YI1)")
        I("u_loop(1'b0, %s)" % ref(tag))

    def v_part(tag, ek, m, cmpr):
        # v = INTT(sum_j t^_j o y^_j) + e2 + Decompress_1(m)
        I("pzero(L_ACC0)")
        I("pzero(L_ACC1)")
        L(tag)
        I("dec(DM_WR, 4'd12, 1'b0, %s, L_T, AM_48J)" % ek, "t^_j")
        I("pwm(1'b1, L_ACC0, L_T, L_YJ0)")
        I("pwm(1'b1, L_ACC1, L_T, L_YJ1)")
        I("u_loop(1'b1, %s)" % ref(tag))
        I("intt(L_ACC0)"); I("intt(L_ACC1)")
        I("h_prf(E_R, 8'd0, HM_P2K2)", "+ e2: PRF(r, 2k), eta2")
        I("cbd(L_ACC0, L_ACC1, 1'b1, 1'b0)")
        I("mu(%s)" % m, "+ mu (masked m)")
        I("%s(D_DV, B_XIN, AM_DUK)" % cmpr, "c2 = Compress_dv(v)")

    def u_part(tag, cmpr):
        # u_i = INTT(sum_j A^[j][i] o y^_j) + e1_i
        L(tag)
        I("pzero(L_ACC0)")
        I("pzero(L_ACC1)")
        L(tag + "J")
        I("h_xof(B_TMP, HM_XOFT, L_T)", "A^[j][i] = SampleNTT(rho || i || j)")
        I("pwm(1'b1, L_ACC0, L_T, L_YJ0)")
        I("pwm(1'b1, L_ACC1, L_T, L_YJ1)")
        I("u_loop(1'b1, %s)" % ref(tag + "J"))
        I("intt(L_ACC0)"); I("intt(L_ACC1)")
        I("h_prf(E_R, 8'd0, HM_PKI2)", "+ e1_i: PRF(r, k + i), eta2")
        I("cbd(L_ACC0, L_ACC1, 1'b1, 1'b0)")
        I("%s(D_DU, B_XIN, AM_DUI)" % cmpr, "c1 part i = Compress_du(u_i)")
        I("u_loop(1'b0, %s)" % ref(tag))

    def rho_copy(ek):
        I("b2s(%s, E_TMP, AM_48K)" % ek, "rho of the key in use ...")
        I("s2b(E_TMP, B_TMP, AM_NONE)", "... to where the XOF reads it")
        I("szero(E_TMP)")

    # ---------------------------------------------------------------- ENCAPS
    org((pc + 15) // 16 * 16); L("EP_ENCAPS")
    I("u_set(ST_RESEED)")
    I("pzero(L_Z)", "the all-zero slot (precharge reads)")
    L("L_ENCHK")
    I("dec(DM_CHK, 4'd12, 1'b1, B_XIN, L_T, AM_48I)", "ek modulus check, t^_i")
    I("u_loop(1'b0, %s)" % ref("L_ENCHK"))
    I("u_br(BC_BAD, %s)" % ref("X_BADIN"))
    I("u_br(BC_INJ, %s)" % ref("L_ENINJ"))
    I("h_trng(E_M)")
    I("u_br(BC_ALWAYS, %s)" % ref("L_ENM"))
    L("L_ENINJ")
    I("b2s(B_INJM, E_M, AM_NONE)", "TEST: injected m")
    I("sremask(E_M)")
    L("L_ENM")
    I("h_hek(B_XIN, E_PH)", "H(ek)")
    I("h_g(E_M, E_PH, E_K1, E_R)", "(K, r) = G(m || H(ek))")
    rho_copy("B_XIN")
    y_loop("L_ENY")
    # v first: the ciphertext is written over the peer ek, whose t^ is read here
    v_part("L_ENV", "B_XIN", "E_M", "cmpro")
    u_part("L_ENU", "cmpro")
    I("s2s(E_K1, E_SK)", "K -> session key (masked)")
    I("u_set(ST_SKV)", "role: initiator")
    I("u_br(BC_KEXP, %s)" % ref("L_ENKX"))
    I("u_br(BC_ALWAYS, %s)" % ref("L_ENW"))
    L("L_ENKX")
    I("s2b(E_SK, B_K, AM_NONE)", "TEST / PERSO: K to the host")
    L("L_ENW")
    I("szero(E_M)"); I("szero(E_R)"); I("szero(E_K1)")
    for k in range(6):
        I("szero(E_CBD + 4'd%d)" % k)
    I("pzero(L_T)"); I("pzero(L_ACC0)"); I("pzero(L_ACC1)")
    L("L_ENZ")
    I("pzero(L_YI0)"); I("pzero(L_YI1)")
    I("u_loop(1'b0, %s)" % ref("L_ENZ"))
    I("u_end(R_OK)")

    # ---------------------------------------------------------------- DECAPS
    org((pc + 15) // 16 * 16); L("EP_DECAPS")
    I("u_br(BC_NOKEY, %s)" % ref("X_NOKEY"))
    I("u_set(ST_RESEED)")
    I("pzero(L_Z)", "(TVLA traces start here)")
    I("m_op(M_OKINI)")
    rho_copy("B_EKOWN")
    # w = v' - INTT(s^T o NTT(u')), each share of s on its own
    I("pzero(L_ACC0)")
    I("pzero(L_ACC1)")
    L("L_DEW")
    I("dec(DM_WR, D_DU, 1'b0, B_XIN, L_T, AM_DUI)", "u'_i")
    I("ntt(L_T)")
    I("pwm(1'b1, L_ACC0, L_SI0, L_T)")
    I("pwm(1'b1, L_ACC1, L_SI1, L_T)")
    I("u_loop(1'b0, %s)" % ref("L_DEW"))
    I("intt(L_ACC0)"); I("intt(L_ACC1)")
    I("dec(DM_RSUB, D_DV, 1'b0, B_XIN, L_ACC0, AM_DUK)", "w0 = v' - acc0")
    I("cmpr1(E_MP)", "m' (fresh masks, fresh order) ...")
    I("cmpr1(E_CBD + 4'd1)", "... again (scratch entry)")
    I("seq(E_MP, E_CBD + 4'd1)", "the two decodings must agree")
    I("h_g(E_MP, E_H, E_K1, E_R)", "(K', r') = G(m' || h)")
    I("h_j(1'b0)", "K-bar = J(z || c), ciphertext lanes of k")
    y_loop("L_DEY")
    u_part("L_DEU", "cmprc")
    v_part("L_DEV", "B_EKOWN", "E_MP", "cmprc")
    I("m_op(M_OKCHK)", "the two ok copies must agree")
    I("u_mask(M_SEL, 4'd0, E_SK, 4'd0, 1'b0, B_K, E_K1, E_KB, 1'b1, AM_NONE, 1'b0)", "K, kept masked")
    I("u_set(ST_SKVR)", "role: responder")
    I("u_br(BC_KEXP, %s)" % ref("L_DEKX"))
    I("u_br(BC_ALWAYS, %s)" % ref("L_DEW2"))
    L("L_DEKX")
    I("s2b(E_SK, B_K, AM_NONE)", "TEST / PERSO: K to the host")
    L("L_DEW2")
    I("szero(E_MP)"); I("szero(E_K1)"); I("szero(E_R)"); I("szero(E_KB)")
    for k in range(6):
        I("szero(E_CBD + 4'd%d)" % k)
    I("pzero(L_T)"); I("pzero(L_ACC0)"); I("pzero(L_ACC1)")
    L("L_DEZ")
    I("pzero(L_YI0)"); I("pzero(L_YI1)")
    I("u_loop(1'b0, %s)" % ref("L_DEZ"))
    I("u_end(R_OK)")

    # ---------------------------------------------------------------- SEAL
    # PQSE_AES: SEAL / OPEN use the GCM programs (L_GKEY) and windows with keys
    # h_kd(SK || "S1" / "S2"); the KMAC programs (cond "kmac") and the sponge's
    # KMAC jobs are then left out
    km = "kmac" if v4f else None

    def K(expr, comment=""):
        I(expr, comment, cond=km)

    org((pc + 15) // 16 * 16); L("EP_SEAL")
    K("u_br(BC_NOSK, %s)" % ref("X_NOSK"))
    K("trunc(1'b0)", "L in 1..128? M bytes from L on := 0")
    K("u_br(BC_BAD, %s)" % ref("X_BADIN"), "(no counter used up)")
    K("u_set(ST_RESEED)")
    K("ctr(IO_CTRW)", "header: counter, L, 0, 0")
    K("u_set(ST_TXINC)", "counted before use: never reused")
    K("u_br(BC_ROLE, %s)" % ref("L_SER"))
    K("h_kks(KC_E1)", "initiator -> responder")
    K("trunc(1'b0)", "C bytes from L on := 0")
    K("h_ktag(SNK_SEED, KC_T1)")
    K("u_br(BC_ALWAYS, %s)" % ref("L_SET"))
    L("L_SER")
    K("h_kks(KC_E2)", "responder -> initiator")
    K("trunc(1'b0)")
    K("h_ktag(SNK_SEED, KC_T2)")
    L("L_SET")
    K("s2b(E_TAG, B_SM_TAG, AM_NONE)")
    K("szero(E_TAG)")
    K("u_end(R_OK)")

    # ---------------------------------------------------------------- OPEN
    end_k = pc
    if v4f:
        def G(expr, comment=""):
            I(expr, comment, cond="aes")

        reorg(labels["EP_SEAL"])
        G("u_br(BC_NOSK, %s)" % ref("X_NOSK"), "SEAL (PQSE_AES): AES-256-GCM in the GCM windows")
        G("u_aes(AO_HDR)", "P, A (out of range: result 1)")
        G("u_br(BC_BAD, %s)" % ref("X_BADIN"))
        G("u_set(ST_RESEED)")
        G("ctrg(IO_CTRW)", "IV lane 0 := the send counter; the tag lanes := 0")
        G("u_set(ST_TXINC)", "counted before use: never reused")
        G("u_br(BC_ROLE, %s)" % ref("L_GSER"))
        G("h_kd(E_SK, 2'd2, 16'h3153)", "K = SHA3-256(SK || \"S1\"): initiator -> responder")
        G("u_br(BC_ALWAYS, %s)" % ref("L_GKEY"), "encrypt, GHASH, the tag to B_GTAG")
        L("L_GSER")
        G("h_kd(E_SK, 2'd2, 16'h3253)", "K = SHA3-256(SK || \"S2\"): responder -> initiator")
        G("u_br(BC_ALWAYS, %s)" % ref("L_GKEY"))
        pc = max(pc, end_k)
    org((pc + 15) // 16 * 16); L("EP_OPEN")
    K("u_br(BC_NOSK, %s)" % ref("X_NOSK"))
    K("ctr(IO_CTRC)", "replay window check")
    K("u_br(BC_BAD, %s)" % ref("X_REPLAY"))
    K("trunc(1'b1)", "length check only")
    K("u_br(BC_BAD, %s)" % ref("X_BADTAG"), "(a sender never seals such a length)")
    K("u_set(ST_RESEED)")
    K("m_op(M_OKINI)")
    K("u_br(BC_ROLE, %s)" % ref("L_OPR"))
    K("h_ktag(SNK_MCMP, KC_T2)", "initiator opens R -> I")
    K("u_br(BC_ALWAYS, %s)" % ref("L_OPC"))
    L("L_OPR")
    K("h_ktag(SNK_MCMP, KC_T1)", "responder opens I -> R")
    L("L_OPC")
    K("m_op(M_OKCHK)", "the two ok copies must agree")
    K("m_op(M_OKOUT)")
    K("u_br(BC_BAD, %s)" % ref("X_BADTAG"), "stays encrypted, window unchanged")
    K("u_set(ST_RXACC)", "authentic: mark the counter")
    K("u_br(BC_ROLE, %s)" % ref("L_OPD"))
    K("h_kks(KC_E2)")
    K("trunc(1'b0)", "plaintext bytes from L on := 0")
    K("u_end(R_OK)")
    L("L_OPD")
    K("h_kks(KC_E1)")
    K("trunc(1'b0)")
    K("u_end(R_OK)")
    if v4f:
        end_k = pc
        reorg(labels["EP_OPEN"])
        G("u_br(BC_NOSK, %s)" % ref("X_NOSK"), "OPEN (PQSE_AES)")
        G("u_aes(AO_HDR)", "P, A (out of range: result 9, a sender never seals that)")
        G("u_br(BC_BAD, %s)" % ref("X_BADTAG"))
        G("ctrg(IO_CTRC)", "replay window check (the counter: IV lane 0)")
        G("u_br(BC_BAD, %s)" % ref("X_REPLAY"))
        G("u_set(ST_RESEED)")
        G("u_br(BC_ROLE, %s)" % ref("L_GOPR"))
        G("h_kd(E_SK, 2'd2, 16'h3253)", "initiator opens R -> I: \"S2\"")
        G("u_br(BC_ALWAYS, %s)" % ref("L_GKEY"), "GHASH, masked tag check, then decrypt (BC_GDEC)")
        L("L_GOPR")
        G("h_kd(E_SK, 2'd2, 16'h3153)", "responder opens I -> R: \"S1\"")
        G("u_br(BC_ALWAYS, %s)" % ref("L_GKEY"))
        pc = max(pc, end_k)

    # ---------------------------------------------------------------- IMPORT
    org((pc + 15) // 16 * 16); L("EP_IMPORT")
    I("u_set(ST_RESEED)")
    I("h_hek(B_EKOWN, E_H)")
    I("scmpn(E_H, B_INJH, 4'd0, AM_NONE)", "dk hash check (4 lanes)")
    I("u_br(BC_BAD, %s)" % ref("X_BADIN"))
    L("L_IMS")
    I("dec(DM_WR, 4'd12, 1'b0, B_XIN, L_SI0, AM_48I)", "s^_i bytes")
    I("msplit(L_SI0, L_SI1)", "-> shares")
    I("u_loop(1'b0, %s)" % ref("L_IMS"))
    I("pzero(L_Z)")
    L("L_IMW")
    I("enc12(L_Z, B_XIN, AM_48I)", "wipe the s^ bytes (B_XIN becomes readable after ENCAPS)")
    I("u_loop(1'b0, %s)" % ref("L_IMW"))
    I("b2s(B_INJZ, E_Z, AM_NONE)")
    I("sremask(E_Z)")
    I("u_set(ST_KEYV)", "key_k := k")
    I("u_end(R_OK)")

    # ---------------------------------------------------------------- ENROLL / PUFRAW / TRNGRAW
    org((pc + 15) // 16 * 16); L("EP_ENROLL")
    I("u_set(ST_RESEED)")
    I("h_trng(E_TMP)", "k (masked)")
    I("u_puf(PF_ENROLL, E_TMP, B_HELP)", "helper -> 15 lanes, k canonical")
    I("h_kchk(E_TMP, E_W0)")
    I("s2bn(E_W0, B_HELP_CHK, 4'd1)", "check value -> helper lane 15")
    I("szero(E_W0)")
    I("szero(E_TMP)")
    I("u_end(R_OK)")
    L("EP_PUFRAW")
    I("u_puf(PF_RAW, 4'd0, B_XIN)", "960 bits -> 15 lanes")
    I("u_end(R_OK)")
    L("EP_TRNGRAW")
    I("u_io(IO_T2B, DM_WR, 4'd0, 1'b0, 1'b0, B_XIN, 4'd0, 4'd0, 4'd0, AM_NONE)", "136 words")
    I("u_end(R_OK)")

    # ---------------------------------------------------------------- ZEROIZE
    org((pc + 15) // 16 * 16); L("EP_ZEROIZE")
    L("L_ZP")
    I("pzero(L_SI0)", "slot 2i, i = 0..9: all 20 slots")
    I("pzero(L_SI1)")
    I("u_loopn(1'b0, %s, 4'd10)" % ref("L_ZP"))
    for e in range(16):
        I("szero(4'd%d)" % e)
    I("s2b(E_TMP, B_K, AM_NONE)", "E_TMP is 0 now")
    I("s2b(E_TMP, B_TMP, AM_NONE)")
    for k in range(6):
        I("s2b(E_TMP, B_SM + 9'd%d, AM_NONE)" % (4 * k), "secure-message window" if k == 0 else "")
    I("u_set(ST_KEYC)")
    I("u_set(ST_SKC)")
    if v4f:
        I("u_br(BC_ALWAYS, %s)" % ref("L_DZZ"), "PQSE_DSA: the ML-DSA polynomials too",
          cond="dsa", alt="u_end(R_OK)")
    else:
        I("u_end(R_OK)")

    # ---------------------------------------------------------------- PCT
    org((pc + 15) // 16 * 16); L("L_PCT")
    I("pzero(L_Z)", "the all-zero slot (precharge reads)")
    I("h_trng(E_M)", "m (masked)")
    I("h_hek(B_EKOWN, E_PH)", "H(ek) of the published ek")
    I("h_g(E_M, E_PH, E_K1, E_R)", "(K, r) = G(m || H(ek))")
    y_loop("L_PCY")
    v_part("L_PCV", "B_EKOWN", "E_M", "cmpro")
    u_part("L_PCU", "cmpro")
    # Decaps of the test ciphertext (in B_XIN) with the new s^
    I("pzero(L_ACC0)")
    I("pzero(L_ACC1)")
    L("L_PCW")
    I("dec(DM_WR, D_DU, 1'b0, B_XIN, L_T, AM_DUI)")
    I("ntt(L_T)")
    I("pwm(1'b1, L_ACC0, L_SI0, L_T)")
    I("pwm(1'b1, L_ACC1, L_SI1, L_T)")
    I("u_loop(1'b0, %s)" % ref("L_PCW"))
    I("intt(L_ACC0)"); I("intt(L_ACC1)")
    I("dec(DM_RSUB, D_DV, 1'b0, B_XIN, L_ACC0, AM_DUK)", "w0 = v' - acc0")
    I("cmpr1(E_TMP)", "m'")
    I("h_g(E_TMP, E_H, E_KB, E_R)", "(K', r') = G(m' || h), h of dk")
    I("seq(E_K1, E_KB)", "K' != K: FAULT (key never valid)")
    I("szero(E_M)"); I("szero(E_TMP)"); I("szero(E_K1)"); I("szero(E_KB)")
    I("pzero(L_ACC0)"); I("pzero(L_ACC1)")
    I("u_br(BC_ALWAYS, %s)" % ref("L_KGV"), "the rest is wiped at L_KGEND")

    end = pc
    if v4f:
        # ---- PUF routine return in LMS / ML-DSA / store / AES builds (branches for
        # options not built never fire)
        org(501); L("L_PRET")
        I("u_br(BC_LMS, %s)" % ref("L_LMSK"), "L_PREC returns here: LMS", cond="pret")
        # 5-bit conditions only where decoded; otherwise the sequencer would take
        # the low bits as a 4-bit condition, so alt = branch to the next word
        I("u_br5(BC_DSA, %s)" % ref("L_DSAK"), "... ML-DSA (DSAGEN, DSASIGN)", cond="dsasign",
          alt="u_br(BC_ALWAYS, 10'd503)")
        I("u_br5(BC_ST, %s)" % ref("L_STK"), "... record store (STREAD, STWRITE, STDEL)",
          cond="store", alt="u_br(BC_ALWAYS, 10'd504)")
        I("u_br5(BC_AES, %s)" % ref("L_AESK"), "... AES (AESGEN, GCMENC / GCMDEC with the blob)",
          cond="aes", alt="u_br(BC_ALWAYS, 10'd505)")
        I("u_br(BC_ALWAYS, %s)" % ref("L_UWK"), "... UNWRAP", cond="pret")
        assert labels["L_PRET"] == 501 and pc == 506
    assert pc <= 512, "the programs no longer fit 512 words"

    # ---------------------------------------------------------------- LMS (v4-flex, PQSE_LMS)
    # LMSGEN: PUF -> KEK, SEED and I from TRNG (TEST: injected), counter bound to I,
    # blob (tag suffix "L" || H). LMSLEAF / LMSSIGN: PUF -> KEK, unwrap (SEED masked
    # in E_W0, I public in B_LMS_I), then pqse_lms.v. SIGN burns q before C, Q and
    # the chains exist.
    if v4f:
        org(512); L("EP_LMSGEN")
        I("u_set(ST_RESEED)", cond="lms")
        I("u_br(BC_ALWAYS, %s)" % ref("L_PREC"), "PUF key -> KEK, back through L_PRET", cond="lms")
        org(528); L("EP_LMSUSE")
        I("u_set(ST_RESEED)", cond="lms")
        I("u_br(BC_ALWAYS, %s)" % ref("L_PREC"), cond="lms")
        L("L_LMSK")
        I("u_br(BC_LMSG, %s)" % ref("L_LGEN"), cond="lms")
        I("m_op(M_OKINI)", "LMSLEAF / LMSSIGN: unwrap the LMS blob", cond="lms")
        I("h_ltag(SNK_MCMP)", "masked tag check (suffix L || H)", cond="lms")
        I("m_op(M_OKCHK)", cond="lms")
        I("m_op(M_OKOUT)", cond="lms")
        I("u_br(BC_BAD, %s)" % ref("L_LUWF"), cond="lms")
        I("b2s(B_BLOB_CT, E_W0, AM_NONE)", cond="lms")
        I("b2s(B_BLOB_CT + 9'd4, E_W1, AM_NONE)", cond="lms")
        I("h_ks(E_W0, E_W1)", "SEED, I now masked plaintext", cond="lms")
        I("szero(E_KEK)", cond="lms")
        I("s2bn(E_W1, B_LMS_I, 4'd2)", "I is public", cond="lms")
        I("szero(E_W1)", cond="lms")
        I("u_br(BC_HSS, %s)" % ref("L_HSS"), "two levels (PQSE_LMS_HSS): its own programs", cond="lms")
        I("u_br(BC_LMSS, %s)" % ref("L_LSIGN"), cond="lms")
        I("u_lms(LO_QLD)", "LMSLEAF: q from the host", cond="lms")
        I("u_br(BC_BAD, %s)" % ref("L_LQF"), cond="lms")
        I("u_lms(LO_LEAF)", "the 67 chain ends of leaf q -> B_LMS_Y", cond="lms")
        I("u_br(BC_ALWAYS, %s)" % ref("L_LEND"), cond="lms")
        L("L_LSIGN")
        I("u_lms(LO_BIND)", "the counter belongs to this key?", cond="lms")
        I("u_br(BC_BAD, %s)" % ref("L_LKF"), cond="lms")
        I("u_lms(LO_BEGIN)", "q := counter, burned first (write-ahead)", cond="lms")
        I("u_br(BC_BAD, %s)" % ref("L_LXF"), cond="lms")
        I("u_br(BC_INJ, %s)" % ref("L_LCI"), cond="lms")
        I("h_trng(E_TMP)", "C", cond="lms")
        I("u_br(BC_ALWAYS, %s)" % ref("L_LC"), cond="lms")
        L("L_LCI")
        I("b2s(B_INJM, E_TMP, AM_NONE)", "TEST: injected C", cond="lms")
        I("sremask(E_TMP)", cond="lms")
        L("L_LC")
        I("s2b(E_TMP, B_LMS_C, AM_NONE)", "C is public", cond="lms")
        I("szero(E_TMP)", cond="lms")
        I("u_lms(LO_MSG)", "Q = H(I || q || D_MESG || C || M)", cond="lms")
        I("u_lms(LO_SIGN)", "y[i] = chain i to digit i of Q || Cksm", cond="lms")
        I("u_lms(LO_INFO)", cond="lms")
        L("L_LEND")
        I("szero(E_W0)", cond="lms")
        I("szero(E_TMP)", cond="lms")
        I("u_end(R_OK)", cond="lms")
        L("L_LGEN")
        I("u_br(BC_INJ, %s)" % ref("L_LGI"), "LMSGEN", cond="lms")
        I("h_trng(E_W0)", "SEED (masked)", cond="lms")
        I("h_trng(E_W1)", "I (lanes 0, 1)", cond="lms")
        I("u_br(BC_ALWAYS, %s)" % ref("L_LGK"), cond="lms")
        L("L_LGI")
        I("b2s(B_INJD, E_W0, AM_NONE)", "TEST: injected SEED, I", cond="lms")
        I("sremask(E_W0)", cond="lms")
        I("b2s(B_INJZ, E_W1, AM_NONE)", cond="lms")
        I("sremask(E_W1)", cond="lms")
        L("L_LGK")
        I("s2bn(E_W1, B_LMS_I, 4'd2)", "I is public", cond="lms")
        I("u_lms(LO_KEYRST)", "counter := 0, bound to the new I", cond="lms")
        I("h_trng(E_TMP)", cond="lms")
        I("s2bn(E_TMP, B_BLOB_NONCE, 4'd2)", "nonce (2 lanes)", cond="lms")
        I("szero(E_TMP)", cond="lms")
        I("h_ks(E_W0, E_W1)", "encrypted in place", cond="lms")
        I("s2b(E_W0, B_BLOB_CT, AM_NONE)", "ciphertext is public", cond="lms")
        I("s2b(E_W1, B_BLOB_CT + 9'd4, AM_NONE)", cond="lms")
        I("h_ltag(SNK_SEED)", cond="lms")
        I("s2b(E_TAG, B_BLOB_TAG, AM_NONE)", cond="lms")
        I("szero(E_TAG)", cond="lms")
        I("szero(E_W0)", cond="lms")
        I("szero(E_W1)", cond="lms")
        I("szero(E_KEK)", cond="lms")
        I("u_lms(LO_INFO)", cond="lms")
        I("u_end(R_OK)", cond="lms")
        L("L_LUWF")
        I("szero(E_KEK)", "the blob's tag did not check out", cond="lms")
        I("u_br(BC_ALWAYS, %s)" % ref("X_BADBLOB"), cond="lms")
        L("L_LQF")
        I("szero(E_W0)", "q out of range", cond="lms")
        I("u_br(BC_ALWAYS, %s)" % ref("X_BADIN"), cond="lms")
        L("L_LKF")
        I("szero(E_W0)", "another key's counter", cond="lms")
        I("u_end(R_LMSKEY)", cond="lms")
        L("L_LXF")
        I("szero(E_W0)", "no signature left", cond="lms")
        I("u_end(R_LMSEXH)", cond="lms")
        # ---- two levels (PQSE_LMS_HSS): top tree certifies bottom trees ----
        # top key (unwrapped above): SEED in E_W0, I in B_LMS_I. LO_DERIV: bottom tree
        # p's SEED -> E_W1, I -> E_PH; LO_LVL selects the tree for the jobs. LMSNEXT:
        # burn next top leaf p, compute tree p's root (LO_ROOT), sign C || its pk
        # with top leaf p.
        L("L_HSS")
        I("u_br(BC_LMSS, %s)" % ref("L_HSIGN"), cond="hss")
        I("u_br(BC_LMSN, %s)" % ref("L_HNEXT"), cond="hss")
        I("u_lms(LO_QLD)", "LMSLEAF: {level, p, q} from the host", cond="hss")
        I("u_br(BC_BAD, %s)" % ref("L_LQF"), cond="hss")
        I("u_lms(LO_DERIV)", "bottom tree p (used for level 1)", cond="hss")
        I("u_lms(LO_LEAF)", "the 67 chain ends of leaf q -> B_LMS_Y", cond="hss")
        I("u_br(BC_ALWAYS, %s)" % ref("L_HEND"), cond="hss")
        L("L_HSIGN")
        I("u_lms(LO_BIND)", "the counter belongs to this key?", cond="hss")
        I("u_br(BC_BAD, %s)" % ref("L_LKF"), cond="hss")
        I("u_lms(LO_BEGIN)", "tree p, leaf b := counter, burned first; the bottom tree", cond="hss")
        I("u_br(BC_BAD, %s)" % ref("L_LXF"), cond="hss")
        I("u_br(BC_INJ, %s)" % ref("L_HCI"), cond="hss")
        I("h_trng(E_TMP)", "C", cond="hss")
        I("u_br(BC_ALWAYS, %s)" % ref("L_HC"), cond="hss")
        L("L_HCI")
        I("b2s(B_INJM, E_TMP, AM_NONE)", "TEST: injected C", cond="hss")
        I("sremask(E_TMP)", cond="hss")
        L("L_HC")
        I("s2b(E_TMP, B_LMS_C, AM_NONE)", "C is public", cond="hss")
        I("szero(E_TMP)", cond="hss")
        I("u_lms(LO_DERIV)", "bottom tree p's SEED, I", cond="hss")
        I("u_lms(LO_MSG)", "Q = H(I_p || b || D_MESG || C || M)", cond="hss")
        I("u_lms(LO_SIGN)", cond="hss")
        I("u_lms(LO_INFO)", cond="hss")
        I("u_br(BC_ALWAYS, %s)" % ref("L_HEND"), cond="hss")
        L("L_HNEXT")
        I("u_lms(LO_BIND)", "LMSNEXT", cond="hss")
        I("u_br(BC_BAD, %s)" % ref("L_LKF"), cond="hss")
        I("u_lms(LO_NEXT)", "top leaf p burned (the rest of the current tree first)", cond="hss")
        I("u_br(BC_BAD, %s)" % ref("L_LXF"), cond="hss")
        I("u_lms(LO_DERIV)", "bottom tree p's SEED, I", cond="hss")
        I("u_lmsb(LO_LVL, 1'b1)", cond="hss")
        I("u_lms(LO_ROOT)", "its root -> B_LMS_M (every leaf, here on the card)", cond="hss")
        I("u_lmsb(LO_LVL, 1'b0)", "top leaf p signs", cond="hss")
        I("u_br(BC_INJ, %s)" % ref("L_HNCI"), cond="hss")
        I("h_trng(E_TMP)", "C", cond="hss")
        I("u_br(BC_ALWAYS, %s)" % ref("L_HNC"), cond="hss")
        L("L_HNCI")
        I("b2s(B_INJM, E_TMP, AM_NONE)", "TEST: injected C", cond="hss")
        I("sremask(E_TMP)", cond="hss")
        L("L_HNC")
        I("s2b(E_TMP, B_LMS_C, AM_NONE)", "C is public", cond="hss")
        I("s2b(E_TMP, B_LMS_X, AM_NONE)", "the message: C ||", cond="hss")
        I("szero(E_TMP)", cond="hss")
        I("s2bn(E_PH, B_LMS_X + 9'd5, 4'd2)", "... types || I_p || root (LO_PUB)", cond="hss")
        I("u_lms(LO_PUB)", cond="hss")
        I("u_lmsb(LO_MSG, 1'b1)", "Q = H(I || p || D_MESG || C || bottom public key)", cond="hss")
        I("u_lms(LO_SIGN)", cond="hss")
        I("u_lms(LO_INFO)", cond="hss")
        I("s2bn(E_PH, B_LMS_Q, 4'd2)", "I_p for the host (in place of Q)", cond="hss")
        L("L_HEND")
        I("szero(E_W0)", cond="hss")
        I("szero(E_W1)", cond="hss")
        I("szero(E_PH)", cond="hss")
        I("szero(E_TMP)", cond="hss")
        I("u_end(R_OK)", cond="hss")
        assert pc <= 1024

    # ---------------------------------------------------------------- ML-DSA (v4-flex, PQSE_DSA)
    # DSAGEN: PUF -> KEK, xi from TRNG, blob (xi || 32 zero bytes, tag suffix "D" || 44). DSASIGN:
    # blob's xi, rnd, key again; attempts write only scratch lanes until accepted. Signing: 44 only.
    # Polys: sign P0..3 s1^ / y^ / z, P4..7 w, P8 A / s, P9 c^, P10 c t0, P11..14 t0^; key P11 rho,
    # P12.. t1; verify P0..6 z^, P7 c^, P8 w'_approx_i, P9 A^[i][j].
    if v4f:
        def dp(n):
            return "dp(4'd%d)" % n

        def dpi(n):
            return "dpi(4'd%d)" % n

        def dpj(n):
            return "dpj(4'd%d)" % n

        dcond = ["dsa"]         # "dsasign": DSAGEN / DSASIGN, not in PQSE_DSA_VER builds

        def D(expr, comment=""):
            I(expr, comment, cond=dcond[0])

        def zero_polys(tag, n, comment=""):
            L(tag)
            D("d_zero(%s)" % dpi(0), comment)
            D("u_loopn(1'b0, %s, 4'd%d)" % (ref(tag), n))

        # free words after the LMS programs: ZEROIZE's ML-DSA part
        dcond[0] = "dsa"
        L("L_DZZ")
        D("d_zero(%s)" % dpi(10), "ZEROIZE (PQSE_DSA): also polynomials 10..15 (slots 20..31)")
        D("u_loopn(1'b0, %s, 4'd6)" % ref("L_DZZ"))
        D("u_set(ST_PKC)", "... and the loaded public key")
        D("u_end(R_OK)")
        assert pc <= 704, "the ML-DSA blocks run into DSAPUF (%d)" % pc

        dcond[0] = "dsasign"
        org(704); L("EP_DSAPUF")
        D("u_set(ST_RESEED)", "DSAGEN, DSASIGN")
        D("u_br(BC_ALWAYS, %s)" % ref("L_PREC"), "PUF key -> KEK, back through L_PRET")

        dcond[0] = "dsa"
        org(712); L("EP_DSAPK")
        D("u_set(ST_PKC)", "the parameter set is the new key's (CONFIG[5:4]) from here on")
        D("d_dec(DM_R8, B_DPK, LM_0, %s)" % dp(11), "rho -> P11 (a byte per word)")
        D("d_dec(DM_T1P, B_DPK + 10'd4, LM_0, %s)" % dp(12), "t1 rows 0, 1 (two coefficients a word) -> P12")
        D("d_dec(DM_T1P, B_DPK + 10'd84, LM_0, %s)" % dp(13), "rows 2, 3 -> P13")
        I("u_br5(BC_DL65, %s)" % ref("L_PK65"), "ML-DSA-65 / 87: the other rows", cond="dsaver",
          alt="u_set(ST_PKC)")
        I("u_br5(BC_DL87, %s)" % ref("L_PK87"), "", cond="dsaver", alt="u_set(ST_PKC)")
        L("L_PKV")
        D("u_set(ST_PKV)")
        D("u_end(R_OK)")

        # DSAVER, per row: w'_approx_i = NTT^-1(sum_j A^[i][j] o z^_j - c^ o NTT(t1_i 2^13))
        # -> P8, hints, w1'_i = UseHint -> B_DW1 + i x stride. P0..l-1 z^, P7 c^, P9
        # A^[i][j] / t1_i. One program per parameter set (65 / 87 only in PQSE_DSA_VER,
        # at the signing programs' addresses); k, l, c~ lanes, strides, hint part are
        # constants
        def dsaver(sfx, k, l, ct, zlm, wlm, hba, nw):
            if sfx:
                D("d_enc(DM_R8, %s, B_DRHO, LM_0)" % dp(11), "ML-DSA-%s: rho of the loaded key, for ExpandA" % sfx)
            else:
                D("d_enc(DM_R8, %s, B_DRHO, LM_0)" % dp(11), "rho of the loaded key, for ExpandA")
            L("L_DVZ" + sfx)
            D("d_dec(DM_Z, B_DSIG + 10'd%d, %s, %s)" % (ct, zlm, dpi(0)), "z_j; BAD if |z_j| >= gamma1 - beta")
            D("d_ntt(%s)" % dpi(0))
            D("u_loopn(1'b0, %s, 4'd%d)" % (ref("L_DVZ" + sfx), l))
            D("u_br(BC_BAD, %s)" % ref("L_DVF"))
            D("d_zero(%s)" % dp(7))
            D("h_dball(SRC_BUF, 8'd%d, 4'd7)" % ct, "c = SampleInBall(c~ of the signature) -> P7")
            D("d_ntt(%s)" % dp(7))
            L("L_DVW" + sfx)
            D("d_zero(%s)" % dp(8))
            L("L_DVWJ" + sfx)
            D("h_dxof(B_DRHO, 4'd9)", "A^[i][j] -> P9")
            D("d_pwm(1'b1, %s, %s, %s)" % (dp(8), dp(9), dpj(0)), "+ A^[i][j] o z^_j")
            D("u_loopn(1'b1, %s, 4'd%d)" % (ref("L_DVWJ" + sfx), l))
            D("d_t1x(%s, %s, %s)" % (dp(9), dp(12), dpi(0)), "t1_i 2^13 -> P9 ...")
            D("d_ntt(%s)" % dp(9))
            D("d_pwm(1'b0, %s, %s, %s)" % (dp(9), dp(9), dp(7)), "... o c^")
            D("d_sub(%s, %s)" % (dp(8), dp(9)))
            D("d_intt(%s)" % dp(8), "w'_approx_i -> P8")
            D("d_hdec(%s, %s, %s)" % (dp(8), dpi(0), hba), "its hints -> bit 23 (BAD: malformed)")
            D("d_enc(DM_UH, %s, B_DW1, %s)" % (dp(8), wlm), "w1'_i = UseHint(h_i, w'_approx_i)")
            D("u_loopn(1'b0, %s, 4'd%d)" % (ref("L_DVW" + sfx), k))
            D("d_hvend(%s)" % hba, "BAD unless the unused position bytes are 0")
            D("u_br(BC_BAD, %s)" % ref("L_DVF"))
            D("h_dch(8'd%d, 8'd%d)" % (nw, ct), "c~' = H(mu || w1Encode(w1')) -> E_DCT (, E_DCT2)")
            if ct > 4:
                D("scmpn(E_DCT2, B_DSIG + 9'd4, 4'd%d, AM_NONE)" % (ct - 4 if ct < 8 else 0))
            D("scmpn(E_DCT, B_DSIG, 4'd0, AM_NONE)", "BAD unless c~' = c~")

        org(720); L("EP_DSAVER")
        D("u_br5(BC_NOPK, %s)" % ref("X_NOKEY"), "DSAPK or DSAGEN first")
        D("u_set(ST_KEYC)", "polynomials 0..10 are ML-KEM's slots: its key is gone")
        I("u_br5(BC_DL65, %s)" % ref("L_DV65"), "the loaded key's parameter set", cond="dsaver",
          alt="u_set(ST_KEYC)")
        I("u_br5(BC_DL87, %s)" % ref("L_DV87"), "", cond="dsaver", alt="u_set(ST_KEYC)")
        dsaver("", 4, 4, 4, "LM_I72", "LM_I24", "{1'b0, B_DHINT}", 96)
        L("L_DVF")
        D("szero(E_DCT)")
        D("szero(E_DCT2)")
        zero_polys("L_DVX", 11, "polynomials 0..10 (the loaded key stays)")
        D("u_br(BC_BAD, %s)" % ref("L_DVBS"))
        D("u_end(R_OK)")
        L("L_DVBS")
        D("u_end(R_BADSIG)")

        # PQSE_DSA_VER: DSAVER ML-DSA-65 / 87 at the signing programs' addresses
        pc_sign = pc
        dcond[0] = "dsaver"
        for sfx, k, l, ct, nw, off in (("65", 6, 5, 6, 96, 406), ("87", 8, 7, 8, 128, 568)):
            L("L_DV" + sfx)
            dsaver(sfx, k, l, ct, "LM_I80", "LM_I16", "{1'b0, B_DSIG} + 10'd%d" % off, nw)
            D("u_br(BC_ALWAYS, %s)" % ref("L_DVF"))
        # DSAPK rows 4 .. k - 1 (80 lanes per polynomial)
        L("L_PK87")
        D("d_dec(DM_T1P, B_DPK + 10'd244, LM_0, %s)" % dp(15), "ML-DSA-87: rows 6, 7 -> P15")
        L("L_PK65")
        D("d_dec(DM_T1P, B_DPK + 10'd164, LM_0, %s)" % dp(14), "ML-DSA-65 / 87: rows 4, 5 -> P14")
        D("u_br(BC_ALWAYS, %s)" % ref("L_PKV"))
        assert pc <= 896, "the ML-DSA-65 / 87 programs run into the record store (%d)" % pc
        pc = pc_sign

        # DSAGEN / DSASIGN after L_PREC (KEK in E_KEK)
        dcond[0] = "dsasign"
        L("L_DSAK")
        D("u_br5(BC_DSAG, %s)" % ref("L_DGEN"))
        D("m_op(M_OKINI)", "DSASIGN: unwrap the ML-DSA blob")
        D("h_dtag(SNK_MCMP)", "masked tag check (suffix D || 44)")
        D("m_op(M_OKCHK)")
        D("m_op(M_OKOUT)")
        D("u_br(BC_BAD, %s)" % ref("L_DUWF"))
        D("b2s(B_BLOB_CT, E_W0, AM_NONE)")
        D("b2s(B_BLOB_CT + 9'd4, E_W1, AM_NONE)")
        D("h_ks(E_W0, E_W1)", "xi now masked plaintext (E_W1: 32 zero bytes)")
        D("szero(E_KEK)")
        D("szero(E_W1)")
        D("u_br(BC_INJ, %s)" % ref("L_DRI"))
        D("h_trng(E_DRND)", "rnd from the TRNG (hedged signing)")
        D("u_br(BC_ALWAYS, %s)" % ref("L_DRN"))
        L("L_DRI")
        D("b2s(B_INJM, E_DRND, AM_NONE)", "TEST: injected rnd (known answers)")
        D("sremask(E_DRND)")
        L("L_DRN")
        D("h_dexp(E_W0)", "(rho, rho', K) = H(xi || 4 || 4) -> E_DRHO, E_DRHOP, E_DK")
        D("szero(E_W0)")
        D("h_drho2(1'b0)", "rho'' = H(K || rnd || mu) -> E_DRHO2")
        D("szero(E_DK)")
        D("szero(E_DRND)")
        D("u_br(BC_ALWAYS, %s)" % ref("L_DSET"))
        L("L_DUWF")
        D("szero(E_KEK)", "the blob's tag did not check out")
        D("u_br(BC_ALWAYS, %s)" % ref("X_BADBLOB"))

        L("L_DGEN")
        D("u_br(BC_INJ, %s)" % ref("L_DGI"), "DSAGEN")
        D("h_trng(E_W0)", "xi (masked)")
        D("u_br(BC_ALWAYS, %s)" % ref("L_DGX"))
        L("L_DGI")
        D("b2s(B_INJD, E_W0, AM_NONE)", "TEST: injected xi")
        D("sremask(E_W0)")
        L("L_DGX")
        D("h_dexp(E_W0)", "(rho, rho', K) = H(xi || 4 || 4)")
        D("szero(E_DK)", "K: signing only")
        D("szero(E_W1)", "the blob's plaintext: xi || 32 zero bytes")
        D("h_trng(E_TMP)")
        D("s2bn(E_TMP, B_BLOB_NONCE, 4'd2)", "nonce (2 lanes)")
        D("szero(E_TMP)")
        D("h_ks(E_W0, E_W1)", "encrypted in place")
        D("s2b(E_W0, B_BLOB_CT, AM_NONE)", "ciphertext is public")
        D("s2b(E_W1, B_BLOB_CT + 9'd4, AM_NONE)")
        D("h_dtag(SNK_SEED)")
        D("s2b(E_TAG, B_BLOB_TAG, AM_NONE)")
        D("szero(E_TAG)")
        D("szero(E_W0)")
        D("szero(E_W1)")
        D("szero(E_KEK)")
        D("s2b(E_DRHO, B_DPK, AM_NONE)", "pk = rho || t1")
        # both: t = NTT^-1(A^ o NTT(s1)) + s2 -> P11..14
        L("L_DSET")
        D("u_set(ST_KEYC)", "polynomials 0..10 are ML-KEM's slots: its key is gone")
        D("s2b(E_DRHO, B_DRHOS, AM_NONE)", "rho is public: where ExpandA reads it")
        D("szero(E_DRHO)")
        L("L_DS1")
        D("h_dexps(8'd0, DI_I, 4'd0)", "s1_i = ExpandS(rho', i) -> P0+i")
        D("d_ntt(%s)" % dpi(0))
        D("u_loopn(1'b0, %s, 4'd4)" % ref("L_DS1"))
        L("L_DS2")
        D("d_zero(%s)" % dpi(11))
        L("L_DS2J")
        D("h_dxof(B_DRHOS, 4'd8)", "A^[i][j] -> P8")
        D("d_pwm(1'b1, %s, %s, %s)" % (dpi(11), dp(8), dpj(0)), "+ A^[i][j] o s1^_j")
        D("u_loopn(1'b1, %s, 4'd4)" % ref("L_DS2J"))
        D("d_intt(%s)" % dpi(11))
        D("h_dexps(8'd4, DI_0, 4'd8)", "s2_i = ExpandS(rho', 4 + i) -> P8")
        D("d_add(%s, %s)" % (dpi(11), dp(8)), "t_i -> P11+i")
        D("u_loopn(1'b0, %s, 4'd4)" % ref("L_DS2"))
        D("u_br5(BC_DSAS, %s)" % ref("L_DSG"))
        D("szero(E_DRHOP)", "DSAGEN: rho' no longer needed")
        D("szero(E_DRHOP + 4'd1)")
        L("L_DG3")
        D("d_enc(DM_T1, %s, B_DPK + 10'd4, LM_I40)" % dpi(11), "t1_i -> pk")
        D("u_loopn(1'b0, %s, 4'd4)" % ref("L_DG3"))
        D("d_dec(DM_T1P, B_DPK + 10'd4, LM_0, %s)" % dp(12), "the loaded key (DSAVER), as DSAPK: t1 -> P12, 13")
        D("d_dec(DM_T1P, B_DPK + 10'd84, LM_0, %s)" % dp(13))
        D("d_zero(%s)" % dp(11), "(t_0, t_3)")
        D("d_zero(%s)" % dp(14))
        D("d_dec(DM_R8, B_DRHOS, LM_0, %s)" % dp(11), "rho -> P11")
        D("u_set(ST_PKV)")
        zero_polys("L_DGZ", 11, "polynomials 0..10")
        D("u_end(R_OK)")

        # DSASIGN
        L("L_DSG")
        D("d_p2r(%s, 1'b0)" % dpi(11), "t0_i ...")
        D("d_ntt(%s)" % dpi(11), "... t0^_i -> P11+i")
        D("u_loopn(1'b0, %s, 4'd4)" % ref("L_DSG"))
        D("u_set(ST_PKC)", "P11..14 no longer hold a public key")
        D("u_set(ST_KAPZ)", "kappa := 0")
        L("L_DATT")
        D("h_dmask(1'b0)", "attempt: y_i = ExpandMask(rho'', kappa + i) -> P0+i")
        D("d_ntt(%s)" % dpi(0))
        D("u_loopn(1'b0, %s, 4'd4)" % ref("L_DATT"))
        L("L_DW")
        D("d_zero(%s)" % dpi(4))
        L("L_DWJ")
        D("h_dxof(B_DRHOS, 4'd8)", "A^[i][j] -> P8")
        D("d_pwm(1'b1, %s, %s, %s)" % (dpi(4), dp(8), dpj(0)), "+ A^[i][j] o y^_j")
        D("u_loopn(1'b1, %s, 4'd4)" % ref("L_DWJ"))
        D("d_intt(%s)" % dpi(4), "w_i -> P4+i")
        D("d_enc(DM_W1, %s, B_DW1, LM_I24)" % dpi(4), "w1_i -> scratch lanes")
        D("u_loopn(1'b0, %s, 4'd4)" % ref("L_DW"))
        D("h_dch(8'd96, 8'd4)", "c~ = H(mu || w1Encode(w1)) -> E_DCT")
        D("d_zero(%s)" % dp(9))
        D("h_dball(SRC_SEED, 8'd4, 4'd9)", "c = SampleInBall(c~) -> P9")
        D("d_ntt(%s)" % dp(9))
        L("L_DZ")
        D("h_dexps(8'd0, DI_0, 4'd8)", "s1_i -> P8 (regenerated)")
        D("d_ntt(%s)" % dp(8))
        D("d_pwm(1'b0, %s, %s, %s)" % (dp(8), dp(8), dp(9)), "c^ o s1^_i")
        D("d_add(%s, %s)" % (dpi(0), dp(8)), "z^_i = y^_i + c^ o s1^_i")
        D("d_intt(%s)" % dpi(0), "z_i -> P0+i")
        D("d_zchk(%s)" % dpi(0), "BAD if |z_i| >= gamma1 - beta")
        D("u_loopn(1'b0, %s, 4'd4)" % ref("L_DZ"))
        D("u_br(BC_BAD, %s)" % ref("L_DREJ"))
        L("L_DR")
        D("h_dexps(8'd4, DI_0, 4'd8)", "s2_i -> P8")
        D("d_ntt(%s)" % dp(8))
        D("d_pwm(1'b0, %s, %s, %s)" % (dp(8), dp(8), dp(9)))
        D("d_intt(%s)" % dp(8), "c s2_i")
        D("d_sub(%s, %s)" % (dpi(4), dp(8)), "r_i = w_i - c s2_i -> P4+i")
        D("u_loopn(1'b0, %s, 4'd4)" % ref("L_DR"))
        D("d_hcnt(B_DHS)", "the hint byte stream, into scratch lanes")
        L("L_DH")
        D("d_pwm(1'b0, %s, %s, %s)" % (dp(10), dp(9), dpi(11)), "c^ o t0^_i")
        D("d_intt(%s)" % dp(10), "c t0_i -> P10")
        D("d_hint(%s, %s)" % (dpi(4), dp(10)), "norm checks; the hints of polynomial i")
        D("u_loopn(1'b0, %s, 4'd4)" % ref("L_DH"))
        D("u_br(BC_BAD, %s)" % ref("L_DREJ"), "(before HEND: its time shows the hint count)")
        D("d_hend(1'b0)", "accepted: zero bytes to omega, the 4 counts")
        for k in range(3):                          # the signature c~ || z || h
            D("b2s(B_DHS + 9'd%d, E_W0, AM_NONE)" % (4 * k), "the hint bytes -> the signature" if k == 0 else "")
            D("s2bn(E_W0, B_DHINT + 9'd%d, 4'd%d)" % (4 * k, 3 if k == 2 else 0))
        D("szero(E_W0)")
        D("s2b(E_DCT, B_DSIG, AM_NONE)", "c~")
        L("L_DZP")
        D("d_enc(DM_Z, %s, B_DSIG + 10'd4, LM_I72)" % dpi(0), "z_i")
        D("u_loopn(1'b0, %s, 4'd4)" % ref("L_DZP"))
        for e in ("E_DRHOP", "E_DRHOP + 4'd1", "E_DRHO2", "E_DRHO2 + 4'd1", "E_DCT"):
            D("szero(%s)" % e)
        zero_polys("L_DSZ", 15, "polynomials 0..14")
        D("u_end(R_OK)")
        L("L_DREJ")
        D("u_set(ST_BADC)", "rejected: the next attempt")
        D("u_set(ST_KAPI)", "kappa += l")
        D("u_br(BC_ALWAYS, %s)" % ref("L_DATT"))

        assert pc <= 896, "the ML-DSA programs run into the record store (%d)" % pc

    # ---------------------------------------------------------------- record store (v4-flex, PQSE_STORE)
    # STREAD / STWRITE / STDEL: slot in B_SM_HDR lane 2, record in the secure-message
    # window (header 4 | data 16 | tag 4 lanes), sealed with the KEK (pqse_store.v,
    # pqse_defs.vh). STREAD checks the stored header before the PUF, the tag after.
    if v4f:
        def S(expr, comment=""):
            I(expr, comment, cond="stk")

        org(896); L("EP_ST")
        S("u_st(SO_SLOT, 1'b0)", "slot := header lane 2 (0..15)")
        S("u_br(BC_BAD, %s)" % ref("X_BADIN"))
        S("u_st(SO_CNT, 1'b0)", "v := its version counter")
        S("u_br(BC_BAD, %s)" % ref("X_STX"))
        S("u_br5(BC_STR, %s)" % ref("L_STR0"))
        S("u_st(SO_CHKF, 1'b0)", "STWRITE / STDEL: a version left?")
        S("u_br(BC_BAD, %s)" % ref("X_STF"))
        S("u_br(BC_ALWAYS, %s)" % ref("L_STP"))
        L("L_STR0")
        S("u_st(SO_CHKE, 1'b0)", "STREAD: ever written?")
        S("u_br(BC_BAD, %s)" % ref("X_STE"))
        S("u_st(SO_RD, 1'b0)", "copy v mod 2 -> B_SM")
        S("u_br(BC_BAD, %s)" % ref("X_STX"))
        S("u_st(SO_HCHK, 1'b0)", "its header: this slot, version v (an older copy fails here)")
        S("u_br(BC_BAD, %s)" % ref("X_STB"))
        L("L_STP")
        S("u_set(ST_RESEED)")
        S("u_br(BC_ALWAYS, %s)" % ref("L_PREC"), "PUF key -> KEK, back through L_PRET")
        L("L_STK")
        S("u_br5(BC_STR, %s)" % ref("L_STRD"))
        S("u_br5(BC_STD, %s)" % ref("L_STDZ"))
        S("u_st(SO_HDR, 1'b0)", "STWRITE: header lane 2 := {magic, v + 1, slot}, lane 3 := 0")
        S("u_br(BC_ALWAYS, %s)" % ref("L_STS"))
        L("L_STDZ")
        for k in range(4):
            S("s2b(E_TMP, B_SM_MSG + 9'd%d, AM_NONE)" % (4 * k),
              "STDEL: the data := 0 (E_TMP is 0 after the PUF routine)" if k == 0 else "")
        S("u_st(SO_HDR, 1'b1)", "... the header marked deleted")
        L("L_STS")
        S("h_trng(E_TMP)")
        S("s2bn(E_TMP, B_SM_HDR, 4'd2)", "nonce: header lanes 0, 1")
        S("szero(E_TMP)")
        S("h_rks(1'b0)", "data xor KMACXOF256(KEK, header, 1024, \"E1\")")
        S("h_rtag(SNK_SEED)", "tag = KMAC256(KEK, header || data, 256, \"T1\")")
        S("s2b(E_TAG, B_SM_TAG, AM_NONE)")
        S("szero(E_TAG)")
        S("szero(E_KEK)")
        S("u_st(SO_WR, 1'b0)", "-> copy (v + 1) mod 2: erase, program, read back")
        S("u_br(BC_BAD, %s)" % ref("X_STX"))
        S("u_st(SO_INC, 1'b0)", "the commit: counter := v + 1 (read back)")
        S("u_br(BC_BAD, %s)" % ref("X_STX"))
        S("u_end(R_OK)")
        L("L_STRD")
        S("m_op(M_OKINI)", "STREAD")
        S("h_rtag(SNK_MCMP)", "masked tag check")
        S("m_op(M_OKCHK)")
        S("m_op(M_OKOUT)")
        S("u_br(BC_BAD, %s)" % ref("L_STRB"))
        S("h_rks(1'b0)", "the data in the clear")
        S("szero(E_KEK)")
        S("u_st(SO_DCHK, 1'b0)", "a deletion?")
        S("u_br(BC_BAD, %s)" % ref("X_STE"), "(its data reads 0)")
        S("u_end(R_OK)")
        L("L_STRB")
        S("szero(E_KEK)", "the tag did not check out")
        L("X_STB")
        S("u_end(R_STBAD)", "not the slot's current record")
        L("X_STE")
        S("u_end(R_STEMPTY)")
        L("X_STF")
        S("u_end(R_STFULL)")
        L("X_STX")
        S("u_end(R_STERR)")
        end_k = pc
        # PQSE_AES: same commands with AES-256-GCM (cond "sta"). pqse_store.v puts the
        # record in the GCM windows (IV = nonce, AAD = header, payload = data, tag) and
        # writes GCM header {P 128, A 16}; key SHA3-256(KEK || "R"). The GCM programs
        # (L_GKEY) encrypt / check + decrypt, then return to L_STGR
        def T(expr, comment=""):
            I(expr, comment, cond="sta")

        reorg(896)
        T("u_st(SO_SLOT, 1'b0)", "slot := B_ST_SLOT (0..63)")
        T("u_br(BC_BAD, %s)" % ref("X_BADIN"))
        T("u_st(SO_CNT, 1'b0)", "v := its version counter")
        T("u_br(BC_BAD, %s)" % ref("X_STXA"))
        T("u_br5(BC_STR, %s)" % ref("L_STR0A"))
        T("u_st(SO_CHKF, 1'b0)", "STWRITE / STDEL: a version left?")
        T("u_br(BC_BAD, %s)" % ref("X_STFA"))
        T("u_br(BC_ALWAYS, %s)" % ref("L_STPA"))
        L("L_STR0A")
        T("u_st(SO_CHKE, 1'b0)", "STREAD: ever written?")
        T("u_br(BC_BAD, %s)" % ref("X_STEA"))
        T("u_st(SO_RD, 1'b0)", "copy v mod 2 -> the GCM windows")
        T("u_br(BC_BAD, %s)" % ref("X_STXA"))
        T("u_st(SO_HCHK, 1'b0)", "its header (this slot, version v); GCM header {128, 16}")
        T("u_br(BC_BAD, %s)" % ref("X_STBA"))
        L("L_STPA")
        T("u_set(ST_RESEED)")
        T("u_br(BC_ALWAYS, %s)" % ref("L_PREC"), "PUF key -> KEK, back through L_PRET")
        L("L_STKA")
        assert labels["L_STKA"] == labels["L_STK"], "L_PRET returns to both store versions"
        T("u_br5(BC_STR, %s)" % ref("L_STKY"))
        T("u_br5(BC_STD, %s)" % ref("L_STDA"))
        T("u_st(SO_HDR, 1'b0)", "STWRITE: AAD lane 0 := {magic, v + 1, slot}, lane 1 := 0; GCM header")
        T("u_br(BC_ALWAYS, %s)" % ref("L_STSA"))
        L("L_STDA")
        for k in range(4):
            T("s2b(E_TMP, B_GMSG + 9'd%d, AM_NONE)" % (4 * k),
              "STDEL: the data := 0 (E_TMP is 0 after the PUF routine)" if k == 0 else "")
        T("u_st(SO_HDR, 1'b1)", "... the header marked deleted")
        L("L_STSA")
        T("h_trng(E_TMP)")
        T("s2bn(E_TMP, B_GIV, 4'd2)", "the IV: a fresh nonce")
        T("szero(E_TMP)")
        L("L_STKY")
        T("h_kd(E_KEK, 2'd1, 16'h0052)", "K = SHA3-256(KEK || \"R\")")
        T("szero(E_KEK)")
        T("u_aes(AO_HDR)", "P = 128, A = 16")
        T("u_br(BC_BAD, %s)" % ref("X_STXA"))
        T("u_br(BC_ALWAYS, %s)" % ref("L_GKEY"), "STWRITE / STDEL: encrypt, tag; STREAD: check, decrypt")
        L("L_STGR")
        T("u_br5(BC_STR, %s)" % ref("L_STRE"), "(back from the GCM programs, tag good)")
        T("u_st(SO_WR, 1'b0)", "-> copy (v + 1) mod 2: erase, program, read back")
        T("u_br(BC_BAD, %s)" % ref("X_STXA"))
        T("u_st(SO_INC, 1'b0)", "the commit: counter := v + 1 (read back)")
        T("u_br(BC_BAD, %s)" % ref("X_STXA"))
        T("u_end(R_OK)")
        L("L_STRE")
        T("u_st(SO_DCHK, 1'b0)", "STREAD: a deletion?")
        T("u_br(BC_BAD, %s)" % ref("X_STEA"), "(its data reads 0)")
        T("u_end(R_OK)")
        L("X_STBA")
        T("u_end(R_STBAD)", "not the slot's current record (or its tag failed)")
        L("X_STEA")
        T("u_end(R_STEMPTY)")
        L("X_STFA")
        T("u_end(R_STFULL)")
        L("X_STXA")
        T("u_end(R_STERR)")
        pc = max(pc, end_k)
        assert pc <= 952, "the store programs run into the AES segment"

    # ---------------------------------------------------------------- AES-256-GCM (v4-flex, PQSE_AES)
    # AESGEN: PUF -> KEK, K from TRNG (TEST: injected), blob (K || 32 zero bytes, tag
    # suffix "A" || 32). GCMENC / GCMDEC: header; key = session key, or blob key via
    # PUF -> KEK; round keys, H, E(K, J0) (pqse_aes.v). GCMENC: encrypt, GHASH, tag out.
    # GCMDEC: GHASH of ciphertext, masked tag check, decrypt. Seed lanes (round keys,
    # H, E(K, J0), T) wiped on every exit.
    if v4f:
        def A(expr, comment=""):
            I(expr, comment, cond="aes")

        org(952); L("EP_AGEN")
        A("u_set(ST_RESEED)", "AESGEN")
        A("u_br(BC_ALWAYS, %s)" % ref("L_PREC"), "PUF key -> KEK, back through L_PRET")
        L("EP_GCM")
        A("u_aes(AO_HDR)", "GCMENC / GCMDEC: P, A, the key source")
        A("u_br(BC_BAD, %s)" % ref("X_BADIN"))
        A("u_set(ST_RESEED)")
        A("u_aes(AO_KSRC)")
        A("u_br(BC_BAD, %s)" % ref("L_GPUF"), "the PUF-wrapped key?")
        A("u_br(BC_NOSK, %s)" % ref("X_NOSK"))
        A("h_ak(1'b0)", "K = SHA3-256(session key || \"A\") -> E_W0")
        A("u_br(BC_ALWAYS, %s)" % ref("L_GKEY"))
        L("L_GPUF")
        A("u_set(ST_BADC)")
        A("u_br(BC_ALWAYS, %s)" % ref("L_PREC"), "PUF key -> KEK, back through L_PRET")
        L("L_AESK")
        A("u_br5(BC_AESG, %s)" % ref("L_AGEN"))
        A("m_op(M_OKINI)", "GCM with the blob's key: unwrap it")
        A("h_atag(SNK_MCMP)", "masked tag check (suffix A || 32)")
        A("m_op(M_OKCHK)")
        A("m_op(M_OKOUT)")
        A("u_br(BC_BAD, %s)" % ref("L_AUWF"))
        A("b2s(B_BLOB_CT, E_W0, AM_NONE)")
        A("b2s(B_BLOB_CT + 9'd4, E_W1, AM_NONE)")
        A("h_ks(E_W0, E_W1)", "K now masked plaintext")
        A("szero(E_KEK)")
        A("szero(E_W1)")
        L("L_GKEY")
        A("u_aes(AO_KEXP)", "the 15 round keys, masked")
        A("szero(E_W0)")
        A("u_aes(AO_H)", "H = E(K, 0)")
        A("u_aes(AO_J0)", "E(K, IV || 1)")
        A("u_br5(BC_GDEC, %s)" % ref("L_GDEC"))
        A("u_aes(AO_CTR)", "GCMENC: encrypt in place")
        A("u_aes(AO_GH)", "GHASH(A, C)")
        A("u_aes(AO_TAG)", "T = E(K, J0) ^ GHASH -> E_W0 lanes 0, 1 (masked)")
        A("s2bn(E_W0, B_GTAG, 4'd2)", "the tag (public)")
        L("L_GZ")
        A("u_aes(AO_WIPE)", "round keys, H, E(K, J0), T; the engine")
        A("u_br(BC_BAD, %s)" % ref("L_GBAD"))
        A("u_br5(BC_ST, %s)" % ref("L_STGR"), "the record store: back to its program")
        A("u_br5(BC_OPEN, %s)" % ref("L_GOPN"))
        A("u_end(R_OK)", "GCMENC, GCMDEC, SEAL")
        L("L_GDEC")
        A("u_aes(AO_GH)", "GCMDEC: GHASH(A, C) of the ciphertext first")
        A("u_aes(AO_TAG)")
        A("h_gtr(1'b0)", "SHA3-256(the received tag) -> E_TAG ...")
        A("s2b(E_TAG, B_SM_TAG, AM_NONE)", "... where the masked compare reads it")
        A("szero(E_TAG)")
        A("m_op(M_OKINI)")
        A("h_gtc(1'b0)", "SHA3-256(T), masked, compared")
        A("m_op(M_OKCHK)")
        A("m_op(M_OKOUT)")
        A("u_br(BC_BAD, %s)" % ref("L_GZ"), "a wrong tag: nothing decrypted (result 9)")
        A("u_aes(AO_CTR)", "decrypt in place")
        A("u_br(BC_ALWAYS, %s)" % ref("L_GZ"))
        L("L_AUWF")
        A("szero(E_KEK)", "the blob's tag did not check out")
        A("u_br(BC_ALWAYS, %s)" % ref("X_BADBLOB"))
        L("L_AGEN")
        A("u_br(BC_INJ, %s)" % ref("L_AGI"), "AESGEN")
        A("h_trng(E_W0)", "K (masked)")
        A("u_br(BC_ALWAYS, %s)" % ref("L_AGX"))
        L("L_AGI")
        A("b2s(B_INJD, E_W0, AM_NONE)", "TEST: injected K")
        A("sremask(E_W0)")
        L("L_AGX")
        A("szero(E_W1)", "the blob's plaintext: K || 32 zero bytes")
        A("h_trng(E_TMP)")
        A("s2bn(E_TMP, B_BLOB_NONCE, 4'd2)", "nonce (2 lanes)")
        A("szero(E_TMP)")
        A("h_ks(E_W0, E_W1)", "encrypted in place")
        A("s2b(E_W0, B_BLOB_CT, AM_NONE)", "ciphertext is public")
        A("s2b(E_W1, B_BLOB_CT + 9'd4, AM_NONE)")
        A("h_atag(SNK_SEED)")
        A("s2b(E_TAG, B_BLOB_TAG, AM_NONE)")
        A("szero(E_TAG)")
        A("szero(E_W0)")
        A("szero(E_W1)")
        A("szero(E_KEK)")
        A("u_end(R_OK)")
        assert pc <= 1024, "the AES programs do not fit the ROM (%d)" % pc
        # gap between ML-DSA and store programs: free in every build
        end_a = pc
        reorg(889)
        L("L_GOPN")
        A("u_set(ST_RXACC)", "OPEN: authentic, mark the counter")
        A("u_end(R_OK)")
        L("L_GBAD")
        A("u_br5(BC_ST, %s)" % ref("X_STBA"), "a record whose tag failed: result 17")
        A("u_end(R_BADTAG)")
        assert pc <= 896
        pc = end_a

    return prog, labels

# ---------------------------------------------------------------- output
def fmt(expr):
    return re.sub(r"\{(\w+)\}", lambda m: "10'd%d" % labels[m.group(1)], expr)

def line(a, e, c):
    t = "      10'd%d:%s ins = %s;" % (a, " " * (4 - len(str(a))), fmt(e))
    return t.ljust(84) + " // " + c if c else t

DEF = {"lms": "PQSE_LMS", "hss": "PQSE_LMS_HSS", "dsa": "PQSE_DSA", "store": "PQSE_STORE",
       "aes": "PQSE_AES", "dsaver": "PQSE_DSA_VER"}
# two-level conditions [(`ifdef / `ifndef, macro), ...]: KMAC secure messaging (no AES),
# record store with KMAC (no AES) or with AES-256-GCM
DEF2 = {"kmac": [("ifndef", "PQSE_AES")],
        "stk": [("ifdef", "PQSE_STORE"), ("ifndef", "PQSE_AES")],
        "sta": [("ifdef", "PQSE_STORE"), ("ifdef", "PQSE_AES")]}

def guarded(cond, body, alt=None):
    """body wrapped in cond's `ifdef lines ("pret": any of LMS / DSA / STORE / AES), alt in `else"""
    if cond == "dsasign":
        out = ["`ifdef PQSE_DSA", "`ifndef PQSE_DSA_VER"] + body
        if alt:
            return out + ["`else"] + alt + ["`endif", "`else"] + alt + ["`endif"]
        return out + ["`endif", "`endif"]
    if cond in DEF2:
        lv = DEF2[cond]
        out = []
        for kw, d in lv:
            out.append("`%s %s" % (kw, d))
        out += body
        if alt:
            # alt: one-level conditions only (asserted)
            out2 = ["`endif"] * 0
            assert len(lv) == 1, "alt only with a one-level condition"
            out += ["`else"] + alt
        return out + ["`endif"] * len(lv)
    if cond == "pret":
        out = (["`ifdef PQSE_LMS"] + body + ["`elsif PQSE_DSA"] + body + ["`elsif PQSE_STORE"] + body +
               ["`elsif PQSE_AES"] + body)
    else:
        out = ["`ifdef " + DEF[cond]] + body
    if alt:
        out += ["`else"] + alt
    return out + ["`endif"]

def emit():
    out, run, cur = [], [], None
    for a, e, c, cond, alt in prog:
        if alt or cond != cur:
            if cur:
                out += guarded(cur, run)
            elif run:
                out += run
            run, cur = [], cond
        if alt:
            out += guarded(cond, [line(a, e, c)], [line(a, alt, "")])
            cur = None
        else:
            run.append(line(a, e, c))
    if cur:
        out += guarded(cur, run)
    else:
        out += run
    return out

if __name__ == "__main__":
    V4F = True                    # --lms accepted, ignored
    build(V4F)
    out = emit()
    args = [x for x in sys.argv[1:] if not x.startswith("--")]
    root = args[0] if args else "."
    sedir = "/hw/se_v4_flex" if V4F else "/hw/se_v1_5"
    defs = open(root + sedir + "/pqse_defs.vh").read()
    # fault injection PCs in hw/sim/tb_pqse_v4f.sv are not checked: update by hand if the layout moves
    eps = ["EP_KEYGEN", "EP_UNWRAP", "EP_ENCAPS", "EP_DECAPS", "EP_SEAL", "EP_OPEN", "EP_IMPORT",
           "EP_ENROLL", "EP_PUFRAW", "EP_TRNGRAW", "EP_ZEROIZE"]
    if V4F:
        eps += ["EP_LMSGEN", "EP_LMSUSE", "EP_DSAPUF", "EP_DSAPK", "EP_DSAVER", "EP_ST", "EP_AGEN",
                "EP_GCM"]
    for ep in eps:
        m = re.search(ep + r"\s*=\s*10'd(\d+)", defs)
        if not m or int(m.group(1)) != labels[ep]:
            sys.exit("pqse_defs.vh: %s must be 10'd%d" % (ep, labels[ep]))

    path = root + sedir + "/pqse_ucode.v"
    src = open(path).read()
    b = "      // ---- generated by scripts/pqse_ucode_v15_gen.py: begin ----\n"
    e = "\n      // ---- generated by scripts/pqse_ucode_v15_gen.py: end ----"
    i, j = src.index(b) + len(b), src.index(e)
    open(path, "w").write(src[:i] + "\n".join(out) + src[j:])
    print("%s: %d instructions, addresses 0 .. %d" % (path, len(prog), pc - 1))
