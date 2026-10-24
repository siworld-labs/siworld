#!/usr/bin/env python3
"""Security estimates for the additive set-hash accumulator (docs/cryptography.md).

A forgery is a nonzero integer vector x over candidate slots with A·x ≡ 0 (mod p), where the
columns of A are set elements E ∈ F_p^48. Its negative part (entries −1, distinct) is the
block's slot set, its positive part (nonnegative multiplicities) the leaves under the root
proof, and both parts have the same total k ≤ N because the tree has exactly N leaf positions.

Prints, for each capacity N:
  - the generalized-birthday (Wagner k-tree) cost with k = 2N lists, classical and quantum;
  - the smallest number of candidate columns d for which such a relation is expected to exist;
  - the BKZ block size (core-SVP) a lattice attack needs in any dimension d >= that threshold,
    for the shortest admissible shape (norm sqrt(2N)) and for the loosest (norm sqrt(N^2 + N)).
Run: python3 scripts/set_hash_security.py
"""

from math import comb, e, lgamma, log, log2, pi, sqrt

P = 2**31 - 2**24 + 1  # KoalaBear
SET_LEN = 48
N_BITS = SET_LEN * log2(P)

CLASSICAL_SIEVE = 0.292  # core-SVP exponent per BKZ block dimension
QUANTUM_SIEVE = 0.265


def log2_comb(n, k):
    if k < 0 or k > n:
        return float("-inf")
    return (lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)) / log(2)


def wagner_bits(n_slots):
    k = 2 * n_slots
    t = k.bit_length() - 1  # floor(log2 k): the k-tree uses 2^t lists
    classical = N_BITS / (t + 1)  # Wagner 2002
    quantum = N_BITS / (t + 2)  # Grassi, Naya-Plasencia, Schrottenloher 2018 (needs qRAM)
    return k, classical, quantum


def log2_relations(d, n_slots):
    """log2 of the expected number of admissible relations among d random columns.

    Admissible shapes with total k: a k-subset (the block side) and a size-k multiset over the
    other columns (the proof side). Each is a relation with probability p^-48.
    """
    best = float("-inf")
    for k in range(1, n_slots + 1):
        shapes = log2_comb(d, k) + log2_comb(d - 1, k)
        best = max(best, shapes)
    return best - N_BITS


def existence_threshold(n_slots):
    lo, hi = SET_LEN + 1, 2
    while log2_relations(hi, n_slots) < 0:
        hi *= 2
    while lo < hi:
        mid = (lo + hi) // 2
        if log2_relations(mid, n_slots) >= 0:
            hi = mid
        else:
            lo = mid + 1
    return lo


def delta(beta):
    return ((beta / (2 * pi * e)) * (pi * beta) ** (1 / beta)) ** (1 / (2 * (beta - 1)))


def bkz_beta(d, norm):
    """Smallest BKZ block size that reaches a vector of the given norm in the q-ary lattice of
    dimension d and determinant p^48: the GSA first-vector bound or the ADPS16 criterion,
    whichever is easier for the attacker. None if no block size up to d suffices."""
    log_det_d = N_BITS / d

    def ok(beta):
        dl = log2(delta(beta))
        gsa = d * dl + log_det_d <= log2(norm)
        adps = 0.5 * log2(beta / d) + log2(norm) <= (2 * beta - d) * dl + log_det_d
        return gsa or adps

    if d < 50 or not ok(d):
        return None
    lo, hi = 50, d  # both criteria get easier as beta grows
    while lo < hi:
        mid = (lo + hi) // 2
        if ok(mid):
            hi = mid
        else:
            lo = mid + 1
    return lo


def lattice_bits(n_slots, norm):
    """Minimum over lattice dimensions of the core-SVP cost. Dimensions below the existence
    threshold contain no admissible relation, so they do not count."""
    d0 = existence_threshold(n_slots)
    best = None
    d = d0
    while d <= 16 * d0:
        beta = bkz_beta(d, norm)
        cost = beta if beta is not None else d  # exact SVP in dimension d otherwise
        if best is None or cost < best[0]:
            best = (cost, d)
        d = int(d * 1.25) + 1
    return d0, best


def bits(x):
    return ">2^9999" if x > 9999 else f"2^{x:.0f}"


def main():
    print(f"p = {P}, |E| = {SET_LEN} elements = {N_BITS:.1f} bits")
    print()
    hdr = (
        f"{'N':<5}{'k=2N':<6}{'Wagner cl':<11}{'Wagner q':<10}{'d_exist':<12}"
        f"{'lattice tight cl/q':<22}{'lattice loose cl/q'}"
    )
    print(hdr)
    for n in (16, 32, 64, 128):
        k, wc, wq = wagner_bits(n)
        d0, (bt, _) = lattice_bits(n, sqrt(2 * n))
        _, (bl, _) = lattice_bits(n, sqrt(n * n + n))
        tight = f"{bits(CLASSICAL_SIEVE * bt)} / {bits(QUANTUM_SIEVE * bt)}"
        loose = f"{bits(CLASSICAL_SIEVE * bl)} / {bits(QUANTUM_SIEVE * bl)}"
        print(
            f"{n:<5}{k:<6}{'2^%.1f' % wc:<11}{'2^%.1f' % wq:<10}{'2^%.1f' % log2(d0):<12}"
            f"{tight:<22}{loose}"
        )
    print()
    # Without the multiplicity bound (multiplicities taken mod p) the same equation is linear:
    # SET_LEN + 1 columns always have a nontrivial dependency, found by Gaussian elimination.
    print(f"unbounded multiplicities: a dependency exists among {SET_LEN + 1} columns (cost ~2^20)")
    # Collision on a 248-bit sponge capacity or an 8-element node digest.
    cap_bits = 8 * log2(P)
    print(f"capacity / node digest: {cap_bits:.1f} bits, generic collision 2^{cap_bits / 2:.1f}")
    print(f"BHT quantum collision with qRAM: 2^{cap_bits / 3:.1f}")


if __name__ == "__main__":
    main()
