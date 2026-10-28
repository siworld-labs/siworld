# D4 Soundness Controls

> **Paused V2 research.** Recursive aggregation and historical proof compression are outside native V1. These experimental parameters, timings and resource limits do not qualify the [current V1 route](../v1-overview.md).

Status: reproducible experimental analysis, not parameter approval.
`security-report` is an opt-in benchmark feature excluded from node defaults.
It pins `p3-security = 0.9.0-rc.2` and extracts actual leaf and recursive table
metadata. The report includes every estimator term, the weakest term,
conjectured and Johnson bounds, and a 16/2/1 union envelope. Unique decoding
is reported separately and never substituted for Johnson.

Recursive batch reports conservatively place summed constraint, quotient,
lookup and opening counts at the largest committed trace height. Quotient
chunks are rounded up to a power of two. This is a screening envelope, not an
exact multi-instance or quantum composition theorem. Raw runtime evidence is
not part of the source distribution.

| Control | Layer | Conjectured weakest term (bits) | Johnson weakest term (bits) |
| --- | --- | ---: | ---: |
| q42 | Leaf | 98.3273 | 57.7638 |
| q42 | Eight-input | 92.5737 | 57.9697 |
| q42 | Root | 93.0371 | 57.9697 |
| q92 | Leaf | 101.7438 | 91.8162 |
| q92 | Eight-input | 91.5737 | 82.7366 |
| q92 | Root | 92.0371 | 83.2000 |
| B | Leaf | 100.7438 | 89.9014 |
| B | Eight-input | 92.5737 | 83.7366 |
| B | Root | 92.0371 | 83.2000 |

The all-term 19-proof conjectured/Johnson union envelopes are respectively
90.8565/53.4734 for q42, 90.0200/81.2090 for q92 and 90.6577/81.7767 for B.
The D4 field ceiling is `4 log2(2130706433) = 123.9547` bits. An eight-element
digest has ideal classical collision exponent 123.9547 and BHT exponent
82.6365. Queries cannot repair these ceilings. **D4/W16 does not meet the
post-quantum target.** B is retained only to validate measurement methods.

The historical B and uniform-q92 proof/verification medians, 29.591 and 64.04
seconds, are below 180 seconds numerically but do not establish the new input
arrival markers, enforced memory limit or required security. No control is
an acceptance result. See [proof composition](proof-composition.md).
