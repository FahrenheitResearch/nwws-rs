"""Head-to-head parse throughput: nwws-rs (Rust, via Python bindings) vs pyIEM.

Methodology
-----------
Both parsers receive the same raw WMO bulletin text and run their full parse
path (headers, UGC, VTEC, segments, geometry). nwws-rs is measured through its
Python bindings, so the numbers include PyO3 boundary overhead -- this is the
honest number for Python users. Each parser gets a warmup pass, then
``--rounds`` timed rounds over the fixture set; the best round is reported
(standard practice for throughput benchmarks; it minimizes scheduler noise).

Usage
-----
    maturin develop --release --features python
    python tools/bench_pyiem_speed.py [--iterations 2000] [--rounds 5]

pyIEM is loaded from a source tree (clone of https://github.com/akrherz/pyIEM);
set PYIEM_SRC or place it next to this repository.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PYIEM_SRC = REPO_ROOT.parent / "pyIEM" / "src"
FIXTURES = [
    REPO_ROOT / "tests" / "fixtures" / "wmo_bulletin.txt",
    REPO_ROOT / "tests" / "fixtures" / "wmo_tornado_warning.txt",
    REPO_ROOT / "tests" / "fixtures" / "wmo_segmented_svs.txt",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=2000,
                        help="parses of the full fixture set per round")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--pyiem-src", type=Path,
                        default=Path(os.environ.get("PYIEM_SRC", DEFAULT_PYIEM_SRC)))
    return parser.parse_args()


def best_round(label: str, fn, payloads, iterations: int, rounds: int) -> float:
    # Warmup
    for payload in payloads:
        fn(payload)
    best = float("inf")
    for _ in range(rounds):
        start = time.perf_counter()
        for _ in range(iterations):
            for payload in payloads:
                fn(payload)
        elapsed = time.perf_counter() - start
        best = min(best, elapsed)
    products = iterations * len(payloads)
    rate = products / best
    print(f"{label:>10}: {rate:>12,.0f} products/sec "
          f"({best:.3f}s best of {rounds} for {products:,} parses)")
    return rate


def main() -> None:
    args = parse_args()

    import nwws_rs

    if not args.pyiem_src.exists():
        raise SystemExit(f"pyIEM source tree not found at {args.pyiem_src}; "
                         "set PYIEM_SRC")
    sys.path.insert(0, str(args.pyiem_src))
    from pyiem.nws.product import TextProduct

    texts = [path.read_text(encoding="utf-8") for path in FIXTURES]
    blobs = [text.encode("utf-8") for text in texts]

    print(f"fixtures: {', '.join(path.name for path in FIXTURES)}")
    print(f"iterations per round: {args.iterations}, rounds: {args.rounds}")
    print()

    rust = best_round("nwws-rs", nwws_rs.parse_bulletin, blobs,
                      args.iterations, args.rounds)
    pyiem = best_round(
        "pyIEM",
        lambda text: TextProduct(text, ugc_provider={}, nwsli_provider={}),
        texts,
        # pyIEM is slow enough that full iterations would take minutes.
        max(args.iterations // 20, 10),
        args.rounds,
    )

    print()
    print(f"speedup: nwws-rs is {rust / pyiem:,.1f}x faster on this corpus")


if __name__ == "__main__":
    main()
