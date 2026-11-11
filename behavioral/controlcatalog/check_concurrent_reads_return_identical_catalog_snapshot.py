"""concurrent-reads-return-identical-catalog-snapshot."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-reads-return-identical-catalog-snapshot"
GROUP = "concurrency"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Eight concurrent ListControls(MaxResults=20) calls return the same non-empty ordered page of control
    ARNs: parallel readers of the read-only catalog never see divergent views."""
    cc = ctx.client("controlcatalog")

    def fetch():
        return tuple(c["Arn"] for c in cc.list_controls(MaxResults=20)["Controls"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: fetch(), range(8)))

    first = results[0]
    assert len(first) >= 1, "ListControls returned no controls to compare across concurrent readers"
    for r in results[1:]:
        assert r == first, "concurrent ListControls calls returned divergent first pages"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
