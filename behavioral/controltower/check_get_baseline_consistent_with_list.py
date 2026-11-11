"""get-baseline-consistent-with-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-baseline-consistent-with-list"
GROUP = "catalog"
SERVICES = ["controltower"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetBaseline on an ARN taken from ListBaselines returns the exact same name and
    description as the list entry (read-your-writes consistency across the two read APIs,
    even though the underlying data is a static AWS-managed catalog)."""
    ct = ctx.client("controltower")
    listed = ct.list_baselines(maxResults=100)["baselines"]
    assert listed, "expected at least one baseline to cross-check"

    target = next((b for b in listed if b["name"] == "AWSControlTowerBaseline"), listed[0])

    got = ct.get_baseline(baselineIdentifier=target["arn"])
    assert got["arn"] == target["arn"]
    assert got["name"] == target["name"]
    assert got.get("description") == target.get("description")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
