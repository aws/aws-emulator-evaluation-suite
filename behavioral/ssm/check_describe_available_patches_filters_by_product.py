"""describe-available-patches-filters-by-product."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-available-patches-filters-by-product"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAvailablePatches with a PRODUCT filter returns only patches whose
    Product matches the filter value (AWS requires PRODUCT to be paired with any
    other Linux filter key, but a bare PRODUCT filter alone is also valid)."""
    ssm = ctx.client("ssm")

    patches = []
    next_token = None
    while True:
        kwargs = {
            "Filters": [{"Key": "PRODUCT", "Values": ["AmazonLinux2.0"]}],
            "MaxResults": 100,
        }
        if next_token:
            kwargs["NextToken"] = next_token
        resp = ssm.describe_available_patches(**kwargs)
        patches.extend(resp["Patches"])
        next_token = resp.get("NextToken")
        if not next_token or len(patches) >= 100:
            break

    assert len(patches) > 0, "expected at least one AmazonLinux2.0 patch in the catalog"
    for patch in patches:
        assert patch["Product"] == "AmazonLinux2.0", (
            f"expected Product == AmazonLinux2.0, got {patch['Product']}"
        )

    # A different, disjoint product filter must not leak AmazonLinux2.0 patches in.
    other = ssm.describe_available_patches(
        Filters=[{"Key": "PRODUCT", "Values": ["AmazonLinux2018.03"]}], MaxResults=100
    )["Patches"]
    assert len(other) > 0, "expected at least one AmazonLinux2018.03 patch in the catalog"
    for patch in other:
        assert patch["Product"] == "AmazonLinux2018.03", (
            f"expected Product == AmazonLinux2018.03, got {patch['Product']}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
