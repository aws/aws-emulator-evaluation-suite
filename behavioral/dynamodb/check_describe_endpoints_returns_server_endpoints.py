"""describe-endpoints-returns-server-endpoints."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-endpoints-returns-server-endpoints"
GROUP = "server-side"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEndpoints is a server-side, no-input operation that returns the
    set of regional service endpoints DynamoDB manages; the response includes
    an address for the target region and is stable across repeated calls."""
    ddb = ctx.client("dynamodb")

    resp1 = ddb.describe_endpoints()
    endpoints1 = resp1["Endpoints"]
    assert len(endpoints1) >= 1, "DescribeEndpoints returned no endpoints"
    for ep in endpoints1:
        assert ep["Address"], "endpoint Address must not be empty"
        assert isinstance(ep["CachePeriodInMinutes"], int) and ep["CachePeriodInMinutes"] > 0, (
            f"CachePeriodInMinutes must be a positive int, got {ep['CachePeriodInMinutes']!r}"
        )

    matching_region = [ep for ep in endpoints1 if ctx.region in ep["Address"] and "dynamodb" in ep["Address"]]
    assert matching_region, f"no endpoint address referenced region {ctx.region}: {endpoints1}"

    resp2 = ddb.describe_endpoints()
    addrs1 = sorted(ep["Address"] for ep in endpoints1)
    addrs2 = sorted(ep["Address"] for ep in resp2["Endpoints"])
    assert addrs1 == addrs2, "DescribeEndpoints returned a different endpoint set on an immediate repeat call"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
