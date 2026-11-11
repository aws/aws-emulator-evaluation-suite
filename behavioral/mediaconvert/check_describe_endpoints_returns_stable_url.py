"""describe-endpoints-returns-stable-url."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-endpoints-returns-stable-url"
GROUP = "control-plane"
SERVICES = ["mediaconvert"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEndpoints is deterministic for a given account/region: two successive calls
    return the identical endpoint URL rather than a fresh/random one each time."""
    mc = ctx.client("mediaconvert")
    first = mc.describe_endpoints()["Endpoints"]
    second = mc.describe_endpoints()["Endpoints"]
    assert first, "expected at least one endpoint"
    assert second, "expected at least one endpoint"
    assert first[0]["Url"] == second[0]["Url"], (
        f"expected stable endpoint URL, got {first[0]['Url']!r} then {second[0]['Url']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
