"""describe-reserved-cache-nodes-and-offerings."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn, expected):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {expected} but the call SUCCEEDED")

def _refusal(fn, expected):
    """(code without its modeled Fault/Exception suffix, message) of the error fn() raises."""
    code, message = _error(fn, expected)
    return _fault_base(code), message

CHECK = "describe-reserved-cache-nodes-and-offerings"
GROUP = 'discovery'
SERVICES = ['elasticache']

@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reserved-node offerings are enumerable; an unknown reservation id is a NotFound."""
    ec = ctx.client("elasticache")
    offerings = ec.describe_reserved_cache_nodes_offerings(MaxRecords=20)[
        "ReservedCacheNodesOfferings"
    ]
    assert offerings, "expected at least one reserved-node offering, got none"
    assert len(offerings) <= 20, f"MaxRecords=20 but got {len(offerings)} offerings"
    sample = offerings[0]
    assert sample.get("ReservedCacheNodesOfferingId"), f"offering missing OfferingId: {sample}"
    assert sample.get("CacheNodeType"), f"offering missing CacheNodeType: {sample}"
    assert sample.get("Duration") is not None, f"offering missing Duration: {sample}"

    nodes = ec.describe_reserved_cache_nodes(MaxRecords=20)["ReservedCacheNodes"]
    assert len(nodes) <= 20, f"MaxRecords=20 but got {len(nodes)} reserved cache nodes"

    missing_id = ctx.unique_name("sim2real-behav-ercn-")
    refused = _refusal(
        lambda: ec.describe_reserved_cache_nodes(ReservedCacheNodeId=missing_id),
        "ReservedCacheNodeNotFoundFault",
    )
    assert refused == (
        "ReservedCacheNodeNotFound",
        f"ReservedCacheNode {missing_id} not found.",
    ), f"expected ReservedCacheNodeNotFound with its exact message, got {refused!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
