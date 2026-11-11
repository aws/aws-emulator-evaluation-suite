"""purchase-reserved-offering-unknown."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn):
    """Call fn(); return (code, message) from the ClientError it must raise.

    An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _refusal(fn):
    """(code without its modeled Fault/Exception suffix, message) of the error fn() raises."""
    code, message = _error(fn)
    return _fault_base(code), message

CHECK = "purchase-reserved-offering-unknown"
GROUP = 'overly-permissive'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: purchasing a reserved-node offering that does not exist must be refused."""
    ec = ctx.client("elasticache")
    offering_id = "00000000-0000-0000-0000-000000000000"
    refused = _refusal(
        lambda: ec.purchase_reserved_cache_nodes_offering(
            ReservedCacheNodesOfferingId=offering_id,
            ReservedCacheNodeId=ctx.unique_name("sim2real-behav-ercn-buy-"),
            CacheNodeCount=1,
        ),
    )
    assert refused == (
        "ReservedCacheNodesOfferingNotFound",
        f"ReservedCacheNodesOfferingId {offering_id} not found.",
    ), f"expected ReservedCacheNodesOfferingNotFound with its exact message, got {refused!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
