"""list-outposts-with-s3-response-shape."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-outposts-with-s3-response-shape"
GROUP = "control-plane"
SERVICES = ["s3outposts"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListOutpostsWithS3(MaxResults=100) returns an Outposts list whose entries carry ARNs, a non-negative
    integer CapacityInBytes and a 12-digit OwnerId, and with fewer than 100 results the response has no
    member but Outposts (no NextToken)."""
    s3o = ctx.client("s3outposts")
    resp = s3o.list_outposts_with_s3(MaxResults=100)
    outposts = resp.get("Outposts")
    assert isinstance(outposts, list), f"Outposts must be a list, got {outposts!r}"
    for op in outposts:
        assert op["OutpostArn"].startswith("arn:")
        assert op["S3OutpostArn"].startswith("arn:")
        assert isinstance(op["CapacityInBytes"], int)
        assert op["CapacityInBytes"] >= 0
        assert len(op["OwnerId"]) == 12 and op["OwnerId"].isdigit()

    if len(outposts) >= 100:
        raise AssertionError(
            "this account already has >=100 s3outposts-with-s3 entries, so the 'no more "
            "pages' case this check targets cannot be distinguished from a genuine next page"
        )
    keys = sorted(set(resp) - {"ResponseMetadata"})
    assert keys == ["Outposts"], (
        f"expected exactly the Outposts member with {len(outposts)} results under "
        f"MaxResults=100 (no NextToken), got members {keys!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
