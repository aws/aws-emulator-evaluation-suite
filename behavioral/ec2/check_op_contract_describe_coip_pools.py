"""op-contract-describe-coip-pools."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-coip-pools"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCoipPools: list-shape success (usually empty outside an Outposts /
    Local Zone account) and the DryRun permission-check contract."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_coip_pools()
    assert "CoipPools" in resp, f"expected a CoipPools key in the response, got {sorted(resp)}"
    assert isinstance(resp["CoipPools"], list), (
        f"expected CoipPools to be a list, got {type(resp['CoipPools'])}"
    )

    dry_code, dry_code_msg = _error(lambda: ec2.describe_coip_pools(DryRun=True))
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code}"
    assert dry_code_msg == "Request would have succeeded, but DryRun flag is set.", (
        f"expected the exact DryRunOperation message, got {dry_code_msg!r}"
    )

    # A distinct boundary from DryRun, exercising request-shape validation rather than
    # a resource lookup: an unrecognized filter name is silently tolerated by this
    # operation (it does not raise InvalidFilter), but a garbage pagination token is
    # rejected. Like DescribeCapacityReservationTopology and several other newer EC2
    # Describe* APIs, this operation mints a dedicated InvalidPaginationToken sentinel
    # for a garbage NextToken rather than a generic InvalidParameterValue.
    bogus_token = "sim2real-bogus-token"
    token_code, token_code_msg = _error(
        lambda: ec2.describe_coip_pools(NextToken=bogus_token)
    )
    assert token_code == "InvalidPaginationToken", (
        f"expected InvalidPaginationToken, got {token_code}"
    )
    assert token_code_msg == f"Next token '{bogus_token}' is invalid", (
        f"expected the exact InvalidPaginationToken message, got {token_code_msg!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
