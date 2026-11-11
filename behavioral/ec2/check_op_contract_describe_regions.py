"""op-contract-describe-regions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-regions"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeRegions: the target region itself is always present with a
    matching endpoint and opt-in status; DryRun=True rejects with
    DryRunOperation."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_regions()
    regions = resp["Regions"]
    assert isinstance(regions, list) and len(regions) > 0
    mine = next((r for r in regions if r["RegionName"] == ctx.region), None)
    assert mine is not None, f"expected {ctx.region} in {regions}"
    assert mine["Endpoint"].startswith("ec2."), mine["Endpoint"]
    assert mine["OptInStatus"] in ("opt-in-not-required", "opted-in", "not-opted-in")

    code, msg = _client_error(lambda: ec2.describe_regions(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_msg = "Request would have succeeded, but DryRun flag is set."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
