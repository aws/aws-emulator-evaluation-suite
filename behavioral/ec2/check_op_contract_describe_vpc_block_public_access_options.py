"""op-contract-describe-vpc-block-public-access-options."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-vpc-block-public-access-options"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVpcBlockPublicAccessOptions returns the caller's account and region with a documented
    State, InternetGatewayBlockMode and ExclusionsAllowed, and DryRun answers DryRunOperation with its
    exact message."""
    ec2 = ctx.client("ec2")

    account_id = ctx.client("sts").get_caller_identity()["Account"]

    resp = ec2.describe_vpc_block_public_access_options()
    options = resp["VpcBlockPublicAccessOptions"]
    # AwsAccountId/AwsRegion echo the caller's own identity (an independent side-channel via
    # STS), so a target that ignores the caller and returns a fixed canned response is caught
    # here even though the State/BlockMode/ExclusionsAllowed enums are fully covered either way.
    assert options["AwsAccountId"] == account_id, (
        f"expected AwsAccountId {account_id!r}, got {options['AwsAccountId']!r}"
    )
    assert options["AwsRegion"] == ctx.region, (
        f"expected AwsRegion {ctx.region!r}, got {options['AwsRegion']!r}"
    )
    assert options["State"] in ("default-state", "update-in-progress", "update-complete"), (
        f"unexpected State {options['State']!r}"
    )
    assert options["InternetGatewayBlockMode"] in ("off", "block-bidirectional", "block-ingress"), (
        f"unexpected InternetGatewayBlockMode {options['InternetGatewayBlockMode']!r}"
    )
    assert options["ExclusionsAllowed"] in ("allowed", "not-allowed"), (
        f"unexpected ExclusionsAllowed {options['ExclusionsAllowed']!r}"
    )

    code, message = _error(lambda: ec2.describe_vpc_block_public_access_options(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"


_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a DryRun call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"DryRun=True unexpectedly SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
