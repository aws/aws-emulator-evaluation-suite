"""op-contract-describe-vpc-block-public-access-exclusions."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-describe-vpc-block-public-access-exclusions"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVpcBlockPublicAccessExclusions reflects a real exclusion and rejects DryRun."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.124.0.0/16",
        TagSpecifications=[_tag_spec(ctx, "vpc", "bpa-vpc")],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    created = ec2.create_vpc_block_public_access_exclusion(
        VpcId=vpc_id,
        InternetGatewayExclusionMode="allow-bidirectional",
        TagSpecifications=[_tag_spec(ctx, "vpc-block-public-access-exclusion", "bpa-excl")],
    )["VpcBlockPublicAccessExclusion"]
    exclusion_id = created["ExclusionId"]

    def _cleanup_exclusion():
        _poll_until(
            lambda: _exclusion_state(ec2, exclusion_id),
            lambda s: s in ("create-complete", "create-failed", "delete-complete"),
            timeout_s=300,
        )
        try:
            ec2.delete_vpc_block_public_access_exclusion(ExclusionId=exclusion_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcBlockPublicAccessExclusionId.NotFound":
                raise
            return
        _poll_until(
            lambda: _exclusion_state(ec2, exclusion_id),
            lambda s: s in ("delete-complete", "not-found"),
            timeout_s=300,
        )

    ctx.on_cleanup(_cleanup_exclusion)

    # A new exclusion id can read back as not-found for a few seconds after the create.
    _poll_until(
        lambda: _exclusion_state(ec2, exclusion_id),
        lambda s: s in ("create-complete", "create-failed"),
        timeout_s=300,
    )
    entry = _describe_exclusion(ec2, exclusion_id)
    assert entry["State"] == "create-complete", f"exclusion ended in {entry['State']!r}"
    assert entry["InternetGatewayExclusionMode"] == "allow-bidirectional", (
        f"expected allow-bidirectional, got {entry['InternetGatewayExclusionMode']!r}"
    )
    assert vpc_id in entry.get("ResourceArn", ""), (
        f"expected exclusion ResourceArn to reference {vpc_id}, got {entry.get('ResourceArn')!r}"
    )

    code, message = _error(lambda: ec2.describe_vpc_block_public_access_exclusions(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"


_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


def _describe_exclusion(ec2, exclusion_id: str) -> dict:
    resp = ec2.describe_vpc_block_public_access_exclusions(ExclusionIds=[exclusion_id])
    items = resp["VpcBlockPublicAccessExclusions"]
    assert len(items) == 1, f"expected exactly one exclusion entry, got {len(items)}"
    return items[0]


def _exclusion_state(ec2, exclusion_id: str) -> str:
    from botocore.exceptions import ClientError

    try:
        return _describe_exclusion(ec2, exclusion_id)["State"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "InvalidVpcBlockPublicAccessExclusionId.NotFound":
            return "not-found"
        raise


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
