"""check-create-vpc-block-public-access-exclusion-missing-target-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "check-create-vpc-block-public-access-exclusion-missing-target-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpcBlockPublicAccessExclusion naming neither VpcId nor SubnetId is refused MissingParameter
    and leaves no exclusion carrying its tag behind; the same call with a VpcId is accepted first as a
    control."""
    ec2 = ctx.client("ec2")

    # --- positive control: a request that DOES name a target is accepted ---
    vpc_id = ec2.create_vpc(
        CidrBlock="10.94.0.0/16",
        TagSpecifications=[_tag_spec(ctx, "vpc", "bpa-target")],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe_delete_vpc(ctx, vpc_id))

    control = ec2.create_vpc_block_public_access_exclusion(
        VpcId=vpc_id,
        InternetGatewayExclusionMode="allow-bidirectional",
        TagSpecifications=[_tag_spec(ctx, "vpc-block-public-access-exclusion", "bpa-control")],
    )["VpcBlockPublicAccessExclusion"]
    control_id = control["ExclusionId"]
    ctx.on_cleanup(lambda: _safe_delete_exclusion(ctx, control_id))
    assert control["State"] in ("create-in-progress", "create-complete"), control["State"]

    # DescribeVpcBlockPublicAccessExclusions requires at least one of ExclusionIds or
    # MaxResults on real AWS (MissingParameter otherwise); MaxResults alone lists everything.
    listed = {e["ExclusionId"] for e in _exclusions(ec2)}
    assert control_id in listed, "control exclusion is not visible in an independent read"

    # Real AWS treats "no VpcId and no SubnetId given" as a missing-required-parameter
    # condition (one of the two is required to name a target), not as a conflicting
    # combination of parameters -- so the API rejects with MissingParameter, not
    # InvalidParameterCombination (which is reserved for cases where mutually exclusive
    # parameters are both supplied).
    rejected_spec = _tag_spec(ctx, "vpc-block-public-access-exclusion", "bpa-rejected")
    rejected_name = rejected_spec["Tags"][0]["Value"]
    code, message = _error(
        lambda: ec2.create_vpc_block_public_access_exclusion(
            InternetGatewayExclusionMode="allow-bidirectional",
            TagSpecifications=[rejected_spec],
        )
    )
    assert code == "MissingParameter", f"expected MissingParameter, got {code}"
    assert message == "One of the following parameters must be provided: VpcId, SubnetId", f"unexpected MissingParameter message {message!r}"

    phantom = [
        e["ExclusionId"]
        for e in _exclusions(ec2)
        if {"Key": "Name", "Value": rejected_name} in (e.get("Tags") or [])
    ]
    assert phantom == [], f"rejected create left a phantom exclusion behind: {phantom!r}"


# ===== helpers =====

def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _exclusions(ec2) -> list:
    """Every VPC BPA exclusion in the region, read through all pages."""
    out, kwargs = [], {"MaxResults": 1000}
    while True:
        page = ec2.describe_vpc_block_public_access_exclusions(**kwargs)
        out.extend(page["VpcBlockPublicAccessExclusions"])
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: a call AWS refuses that succeeds is reported as such,
    not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_exclusion(ctx, exclusion_id: str) -> None:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + 45.0
    while True:
        try:
            ec2.delete_vpc_block_public_access_exclusion(ExclusionId=exclusion_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVpcBlockPublicAccessExclusionId.NotFound":
                return
            # A delete is refused while the exclusion is still being created.
            if code != "IncorrectState" or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _safe_delete_vpc(ctx, vpc_id: str) -> None:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    try:
        ec2.delete_vpc(VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
