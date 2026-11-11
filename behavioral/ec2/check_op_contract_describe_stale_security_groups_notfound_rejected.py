"""op-contract-describe-stale-security-groups-notfound-rejected."""
from __future__ import annotations

import random

from behavioral_harness import tags

CHECK = "op-contract-describe-stale-security-groups-notfound-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStaleSecurityGroups returns no stale groups for a new VPC, and a short-form VpcId that does not
    exist fails with InvalidVpcID.NotFound and its exact message."""
    ec2 = ctx.client("ec2")
    cidr = f"10.{random.randint(0, 200)}.0.0/16"
    vpc_id = ec2.create_vpc(CidrBlock=cidr)["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    resp = ec2.describe_stale_security_groups(VpcId=vpc_id)
    assert "StaleSecurityGroupSet" in resp, f"expected StaleSecurityGroupSet key, got {resp!r}"
    assert resp["StaleSecurityGroupSet"] == [], "a fresh VPC must have no stale SG rules"

    # DescribeStaleSecurityGroups accepts only the 8-hex-char VpcId form; a 17-char suffix is
    # rejected as malformed before any existence lookup, so the short form reaches NotFound.
    fake_vpc = "vpc-" + "f" * 8
    code, message = _error(lambda: ec2.describe_stale_security_groups(VpcId=fake_vpc))
    # The code spells "ID" in capitals, like InvalidSubnetID.NotFound.
    assert code == "InvalidVpcID.NotFound", f"expected NotFound, got {code!r}"
    assert message == f"{fake_vpc} is not found for user.", message


def _error(fn):
    """Call fn() and return its error code and message; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected NotFound rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
