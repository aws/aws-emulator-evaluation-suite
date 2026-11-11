"""op-contract-get-security-groups-for-vpc."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "op-contract-get-security-groups-for-vpc"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSecurityGroupsForVpc lists the VPC's default security group with PrimaryVpcId set;
    a well-formed but nonexistent VPC ID is rejected as InvalidVpcId.Malformed."""
    ec2 = ctx.client("ec2")

    # Read-only, so the shared network VPC suffices and costs nothing against the VPC limit.
    vpc_id = _get_default_vpc(ec2, ctx=ctx)

    default_sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]

    sg_set = ec2.get_security_groups_for_vpc(VpcId=vpc_id)["SecurityGroupForVpcs"]
    match = next((sg for sg in sg_set if sg["GroupId"] == default_sg_id), None)
    assert match is not None, f"default SG {default_sg_id} missing from {sg_set!r}"
    assert match["PrimaryVpcId"] == vpc_id, (
        f"expected PrimaryVpcId {vpc_id!r}, got {match['PrimaryVpcId']!r}"
    )

    # Unlike DescribeVpcs, this operation reports a plausible but unissued VPC ID as Malformed
    # (lowercase "Id"), not InvalidVpcID.NotFound.
    bogus_id = _bogus_id_like(vpc_id)
    code, message = _client_error(lambda: ec2.get_security_groups_for_vpc(VpcId=bogus_id))
    assert code == "InvalidVpcId.Malformed", f"unexpected error code: {code}"
    expected_message = f"The vpc ID '{bogus_id}' is malformed"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _get_default_vpc(ec2, *, ctx) -> str:
    """Return the shared network's VPC id, failing if it is not visible."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    return vpcs[0]["VpcId"]


def _client_error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _bogus_id_like(real_id: str) -> str:
    def repl(m):
        return "f" * len(m.group())
    bogus = re.sub(r"[0-9a-f]+$", repl, real_id)
    assert bogus != real_id, "could not derive a distinct bogus id"
    return bogus


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
