"""op-contract-create-security-group."""
from __future__ import annotations

import time
from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-security-group"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSecurityGroup creates a group with the default allow-all egress rule; a duplicate name in
    the same VPC fails with InvalidGroup.Duplicate and mints no second group; after delete the name
    is reusable with a new ID and the old ID fails InvalidGroup.NotFound on describe and revoke."""
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": "create-security-group-contract"}]
    name = ctx.unique_name("sim2real-sg-")

    vpc_id = _default_vpc_id(ec2, ctx=ctx)

    resp = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )
    group_id = resp["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(ec2, group_id))

    assert group_id.startswith("sg-")
    assert "SecurityGroupArn" in resp

    described = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    assert described["GroupName"] == name
    assert described["VpcId"] == vpc_id
    egress = described["IpPermissionsEgress"]
    assert any(
        rule.get("IpProtocol") == "-1"
        and any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
        for rule in egress
    ), f"expected default allow-all egress rule, got {egress!r}"

    # Error boundary: reusing GroupName within the same VPC must be rejected.
    code, message = _error_of(
        lambda: ec2.create_security_group(
            GroupName=name, Description="duplicate", VpcId=vpc_id
        )
    )
    assert code == "InvalidGroup.Duplicate", f"expected InvalidGroup.Duplicate, got {code!r}"
    assert message == f"The security group '{name}' already exists for VPC '{vpc_id}'", message

    # Effect-absent: the rejected duplicate must not have minted a second group under the name.
    matching = ec2.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [name]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    )["SecurityGroups"]
    assert len(matching) == 1, f"expected exactly one group named {name!r}, got {len(matching)}"

    # Restore: deleting the original frees the name for a genuinely identical create.
    ec2.delete_security_group(GroupId=group_id)
    retry_resp = ec2.create_security_group(
        GroupName=name,
        Description="reused after delete",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )
    new_group_id = retry_resp["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(ec2, new_group_id))
    assert new_group_id != group_id, "reusing the freed name must mint a fresh group id"

    # Deletes prove gone and unusable: an independent read reports the specific not-found code,
    # and a mutation against the dead id fails the same way.
    code, message = _error_of(lambda: ec2.describe_security_groups(GroupIds=[group_id]))
    assert code == "InvalidGroup.NotFound", f"expected InvalidGroup.NotFound, got {code!r}"
    assert message == f"The security group '{group_id}' does not exist", message
    code, message = _error_of(
        lambda: ec2.revoke_security_group_egress(
            GroupId=group_id,
            IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )
    )
    assert code == "InvalidGroup.NotFound", f"expected InvalidGroup.NotFound, got {code!r}"
    assert message == f"The security group '{group_id}' does not exist", message


def _error_of(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete(ec2, group_id):
    try:
        _delete_security_group_when_free(ec2, group_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidGroup.NotFound":
            raise


def _default_vpc_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    return vpcs[0]["VpcId"]


def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
