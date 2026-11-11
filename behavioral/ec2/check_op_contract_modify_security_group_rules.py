"""op-contract-modify-security-group-rules."""
from __future__ import annotations

import time
from behavioral_harness import tags

CHECK = "op-contract-modify-security-group-rules"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifySecurityGroupRules: updating an existing rule's port/description is
    observable via DescribeSecurityGroupRules, and a fabricated rule id is rejected."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-sg-")
    vpc_id = _shared_vpc(ctx)

    sg = ec2.create_security_group(
        GroupName=name, Description="behavioral test sg", VpcId=vpc_id,
        TagSpecifications=[_tag_spec("security-group", name)],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))

    authorized = ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "10.0.0.0/32"}]}
        ],
    )
    rule_id = authorized["SecurityGroupRules"][0]["SecurityGroupRuleId"]

    ec2.modify_security_group_rules(
        GroupId=sg_id,
        SecurityGroupRules=[
            {
                "SecurityGroupRuleId": rule_id,
                "SecurityGroupRule": {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "CidrIpv4": "10.0.0.0/32",
                    "Description": "updated-to-443",
                },
            }
        ],
    )
    rules = ec2.describe_security_group_rules(
        Filters=[{"Name": "group-id", "Values": [sg_id]}]
    )["SecurityGroupRules"]
    updated = next(r for r in rules if r["SecurityGroupRuleId"] == rule_id)
    assert updated["FromPort"] == 443 and updated["ToPort"] == 443, (
        f"expected ports 443/443 after modify, got {updated['FromPort']}/{updated['ToPort']}: {updated}"
    )
    assert updated["Description"] == "updated-to-443", (
        f"expected description 'updated-to-443' after modify, got {updated['Description']!r}: {updated}"
    )

    # error boundary: fabricated rule id
    err, err_message = _client_error(
        lambda: ec2.modify_security_group_rules(
            GroupId=sg_id,
            SecurityGroupRules=[
                {
                    "SecurityGroupRuleId": "sgr-00000000000000000",
                    "SecurityGroupRule": {
                        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIpv4": "10.0.0.0/32"
                    },
                }
            ],
        )
    )
    assert err == "InvalidSecurityGroupRuleId.NotFound", (
        f"expected InvalidSecurityGroupRuleId.NotFound for a fabricated rule id, got {err!r}"
    )
    expected_message = "The security group rule ID 'sgr-00000000000000000' does not exist"
    assert err_message == expected_message, f"expected message {expected_message!r}, got {err_message!r}"


def _client_error(fn):
    """Call fn() and return its error (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _shared_vpc(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
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
