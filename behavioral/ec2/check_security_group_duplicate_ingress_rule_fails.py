"""security-group-duplicate-ingress-rule-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-duplicate-ingress-rule-fails"
GROUP = 'error-semantics'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Authorizing an identical ingress rule twice raises InvalidPermission.Duplicate."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"] == "available":
            break
        time.sleep(2)

    gid = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="behavioral check sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=gid))
    perms = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "198.51.100.0/32"}]}]

    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
    try:
        ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidPermission.Duplicate", f"expected InvalidPermission.Duplicate, got {code}"
    expected = 'the specified rule "peer: 198.51.100.0/32, TCP, from port: 443, to port: 443, ALLOW" already exists'
    assert message == expected, f"unexpected message: {message!r}"

    rules = ec2.describe_security_group_rules(
        Filters=[{"Name": "group-id", "Values": [gid]}]
    )["SecurityGroupRules"]
    matching = [
        r for r in rules
        if not r["IsEgress"]
        and r.get("IpProtocol") == "tcp"
        and r.get("FromPort") == 443
        and r.get("ToPort") == 443
        and r.get("CidrIpv4") == "198.51.100.0/32"
    ]
    assert len(matching) == 1, (
        f"expected exactly one ingress rule to survive the rejected duplicate, got {len(matching)}: {matching}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
