"""security-group-authorize-revoke-ingress."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-authorize-revoke-ingress"
GROUP = 'security-group'
SERVICES = ['ec2']
#: The default service-class budget for a poll; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0
_RULE = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "203.0.113.0/32"}]}

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AuthorizeSecurityGroupIngress adds a rule that DescribeSecurityGroups reflects; RevokeSecurityGroupIngress removes it."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        if ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"] == "available":
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"VPC not available after {POLL_BUDGET_S:.0f}s")
        time.sleep(2)

    group_name = ctx.unique_name("sim2real-behav-sg-")
    gid = ec2.create_security_group(
        GroupName=group_name,
        Description="behavioral check sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["GroupId"]
    deleted_sg = {"value": False}
    ctx.on_cleanup(lambda: None if deleted_sg["value"] else ec2.delete_security_group(GroupId=gid))

    ec2.authorize_security_group_ingress(
        GroupId=gid,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "203.0.113.0/32"}]}
        ],
    )
    sg = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]
    assert any(
        p.get("IpProtocol") == "tcp"
        and p.get("FromPort") == 22
        and p.get("ToPort") == 22
        and any(r.get("CidrIp") == "203.0.113.0/32" for r in p.get("IpRanges", []))
        for p in sg["IpPermissions"]
    ), f"expected ingress rule present, got {sg['IpPermissions']}"
    rules = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [gid]}]).get("SecurityGroupRules", [])
    assert any(
        not r.get("IsEgress") and r.get("IpProtocol") == "tcp" and r.get("FromPort") == 22
        and r.get("ToPort") == 22 and r.get("CidrIpv4") == "203.0.113.0/32"
        for r in rules
    ), f"DescribeSecurityGroupRules does not reflect the authorized ingress rule: {rules!r}"

    ec2.revoke_security_group_ingress(
        GroupId=gid,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "203.0.113.0/32"}]}
        ],
    )
    sg = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]
    assert not any(
        p.get("IpProtocol") == "tcp"
        and p.get("FromPort") == 22
        and p.get("ToPort") == 22
        and any(r.get("CidrIp") == "203.0.113.0/32" for r in p.get("IpRanges", []))
        for p in sg["IpPermissions"]
    ), f"expected ingress rule removed, got {sg['IpPermissions']}"

    ec2.delete_security_group(GroupId=gid)
    deleted_sg["value"] = True
    gone_message = f"The security group '{gid}' does not exist"
    err = _error(lambda: ec2.describe_security_groups(GroupIds=[gid]))
    _assert_error(err, "InvalidGroup.NotFound", gid)
    assert err["Error"]["Message"] == gone_message, err["Error"]["Message"]
    by_name = ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": [group_name]}, {"Name": "vpc-id", "Values": [vpc_id]}]
    )["SecurityGroups"]
    assert not by_name, f"the deleted group is still listed by name: {[g['GroupId'] for g in by_name]!r}"
    err = _error(lambda: ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[_RULE]))
    _assert_error(err, "InvalidGroup.NotFound", None, status=None)
    assert err["Error"]["Message"] == gone_message, err["Error"]["Message"]


def _error(fn):
    """Call fn() and return its ClientError response; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _assert_error(resp, code, subject, status=400):
    """Grade a refusal on code + HTTP status (any 4xx when status is None) + a non-empty message
    (naming the subject id if given)."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert err.get("Code") == code, f"expected {code}, got {err.get('Code')!r}"
    if status is None:
        assert isinstance(got_status, int) and 400 <= got_status < 500, f"expected a 4xx for {code}, got {got_status!r}"
    else:
        assert got_status == status, f"expected HTTP {status} for {code}, got {got_status!r}"
    assert err.get("Message"), f"expected a non-empty {code} message, got {err!r}"
    if subject is not None:
        assert subject in err["Message"], f"expected the {code} message to name {subject!r}, got {err['Message']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
