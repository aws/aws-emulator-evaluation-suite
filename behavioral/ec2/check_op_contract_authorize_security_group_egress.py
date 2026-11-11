"""op-contract-authorize-security-group-egress."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-authorize-security-group-egress"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AuthorizeSecurityGroupEgress adds a rule beside the default allow-all egress rule, rejects
    an exact duplicate with InvalidPermission.Duplicate without adding a rule, and succeeds
    again once the original is revoked."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-sgegress-")
    tag = [{"Key": "sim2real", "Value": "1"}]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.98.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    permission = {
        "IpProtocol": "tcp",
        "FromPort": 8080,
        "ToPort": 8080,
        "IpRanges": [{"CidrIp": "10.0.0.0/24", "Description": "sim2real"}],
    }

    def _matching_egress():
        described = ec2.describe_security_group_rules(
            Filters=[{"Name": "group-id", "Values": [sg_id]}]
        )["SecurityGroupRules"]
        return [
            r
            for r in described
            if r["IsEgress"] and r.get("CidrIpv4") == "10.0.0.0/24" and r["FromPort"] == 8080
        ]

    resp = ec2.authorize_security_group_egress(GroupId=sg_id, IpPermissions=[permission])
    assert resp["Return"] is True, f"expected Return=True, got {resp.get('Return')}"
    rules = resp["SecurityGroupRules"]
    assert len(rules) == 1, f"expected exactly one rule in the response, got {rules}"
    rule = rules[0]
    assert rule["GroupId"] == sg_id, f"expected GroupId {sg_id}, got {rule.get('GroupId')}"
    assert rule["IsEgress"] is True, f"expected IsEgress=True, got {rule.get('IsEgress')}"
    assert rule["IpProtocol"] == "tcp", f"expected IpProtocol tcp, got {rule.get('IpProtocol')}"
    assert rule["FromPort"] == 8080 and rule["ToPort"] == 8080, (
        f"expected port range 8080..8080, got {rule.get('FromPort')}..{rule.get('ToPort')}"
    )
    assert rule["CidrIpv4"] == "10.0.0.0/24", (
        f"expected CidrIpv4 10.0.0.0/24, got {rule.get('CidrIpv4')}"
    )

    described = ec2.describe_security_group_rules(
        Filters=[{"Name": "group-id", "Values": [sg_id]}]
    )["SecurityGroupRules"]
    matching = _matching_egress()
    assert len(matching) == 1, f"expected exactly one matching egress rule, found {described}"
    default_egress = [
        r for r in described if r["IsEgress"] and r.get("CidrIpv4") == "0.0.0.0/0" and r["IpProtocol"] == "-1"
    ]
    assert len(default_egress) == 1, f"expected the untouched default egress rule, got {described}"

    code, message = _error_of(
        lambda: ec2.authorize_security_group_egress(GroupId=sg_id, IpPermissions=[permission])
    )
    assert code == "InvalidPermission.Duplicate", f"expected duplicate rejection, got {code}"
    assert message == (
        'the specified rule "peer: 10.0.0.0/24, TCP, from port: 8080, to port: 8080, ALLOW" '
        "already exists"
    ), message

    matching_after_duplicate = _matching_egress()
    assert len(matching_after_duplicate) == 1, (
        f"a rejected duplicate must not add a second rule, found {matching_after_duplicate}"
    )

    revoked = ec2.revoke_security_group_egress(GroupId=sg_id, IpPermissions=[permission])
    assert revoked["Return"] is True, f"expected Return=True on revoke, got {revoked.get('Return')}"
    assert _matching_egress() == [], (
        f"expected the rule gone after revoke, found {_matching_egress()}"
    )

    restored = ec2.authorize_security_group_egress(GroupId=sg_id, IpPermissions=[permission])
    assert restored["Return"] is True, (
        f"expected Return=True re-authorizing after revoke, got {restored.get('Return')}"
    )
    final_matching = _matching_egress()
    assert len(final_matching) == 1, (
        f"expected the identical call to succeed once the duplicate is gone, found {final_matching}"
    )


def _error_of(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError("expected a ClientError, call succeeded unexpectedly")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
