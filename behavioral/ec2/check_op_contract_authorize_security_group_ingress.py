"""op-contract-authorize-security-group-ingress."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-authorize-security-group-ingress"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AuthorizeSecurityGroupIngress adds a real rule visible via describe, rejects an exact
    duplicate with InvalidPermission.Duplicate without inserting a second copy, and accepts the
    identical rule again once the original has been revoked."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-sgingress-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.99.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    permission = {
        "IpProtocol": "tcp",
        "FromPort": 2222,
        "ToPort": 2222,
        "IpRanges": [{"CidrIp": "203.0.113.0/24", "Description": "sim2real"}],
    }

    def matching_rules():
        described = ec2.describe_security_group_rules(
            Filters=[{"Name": "group-id", "Values": [sg_id]}]
        )["SecurityGroupRules"]
        return [
            r
            for r in described
            if not r["IsEgress"]
            and r.get("CidrIpv4") == "203.0.113.0/24"
            and r["FromPort"] == 2222
        ]

    resp = ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[permission])
    assert resp["Return"] is True, f"expected Return=True, got {resp['Return']}"
    rules = resp["SecurityGroupRules"]
    assert len(rules) == 1, f"expected exactly one rule created, got {len(rules)}"
    rule = rules[0]
    assert rule["GroupId"] == sg_id, f"expected GroupId {sg_id}, got {rule['GroupId']}"
    assert rule["IsEgress"] is False, f"expected an ingress rule, got IsEgress={rule['IsEgress']}"
    assert rule["IpProtocol"] == "tcp", f"expected tcp, got {rule['IpProtocol']}"
    assert rule["FromPort"] == 2222 and rule["ToPort"] == 2222, (
        f"expected port 2222, got {rule['FromPort']}-{rule['ToPort']}"
    )
    assert rule["CidrIpv4"] == "203.0.113.0/24", f"expected 203.0.113.0/24, got {rule['CidrIpv4']}"

    matching = matching_rules()
    assert len(matching) == 1, f"expected exactly one matching ingress rule, found {matching}"

    code, code_message = _error_code(
        lambda: ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[permission])
    )
    assert code == "InvalidPermission.Duplicate", f"expected duplicate rejection, got {code}"
    expected_code_message = (
        'the specified rule "peer: 203.0.113.0/24, TCP, from port: 2222, to port: 2222, ALLOW" '
        "already exists"
    )
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    matching = matching_rules()
    assert len(matching) == 1, (
        f"duplicate rejection must not insert a second copy, found {matching}"
    )

    ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[permission])
    matching = matching_rules()
    assert len(matching) == 0, f"expected rule removed after revoke, found {matching}"

    resp = ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[permission])
    assert resp["Return"] is True, (
        f"expected the identical rule to be authorizable again after revoke, got Return={resp['Return']}"
    )
    matching = matching_rules()
    assert len(matching) == 1, f"expected rule restored after revoke+reauthorize, found {matching}"


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
