"""op-contract-update-security-group-rule-descriptions-egress."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-update-security-group-rule-descriptions-egress"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSecurityGroupRuleDescriptionsEgress updates the description of an existing
    egress rule (success-path contract) and rejects a request against a non-existent
    security group with InvalidGroup.NotFound (distinct error boundary)."""
    ec2 = ctx.client("ec2")

    vpc_id = ctx.network().vpc_id

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-sgeg-"),
        Description="sim2real egress description update check",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec(ctx, "sg")],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    cidr = "10.0.0.0/8"
    ec2.authorize_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": cidr, "Description": "initial-description"}],
            }
        ],
    )

    updated_description = "updated-by-sim2real-check"
    ec2.update_security_group_rule_descriptions_egress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": cidr, "Description": updated_description}],
            }
        ],
    )

    matched = _poll_until(
        lambda: _find_egress_description(ec2, sg_id, cidr),
        lambda desc: desc == updated_description,
        timeout_s=20.0,
        description="egress rule description updated",
    )
    assert matched == updated_description, (
        f"expected updated egress rule description {updated_description!r}, got {matched!r}"
    )

    # Distinct error boundary: a syntactically valid but non-existent security group ID.
    code, message = _error_code(
        lambda: ec2.update_security_group_rule_descriptions_egress(
            GroupId="sg-00000000000000000",
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": cidr, "Description": "irrelevant"}],
                }
            ],
        )
    )
    assert code == "InvalidGroup.NotFound", f"expected InvalidGroup.NotFound, got {code!r}"
    assert message == "The security group 'sg-00000000000000000' does not exist", message


def _tag_spec(ctx: Any, kind: str) -> dict:
    return {
        "ResourceType": "security-group",
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{kind}-")}],
    }


def _find_egress_description(ec2, sg_id: str, cidr: str):
    resp = ec2.describe_security_group_rules(
        Filters=[{"Name": "group-id", "Values": [sg_id]}]
    )
    for rule in resp["SecurityGroupRules"]:
        if (
            not rule.get("IsEgress")
            or rule.get("CidrIpv4") != cidr
            or rule.get("FromPort") != 443
        ):
            continue
        return rule.get("Description")
    return None


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 30.0, interval_s: float = 1.0, description: str = "condition") -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _error_code(fn: Callable[[], Any]):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
