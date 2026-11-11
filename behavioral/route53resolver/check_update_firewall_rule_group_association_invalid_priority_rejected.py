"""update-firewall-rule-group-association-invalid-priority-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-firewall-rule-group-association-invalid-priority-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFirewallRuleGroupAssociation to Priority 99999, outside 100-9900, is refused with
    ValidationException and leaves Priority 137 stored, while an update to 502 succeeds and
    persists.
    """
    r53r = ctx.client("route53resolver")

    vpc_id = _create_vpc(ctx)
    group_id = _create_firewall_rule_group(ctx)
    assoc = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
        FirewallRuleGroupId=group_id,
        VpcId=vpc_id,
        Priority=137,
        Name=ctx.unique_name("sim2real-behav-assoc-"),
    )["FirewallRuleGroupAssociation"]
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: _disassociate_and_wait(r53r, assoc_id))

    refusal = _error(
        lambda: r53r.update_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id, Priority=99999
        )
    )
    expected = (
        "ValidationException",
        '[RSLVR-02018] The Priority you provided is not valid. Provide a number smaller than "10000".',
    )
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    unchanged = r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
        "FirewallRuleGroupAssociation"
    ]
    assert unchanged["Priority"] == 137, f"priority must remain 137, got {unchanged['Priority']}"

    # Positive control: an in-range priority update succeeds and persists.
    r53r.update_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id, Priority=502)
    updated = r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
        "FirewallRuleGroupAssociation"
    ]
    assert updated["Priority"] == 502, f"expected persisted priority 502, got {updated['Priority']}"


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _disassociate_and_wait(r53r, assoc_id: str, timeout_s: float = 180.0) -> None:
    """Disassociate, then wait until the association is gone so the group and VPC can go."""
    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"association {assoc_id} still present {timeout_s}s after disassociate")
        time.sleep(3.0)


def _create_vpc(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    vpc = ec2.create_vpc(
        CidrBlock="10.80.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _create_firewall_rule_group(ctx) -> str:
    r53r = ctx.client("route53resolver")
    group = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
        Name=ctx.unique_name("sim2real-behav-frg-"),
    )["FirewallRuleGroup"]
    group_id = group["Id"]
    ctx.on_cleanup(lambda: r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id))
    return group_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
