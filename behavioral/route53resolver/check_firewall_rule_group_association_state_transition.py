"""firewall-rule-group-association-state-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-rule-group-association-state-transition"
GROUP = "state-machine"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateFirewallRuleGroup yields a COMPLETE association that
    GetFirewallRuleGroupAssociation and ListFirewallRuleGroupAssociations both return, and
    DisassociateFirewallRuleGroup removes it from both.
    """
    ec2 = ctx.client("ec2")
    r53r = ctx.client("route53resolver")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.92.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    rule_group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-frg-cr-"),
        Name=ctx.unique_name("sim2real-frg-"),
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda: r53r.delete_firewall_rule_group(FirewallRuleGroupId=rule_group_id))

    assoc = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-assoc-cr-"),
        FirewallRuleGroupId=rule_group_id,
        VpcId=vpc_id,
        Priority=101,
        Name=ctx.unique_name("sim2real-frg-assoc-"),
    )["FirewallRuleGroupAssociation"]
    assoc_id = assoc["Id"]

    status = _poll_until(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ]["Status"],
        lambda s: s in ("COMPLETE", "DELETING"),
        timeout_s=120,
        interval_s=5,
    )
    assert status == "COMPLETE", f"association reached {status!r} instead of COMPLETE"

    fetched = r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
        "FirewallRuleGroupAssociation"
    ]
    assert fetched["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r}, got {fetched['VpcId']!r}"
    assert fetched["FirewallRuleGroupId"] == rule_group_id, (
        f"expected FirewallRuleGroupId {rule_group_id!r}, got {fetched['FirewallRuleGroupId']!r}"
    )
    assert fetched["Priority"] == 101, f"expected Priority 101, got {fetched['Priority']!r}"

    listed = r53r.list_firewall_rule_group_associations()["FirewallRuleGroupAssociations"]
    assert any(a["Id"] == assoc_id for a in listed), (
        "association missing from ListFirewallRuleGroupAssociations"
    )

    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    _poll_until(
        lambda: _still_present(
            lambda: r53r.get_firewall_rule_group_association(
                FirewallRuleGroupAssociationId=assoc_id
            )
        ),
        lambda still: not still,
        timeout_s=120,
        interval_s=5,
    )
    code, message = _error(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f'[RSLVR-02025] Can\u2019t find the resource with ID "{assoc_id}".'
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    remaining = r53r.list_firewall_rule_group_associations()["FirewallRuleGroupAssociations"]
    assert not any(a["Id"] == assoc_id for a in remaining), "disassociated rule group still listed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


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


def _still_present(fn) -> bool:
    """True while fn() succeeds; False once it raises ResourceNotFoundException."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return False
        raise
    return True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
