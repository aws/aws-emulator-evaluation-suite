"""firewall-association-mutation-protection-priority-change-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-association-mutation-protection-priority-change-rejected"
GROUP = "error-semantics"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """When MutationProtection is ENABLED on a FirewallRuleGroupAssociation, changing its
    Priority is rejected with ValidationException and the Priority does not change. Disabling
    MutationProtection first (a distinct, always-permitted update) unblocks the same change."""
    r53r = ctx.client("route53resolver")
    trace_root = _traced(r53r)
    ec2 = ctx.client("ec2")

    group_id = _create_rule_group(ctx, r53r)
    vpc_id = _create_vpc(ctx, ec2)

    assoc = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-afrg-"),
        FirewallRuleGroupId=group_id,
        VpcId=vpc_id,
        Priority=101,
        Name=ctx.unique_name("sim2real-fwassoc-")[:64],
        MutationProtection="ENABLED",
    )["FirewallRuleGroupAssociation"]
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: _safe_disassociate(r53r, assoc_id))
    _poll_until(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ],
        lambda a: a["Status"] == "COMPLETE",
        timeout_s=60,
        interval_s=2,
    )

    # Break exactly one thing: try to change Priority while MutationProtection is ENABLED.
    code, message = _error_code(
        lambda: r53r.update_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id, Priority=200
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    expected = (
        "[RSLVR-02307] The DNS Firewall rule group association is under mutation protection. "
        f'Remove the mutation protection and try again. Trace Id: "{trace_root}"'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: priority is unchanged.
    unchanged = r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
        "FirewallRuleGroupAssociation"
    ]
    assert unchanged["Priority"] == 101

    # Positive control in the same file: disable MutationProtection, then the same
    # priority change that was just rejected now succeeds.
    r53r.update_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=assoc_id, MutationProtection="DISABLED"
    )
    r53r.update_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id, Priority=200)
    changed = _poll_until(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ],
        lambda a: a["Status"] == "COMPLETE" and a["Priority"] == 200,
        timeout_s=60,
        interval_s=2,
    )
    assert changed["Priority"] == 200


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _traced(client):
    """Send one caller-chosen X-Ray trace id on every call of client; return its Root.

    Route 53 Resolver ends a DNS Firewall refusal message with the caller's trace Root,
    so a fixed Root makes the whole message exact.
    """
    root = f"1-{int(time.time()):08x}-{uuid.uuid4().hex[:24]}"
    header = f"Root={root};Sampled=0"

    def _add_header(request, **_):
        request.headers["X-Amzn-Trace-Id"] = header

    client.meta.events.register("before-sign.route53resolver.*", _add_header)
    return root


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _create_vpc(ctx, ec2):
    name = ctx.unique_name("sim2real-r53r-vpc-")
    resp = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id


def _create_rule_group(ctx, r53r):
    group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crg-"),
        Name=ctx.unique_name("sim2real-fwgroup-")[:64],
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_group(r53r, group_id))
    return group_id


def _safe_delete_group(r53r, group_id):
    try:
        r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_disassociate(r53r, assoc_id):
    try:
        # MutationProtection may still be ENABLED if the run failed before disabling it.
        try:
            r53r.update_firewall_rule_group_association(
                FirewallRuleGroupAssociationId=assoc_id, MutationProtection="DISABLED"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    # The rule group delete that runs next is refused until the association is gone.
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        try:
            r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3.0)
    raise AssertionError(f"association {assoc_id} was not removed within 180s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
