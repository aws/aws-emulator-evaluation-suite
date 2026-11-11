"""delete-firewall-rule-group-active-association-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-firewall-rule-group-active-association-rejected"
GROUP = "error-semantics"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a FirewallRuleGroup that still has an active VPC association is rejected
    with ConflictException and the rule group is left in place; disassociating first
    (removing the conflicting state) allows the exact same delete call to succeed."""
    r53r = ctx.client("route53resolver")
    trace_root = _traced(r53r)
    ec2 = ctx.client("ec2")

    group_id = _create_rule_group(ctx, r53r)
    vpc_id = _create_vpc(ctx, ec2)

    assoc_id = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-afrg-"),
        FirewallRuleGroupId=group_id,
        VpcId=vpc_id,
        Priority=101,
        Name=ctx.unique_name("sim2real-fwassoc-")[:64],
        MutationProtection="DISABLED",
    )["FirewallRuleGroupAssociation"]["Id"]
    _poll_until(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ],
        lambda a: a["Status"] == "COMPLETE",
        timeout_s=60,
        interval_s=2,
    )

    # Break exactly one thing: try to delete the rule group while it is still associated.
    code, message = _client_error(
        lambda: r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id)
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected = (
        f'[RSLVR-02101] The DNS Firewall rule group is associated to a VPC: "{group_id}". '
        f'Delete the association and try again later. Trace Id: "{trace_root}"'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rule group still exists and is usable.
    still_there = r53r.get_firewall_rule_group(FirewallRuleGroupId=group_id)["FirewallRuleGroup"]
    assert still_there["Id"] == group_id, (
        f"expected the rejected delete to leave {group_id!r} in place, got {still_there!r}"
    )

    # Positive control in the same file: remove the conflicting association, then the
    # exact same delete call succeeds.
    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    _poll_until(
        lambda: _get_association_or_none(r53r, assoc_id),
        lambda a: a is None,
        timeout_s=60,
        interval_s=2,
    )
    r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id)
    deleted_code, deleted_message = _client_error(
        lambda: r53r.get_firewall_rule_group(FirewallRuleGroupId=group_id)
    )
    assert deleted_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the deleted group, got {deleted_code!r}"
    )
    expected = (
        f'[RSLVR-02025] Can’t find the resource with ID "{group_id}". Trace Id: "{trace_root}"'
    )
    assert deleted_message == expected, f"expected message {expected!r}, got {deleted_message!r}"


def _client_error(fn):
    """Call fn(), which AWS refuses; return the (code, message) of its ClientError."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded; expected AWS to refuse it with a ClientError")


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


def _get_association_or_none(r53r, assoc_id):
    try:
        return r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
