"""disassociate-firewall-rule-group-nonexistent-association-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-firewall-rule-group-nonexistent-association-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateFirewallRuleGroup for an association id never created is refused with
    ResourceNotFoundException and leaves the real association in place; the real one then
    disassociates, and repeating that call on its id is refused the same way.
    """
    r53r = ctx.client("route53resolver")
    trace_root = _traced(r53r)
    ec2 = ctx.client("ec2")

    vpc_name = ctx.unique_name("sim2real-r53r-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.94.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-frg-"),
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_rule_group_best_effort(r53r, group_id))

    real_assoc_id = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        FirewallRuleGroupId=group_id,
        VpcId=vpc_id,
        Priority=101,
        Name=ctx.unique_name("sim2real-frg-assoc-"),
    )["FirewallRuleGroupAssociation"]["Id"]
    ctx.on_cleanup(lambda: _disassociate_best_effort(r53r, real_assoc_id))
    _poll_assoc_status(r53r, real_assoc_id, {"COMPLETE"}, timeout_s=120.0)

    fake_assoc_id = "rslvr-frgassoc-" + "0" * 17
    code, message = _client_error(
        lambda: r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=fake_assoc_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = (
        f'[RSLVR-02025] Can’t find the resource with ID "{fake_assoc_id}". Trace Id: "{trace_root}"'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    still_there = r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=real_assoc_id)[
        "FirewallRuleGroupAssociation"
    ]
    assert still_there["Status"] in ("COMPLETE", "UPDATING"), (
        f"real association was disturbed by the rejected call on the fake id, "
        f"status={still_there['Status']!r}"
    )

    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=real_assoc_id)
    removed = _poll_until_removed(r53r, real_assoc_id, timeout_s=120.0)
    assert removed, "real association was never removed by a valid DisassociateFirewallRuleGroup call"

    dead_code, dead_message = _client_error(
        lambda: r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=real_assoc_id)
    )
    assert dead_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException disassociating an already-removed association, "
        f"got {dead_code!r}"
    )
    expected = (
        f'[RSLVR-02025] Can’t find the resource with ID "{real_assoc_id}". Trace Id: "{trace_root}"'
    )
    assert dead_message == expected, f"expected message {expected!r}, got {dead_message!r}"


def _client_error(fn):
    """Call fn(), which AWS refuses; return the (code, message) of its ClientError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


def _delete_rule_group_best_effort(r53r, group_id: str) -> None:
    try:
        r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id)
    except (r53r.exceptions.ResourceNotFoundException, r53r.exceptions.ConflictException):
        pass


def _disassociate_best_effort(r53r, assoc_id: str) -> None:
    try:
        r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    except r53r.exceptions.ResourceNotFoundException:
        pass


def _poll_assoc_status(r53r, assoc_id: str, terminal_statuses, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ]["Status"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    return status


def _poll_until_removed(r53r, assoc_id: str, timeout_s=120.0, interval_s=3.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
        except r53r.exceptions.ResourceNotFoundException:
            return True
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
