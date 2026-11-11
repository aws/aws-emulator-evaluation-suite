"""concurrent-firewall-rule-group-association-update-race."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-firewall-rule-group-association-update-race"
GROUP = "concurrency"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateFirewallRuleGroupAssociation calls changing one association's Priority each
    succeed or fail with ConflictException, at least one succeeds, and the association returns to
    COMPLETE with one of the requested priorities.
    """
    r53r = ctx.client("route53resolver")
    ec2 = ctx.client("ec2")
    # One teardown deadline for this run's deletes.
    teardown = {}

    group_id = _create_rule_group(ctx, r53r, teardown)
    vpc_id = _create_vpc(ctx, ec2, teardown)

    assoc_id = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-afrg-"),
        FirewallRuleGroupId=group_id,
        VpcId=vpc_id,
        Priority=101,
        Name=ctx.unique_name("sim2real-fwassoc-")[:64],
        MutationProtection="DISABLED",
    )["FirewallRuleGroupAssociation"]["Id"]
    ctx.on_cleanup(lambda: _safe_disassociate(r53r, assoc_id, teardown))
    # A new association can stay UPDATING ("Creating ...") for minutes before COMPLETE.
    _poll_until(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ],
        lambda a: a["Status"] == "COMPLETE",
        timeout_s=600,
        interval_s=2,
    )

    racer_priorities = [201, 202, 203, 204]
    barrier = threading.Barrier(len(racer_priorities))

    def racer(priority):
        barrier.wait()
        try:
            r53r.update_firewall_rule_group_association(
                FirewallRuleGroupAssociationId=assoc_id, Priority=priority
            )
            return ("ok", priority, None)
        except ClientError as e:
            return ("error", priority, e.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=len(racer_priorities)) as pool:
        results = list(pool.map(racer, racer_priorities))

    successes = [r for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] == "error"]

    assert len(successes) + len(errors) == len(racer_priorities)
    assert len(successes) >= 1, f"no racer succeeded: {results}"
    for _, _, code in errors:
        assert code == "ConflictException", f"unexpected error code under contention: {code!r}"

    final = _poll_until(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ],
        lambda a: a["Status"] == "COMPLETE",
        timeout_s=600,
        interval_s=2,
    )
    assert final["Priority"] in racer_priorities, (
        f"final priority {final['Priority']} was not one of the attempted values "
        f"{racer_priorities} -- update was corrupted under contention"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _teardown_deadline(teardown) -> float:
    """The run's one teardown deadline: 840 s from the first delete, inside the suite's 900 s
    cleanup budget."""
    if "deadline" not in teardown:
        teardown["deadline"] = time.monotonic() + 840.0
    return teardown["deadline"]


def _retry_busy(call, busy_code, gone_code, teardown) -> None:
    """Call ``call``, retrying every 2 s while it answers ``busy_code``; ``gone_code`` is done."""
    deadline = _teardown_deadline(teardown)
    while True:
        try:
            call()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == gone_code:
                return
            if code != busy_code or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_vpc(ctx, ec2, teardown):
    name = ctx.unique_name("sim2real-r53r-vpc-")
    resp = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    # DeleteVpc answers DependencyViolation until the association's resolver attachment is gone.
    ctx.on_cleanup(lambda: _retry_busy(
        lambda: ec2.delete_vpc(VpcId=vpc_id), "DependencyViolation", "InvalidVpcID.NotFound", teardown))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id


def _create_rule_group(ctx, r53r, teardown):
    group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crg-"),
        Name=ctx.unique_name("sim2real-fwgroup-")[:64],
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_group(r53r, group_id, teardown))
    return group_id


def _safe_delete_group(r53r, group_id, teardown):
    """Delete the rule group, retrying ConflictException ("[RSLVR-02101] The DNS Firewall rule
    group is associated to a VPC ...") while the disassociation finishes."""
    _retry_busy(lambda: r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id),
                "ConflictException", "ResourceNotFoundException", teardown)


def _safe_disassociate(r53r, assoc_id, teardown):
    """Disassociate, retrying ConflictException while an update is still applying, then wait until
    GetFirewallRuleGroupAssociation answers ResourceNotFoundException."""
    _retry_busy(lambda: r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id),
                "ConflictException", "ResourceNotFoundException", teardown)
    deadline = _teardown_deadline(teardown)
    while True:
        try:
            r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"association {assoc_id} still present at the teardown deadline")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
