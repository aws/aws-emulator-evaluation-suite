"""concurrent-associate-firewall-rule-group-priority-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-associate-firewall-rule-group-priority-conflict"
GROUP = "concurrency"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent AssociateFirewallRuleGroup calls for the same VPC and Priority yield exactly
    one association; the other is refused with ValidationException ("[RSLVR-02303] This priority is
    the same with another association ...") naming the winner, which is the only one listed.
    """
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    r53r = ctx.client("route53resolver")

    vpc_id = _create_vpc(ctx, teardown_deadline)
    group_a = _create_firewall_rule_group(ctx, teardown_deadline)
    group_b = _create_firewall_rule_group(ctx, teardown_deadline)
    priority = 733

    def _associate(group_id: str, tag: str):
        try:
            resp = r53r.associate_firewall_rule_group(
                CreatorRequestId=ctx.unique_name(f"sim2real-behav-creq-{tag}-"),
                FirewallRuleGroupId=group_id,
                VpcId=vpc_id,
                Priority=priority,
                Name=ctx.unique_name(f"sim2real-behav-assoc-{tag}-"),
            )
            return ("ok", resp["FirewallRuleGroupAssociation"])
        except ClientError as err:
            return ("error", (err.response["Error"]["Code"], err.response["Error"].get("Message", "")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_associate, group_a, "a")
        fut_b = pool.submit(_associate, group_b, "b")
        result_a = fut_a.result()
        result_b = fut_b.result()

    outcomes = [result_a, result_b]
    successes = [r for kind, r in outcomes if kind == "ok"]
    errors = [r for kind, r in outcomes if kind == "error"]

    assert len(successes) == 1, f"expected exactly 1 successful association, got {outcomes}"
    assert len(errors) == 1, f"expected exactly 1 rejected association, got {outcomes}"
    # Route 53 Resolver answers the same-priority race with ValidationException
    # ("This priority is the same with another association"), not ConflictException.
    code, message = errors[0]
    assert code == "ValidationException", f"expected ValidationException, got {errors[0]}"

    winner_assoc_id = successes[0]["Id"]
    # The message ends in a per-request trace id, so everything before it is asserted.
    expected_prefix = (
        f'[RSLVR-02303] This priority is the same with another association: "{winner_assoc_id}" . '
        'Try again with another priority number. Trace Id: "'
    )
    assert message.startswith(expected_prefix), f"expected message starting {expected_prefix!r}, got {message!r}"

    ctx.on_cleanup(lambda: _teardown(
        lambda: r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=winner_assoc_id),
        teardown_deadline,
        retry=("ConflictException",), gone=("ResourceNotFoundException",),
    ))

    live = r53r.list_firewall_rule_group_associations(VpcId=vpc_id, Priority=priority)[
        "FirewallRuleGroupAssociations"
    ]
    assert len(live) == 1, f"expected exactly 1 live association at priority {priority}, got {len(live)}"
    assert live[0]["Id"] == winner_assoc_id, (
        f"the live association at priority {priority} is {live[0]['Id']!r}, "
        f"but the racer that won the create call was {winner_assoc_id!r}"
    )


# budget.cleanup_timeout for behavioral/route53resolver, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _teardown(fn, teardown_deadline, *, retry, gone) -> None:
    """Teardown: done when fn succeeds or answers a `gone` code; retry the `retry` (in-use)
    refusals every 2 s to the shared cleanup deadline, and raise everything else."""
    # A margin inside the budget, so a teardown raises its own error before the runner gives up.
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone:
                return
            if code not in retry or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_vpc(ctx, teardown_deadline) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    vpc = ec2.create_vpc(
        CidrBlock="10.83.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _teardown(
        lambda: ec2.delete_vpc(VpcId=vpc_id), teardown_deadline,
        retry=("DependencyViolation",), gone=("InvalidVpcID.NotFound",),
    ))
    return vpc_id


def _create_firewall_rule_group(ctx, teardown_deadline) -> str:
    r53r = ctx.client("route53resolver")
    group = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
        Name=ctx.unique_name("sim2real-behav-frg-"),
    )["FirewallRuleGroup"]
    group_id = group["Id"]
    # A rule group is refused (ConflictException) until its asynchronous disassociation completes.
    ctx.on_cleanup(lambda: _teardown(
        lambda: r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id),
        teardown_deadline,
        retry=("ConflictException",), gone=("ResourceNotFoundException",),
    ))
    return group_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
