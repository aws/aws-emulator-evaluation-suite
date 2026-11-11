"""associate-firewall-rule-group-priority-below-floor-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-firewall-rule-group-priority-below-floor-rejected"
GROUP = 'overly-permissive'
SERVICES = ['route53resolver']

TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


# ===== helpers (self-contained) =====
# A VPC with no subnets, NAT gateway or endpoint is free.
def _err_code(fn):
    """Call fn(); return botocore Error.Code if a ClientError is raised.

    An unexpected SUCCESS raises, because an emulator ACCEPTING an association real AWS
    refuses is the strongest signal available and must not be reduced to an error-code
    mismatch via a falsy sentinel.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), _without_trace_id(error.get("Message"))
    raise AssertionError(
        f"real AWS rejects Priority=50 (below the 100 floor), but the call SUCCEEDED and "
        f"returned {result!r}"
    )


def _poll(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_when_possible(fn, *, timeout_s=180.0, interval_s=5.0, **kwargs):
    """Retry a delete until it succeeds or the resource is already gone.

    Registered as teardown for a resource whose delete is refused while a dependent
    still exists. Raises on deadline miss so a leak is a loud failure rather than a
    silent hand-off to an out-of-band cleanup.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            fn(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if "NotFound" in code or code == "ResourceNotFoundException":
                return
            last = code
        time.sleep(interval_s)
    raise AssertionError(f"teardown {fn.__name__}({kwargs}) never succeeded; last error {last}")


def _create_test_vpc(ctx):
    """Create a tagged, isolated, free VPC and register its teardown. Returns vpc_id."""
    ec2 = ctx.client("ec2")
    try:
        vpc_id = ec2.create_vpc(
            CidrBlock="10.91.0.0/16",
            TagSpecifications=[
                {
                    "ResourceType": "vpc",
                    "Tags": TAGS_KV
                    + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
                }
            ],
        )["Vpc"]["VpcId"]
    except ClientError as exc:
        raise AssertionError(
            f"cannot create an isolated VPC in {ctx.region}: "
            f"{exc.response.get('Error', {}).get('Code')}"
        ) from None
    ctx.on_cleanup(lambda v=vpc_id: _delete_when_possible(ec2.delete_vpc, VpcId=v))
    return vpc_id


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A firewall-rule-group VPC association Priority below the 100 floor is refused: the model has
    no @range on Priority, so only the server enforces it, and accepting 50 would silently reorder
    the DNS Firewall evaluation chain.
    """
    r53 = ctx.client("route53resolver")
    vpc_id = _create_test_vpc(ctx)

    group_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-frg-"),
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(
        lambda x=group_id: _delete_when_possible(
            r53.delete_firewall_rule_group, FirewallRuleGroupId=x
        )
    )

    # CONTROL: an in-range priority is accepted.
    good_name = ctx.unique_name("sim2real-behav-frga-ok-")
    assoc = r53.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        FirewallRuleGroupId=group_id,
        VpcId=vpc_id,
        Priority=101,
        Name=good_name,
    )["FirewallRuleGroupAssociation"]
    assoc_id = assoc["Id"]
    ctx.on_cleanup(
        lambda x=assoc_id: _delete_when_possible(
            r53.disassociate_firewall_rule_group, FirewallRuleGroupAssociationId=x
        )
    )
    assert assoc["Priority"] == 101, assoc
    assert assoc["VpcId"] == vpc_id, assoc

    # BREAK EXACTLY ONE THING: identical request, Priority=50 (below the 100 floor).
    bad_name = ctx.unique_name("sim2real-behav-frga-bad-")
    code, message = _err_code(
        lambda: r53.associate_firewall_rule_group(
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
            FirewallRuleGroupId=group_id,
            VpcId=vpc_id,
            Priority=50,
            Name=bad_name,
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for association Priority=50 (floor is 100), got {code}"
    )
    expected = (
        '[RSLVR-02017] The priority value you provided is reserved. Provide a number between '
        '"100" and "9900".'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # EFFECT ABSENT: no second association was created.
    assocs = r53.list_firewall_rule_group_associations(VpcId=vpc_id)[
        "FirewallRuleGroupAssociations"
    ]
    names = sorted(a["Name"] for a in assocs)
    assert bad_name not in names, (
        f"a rejected out-of-range association must not be stored; VPC holds {names}"
    )
    assert names == [good_name], f"VPC must hold exactly the control association, got {names}"

    # CONTROL STILL WORKS: the surviving association keeps its priority and settles.
    settled = _poll(
        lambda: r53.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id
        )["FirewallRuleGroupAssociation"],
        lambda a: a["Status"] == "COMPLETE",
        timeout_s=120,
        interval_s=5,
        description="control firewall rule group association reaches COMPLETE",
    )
    assert settled["Priority"] == 101, settled
    assert settled["FirewallRuleGroupId"] == group_id, settled


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
