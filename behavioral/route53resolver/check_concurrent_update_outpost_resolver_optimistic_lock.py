"""concurrent-update-outpost-resolver-optimistic-lock."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-outpost-resolver-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateFirewallRuleGroupAssociation calls each set a full (Priority, Name)
    pair; once COMPLETE again the association equals one racer's pair whole, never a mix.
    UpdateOutpostResolver is not called (it needs Outposts hardware)."""
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
    ctx.on_cleanup(lambda: r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id))
    _poll_until(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ],
        lambda a: a["Status"] == "COMPLETE",
        timeout_s=60.0,
    )

    writer_a = {"Priority": 4001, "Name": ctx.unique_name("sim2real-behav-writer-a-")}
    writer_b = {"Priority": 4002, "Name": ctx.unique_name("sim2real-behav-writer-b-")}

    def _write(payload):
        r53r.update_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id,
            Priority=payload["Priority"],
            Name=payload["Name"],
        )
        return payload

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_write, writer_a)
        fut_b = pool.submit(_write, writer_b)
        fut_a.result()
        fut_b.result()

    final = _poll_until(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ],
        lambda a: a["Status"] == "COMPLETE",
        timeout_s=60.0,
    )

    matches_a = final["Priority"] == writer_a["Priority"] and final["Name"] == writer_a["Name"]
    matches_b = final["Priority"] == writer_b["Priority"] and final["Name"] == writer_b["Name"]
    assert matches_a or matches_b, (
        f"final state {final['Priority']!r}/{final['Name']!r} matches neither writer "
        f"whole -- interleaved partial update: a={writer_a}, b={writer_b}"
    )
    assert not (matches_a and matches_b), "writers must not be identical payloads"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s, last={last}")


def _create_vpc(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    vpc = ec2.create_vpc(
        CidrBlock="10.84.0.0/16",
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
