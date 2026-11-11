"""batch-update-and-delete-firewall-rule."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-update-and-delete-firewall-rule"
GROUP = 'firewall-rule-batch'
SERVICES = ['route53resolver']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchUpdateFirewallRule / BatchDeleteFirewallRule mutate the rules they name."""
    r53r = ctx.client("route53resolver")
    group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=_creator_request_id(ctx),
        Name=ctx.unique_name("sim2real-behav-frg-"),
        Tags=[{"Key": "env", "Value": "behavioral-test"}],
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda: _swallow(lambda: r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id)))

    list_ids = []
    for _ in range(2):
        lid = r53r.create_firewall_domain_list(
            CreatorRequestId=_creator_request_id(ctx),
            Name=ctx.unique_name("sim2real-behav-fdl-"),
            Tags=[{"Key": "env", "Value": "behavioral-test"}],
        )["FirewallDomainList"]["Id"]
        ctx.on_cleanup(lambda i=lid: _swallow(lambda: r53r.delete_firewall_domain_list(FirewallDomainListId=i)))
        list_ids.append(lid)

    for i, lid in enumerate(list_ids):
        r53r.create_firewall_rule(
            CreatorRequestId=_creator_request_id(ctx),
            FirewallRuleGroupId=group_id,
            FirewallDomainListId=lid,
            Priority=300 + i,
            Action="ALLOW",
            Name=ctx.unique_name(f"sim2real-behav-frule-{i}-"),
        )
        # A rule holds both its group and its domain list, so it must go first.
        ctx.on_cleanup(
            lambda g=group_id, i=lid: _swallow(
                lambda: r53r.delete_firewall_rule(
                    FirewallRuleGroupId=g, FirewallDomainListId=i
                )
            )
        )

    update_resp = r53r.batch_update_firewall_rule(
        UpdateFirewallRuleEntries=[
            {
                "FirewallRuleGroupId": group_id,
                "FirewallDomainListId": lid,
                "Action": "BLOCK",
                "BlockResponse": "NODATA",
            }
            for lid in list_ids
        ]
    )
    assert not update_resp.get("UpdateErrors"), update_resp["UpdateErrors"]
    assert len(update_resp["UpdatedFirewallRules"]) == 2, update_resp
    assert all(r["Action"] == "BLOCK" for r in update_resp["UpdatedFirewallRules"]), update_resp

    rules = r53r.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]
    by_list = {r["FirewallDomainListId"]: r for r in rules}
    for lid in list_ids:
        assert by_list[lid]["Action"] == "BLOCK", by_list[lid]
        assert by_list[lid]["BlockResponse"] == "NODATA", by_list[lid]

    delete_resp = r53r.batch_delete_firewall_rule(
        DeleteFirewallRuleEntries=[
            {"FirewallRuleGroupId": group_id, "FirewallDomainListId": lid} for lid in list_ids
        ]
    )
    assert not delete_resp.get("DeleteErrors"), delete_resp["DeleteErrors"]
    assert len(delete_resp["DeletedFirewallRules"]) == 2, delete_resp

    remaining = r53r.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]
    assert remaining == [], remaining

    redelete_resp = r53r.batch_delete_firewall_rule(
        DeleteFirewallRuleEntries=[
            {"FirewallRuleGroupId": group_id, "FirewallDomainListId": lid} for lid in list_ids
        ]
    )
    assert len(redelete_resp.get("DeleteErrors", [])) == 2, (
        f"expected both already-deleted rules to error on re-delete, got {redelete_resp}"
    )
    assert not redelete_resp.get("DeletedFirewallRules"), redelete_resp


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _creator_request_id(ctx) -> str:
    """A fresh CreatorRequestId for idempotency-token style params."""
    return ctx.unique_name("sim2real-behav-crid-")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
