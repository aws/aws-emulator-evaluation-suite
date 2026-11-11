"""ip-group-lifecycle-rules-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ip-group-lifecycle-rules-round-trip"
GROUP = "state"
SERVICES = ["workspaces"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIpGroup + AuthorizeIpRules/RevokeIpRules are additive; UpdateRulesOfIpGroup replaces
    the whole rule set. Verifies the IP-group rule data plane end-to-end via DescribeIpGroups."""
    ws = ctx.client("workspaces")
    name = ctx.unique_name("sim2real-wsipg-")

    try:
        created = ws.create_ip_group(
            GroupName=name,
            GroupDesc="sim2real lifecycle test",
            UserRules=[{"ipRule": "10.0.0.0/32"}],
        )
    except Exception as e:
        raise AssertionError(f"DEBUG create_ip_group failed: {type(e).__name__}: {e}") from e
    group_id = created["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_ip_group(ctx, group_id))

    rules = _describe_rules(ctx, group_id)
    assert rules == {"10.0.0.0/32"}, f"expected initial rule only, got {rules}"

    # Additive: AuthorizeIpRules adds without removing the existing rule.
    try:
        ws.authorize_ip_rules(GroupId=group_id, UserRules=[{"ipRule": "10.0.0.1/32"}])
    except Exception as e:
        raise AssertionError(f"DEBUG authorize: {str(e)[-160:]}") from e
    rules = _describe_rules(ctx, group_id)
    assert rules == {"10.0.0.0/32", "10.0.0.1/32"}, f"authorize did not add additively: {rules}"

    # Additive removal: RevokeIpRules removes exactly the rule specified, leaves the rest.
    # Unlike Authorize/Update, RevokeIpRules' UserRules is a list of bare IP-rule strings, not
    # IpRuleItem objects.
    try:
        ws.revoke_ip_rules(GroupId=group_id, UserRules=["10.0.0.0/32"])
    except Exception as e:
        raise AssertionError(f"DEBUG revoke: {str(e)[-160:]}") from e
    rules = _describe_rules(ctx, group_id)
    assert rules == {"10.0.0.1/32"}, f"revoke did not remove exactly the targeted rule: {rules}"

    # Replacing: UpdateRulesOfIpGroup replaces the ENTIRE rule set, not additive.
    try:
        ws.update_rules_of_ip_group(GroupId=group_id, UserRules=[{"ipRule": "10.0.0.2/32"}])
    except Exception as e:
        raise AssertionError(f"DEBUG update: {str(e)[-160:]}") from e
    rules = _describe_rules(ctx, group_id)
    assert rules == {"10.0.0.2/32"}, f"UpdateRulesOfIpGroup did not fully replace the set: {rules}"


    ws.delete_ip_group(GroupId=group_id)
    remaining = ws.describe_ip_groups(GroupIds=[group_id])["Result"]
    assert remaining == [], f"group still present after delete: {remaining}"


def _describe_rules(ctx, group_id: str) -> set:
    ws = ctx.client("workspaces")
    result = ws.describe_ip_groups(GroupIds=[group_id])["Result"]
    assert len(result) == 1, f"expected exactly one group, got {result}"
    return {r["ipRule"] for r in result[0]["userRules"]}


def _safe_delete_ip_group(ctx, group_id: str) -> None:
    from botocore.exceptions import ClientError

    ws = ctx.client("workspaces")
    try:
        ws.delete_ip_group(GroupId=group_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
