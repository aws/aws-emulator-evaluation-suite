"""create-firewall-rule-invalid-group-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-firewall-rule-invalid-group-not-found"
GROUP = 'firewall-rule-group'
SERVICES = ['route53resolver']

def _err_code(fn):
    """Call fn(); return botocore Error.Code of the ClientError it raises. A call that
    succeeds fails the check: a target accepting what AWS refuses must not read as an
    error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), _without_trace_id(error.get("Message"))
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFirewallRule against a nonexistent FirewallRuleGroupId raises ResourceNotFoundException
    and leaves no group under that id; the identical call against a real group succeeds and is
    visible via an independent read."""
    r53 = ctx.client("route53resolver")
    dl_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-fdl-")
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_id: r53.delete_firewall_domain_list(FirewallDomainListId=x))

    bogus_group = ctx.unique_name("sim2real-behav-rslvr-frg-doesnotexist-")
    code, message = _err_code(
        lambda: r53.create_firewall_rule(
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
            FirewallRuleGroupId=bogus_group,
            FirewallDomainListId=dl_id,
            Priority=1,
            Action="ALLOW",
            Name=ctx.unique_name("sim2real-behav-fr-"),
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f'[RSLVR-02025] Can\u2019t find the resource with ID "{bogus_group}".'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Independent read, different operation: the rejected create must not have vivified a
    # group under the bogus id either.
    get_code, get_message = _err_code(lambda: r53.get_firewall_rule_group(FirewallRuleGroupId=bogus_group))
    assert get_message == f'[RSLVR-02025] Can\u2019t find the resource with ID "{bogus_group}".', (
        f"expected GetFirewallRuleGroup's not-found message for {bogus_group}, got {get_message!r}"
    )
    assert get_code == "ResourceNotFoundException", (
        f"bogus group {bogus_group} should still be unknown to GetFirewallRuleGroup, got {get_code}"
    )

    # Positive control: the identical call against a real group succeeds, proving the rejection
    # above is specific to the nonexistent group rather than a blanket CreateFirewallRule failure.
    group_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-frg-")
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=group_id: r53.delete_firewall_rule_group(FirewallRuleGroupId=x))
    rule_name = ctx.unique_name("sim2real-behav-fr-")
    rule = r53.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        FirewallRuleGroupId=group_id,
        FirewallDomainListId=dl_id,
        Priority=1,
        Action="ALLOW",
        Name=rule_name,
    )["FirewallRule"]
    ctx.on_cleanup(lambda g=group_id, d=dl_id: r53.delete_firewall_rule(FirewallRuleGroupId=g, FirewallDomainListId=d))
    assert rule["FirewallRuleGroupId"] == group_id, f"expected rule under {group_id}, got {rule}"

    found = next(
        (
            r
            for r in r53.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]
            if r["Name"] == rule_name
        ),
        None,
    )
    assert found is not None, f"created rule {rule_name!r} not visible via ListFirewallRules on {group_id}"
    assert found["FirewallDomainListId"] == dl_id, f"expected FirewallDomainListId {dl_id}, got {found}"


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
