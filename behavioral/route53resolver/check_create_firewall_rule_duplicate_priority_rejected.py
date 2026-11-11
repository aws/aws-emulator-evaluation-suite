"""create-firewall-rule-duplicate-priority-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-firewall-rule-duplicate-priority-rejected"
GROUP = 'overly-permissive'
SERVICES = ['route53resolver']

TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


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


def _delete_rule_if_present(r53, group_id, dl_id):
    """Delete a firewall rule this check created; tolerate it already being gone."""
    try:
        r53.delete_firewall_rule(FirewallRuleGroupId=group_id, FirewallDomainListId=dl_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _rule_names(r53, group_id):
    """Return the Name of every rule currently in the group, following pagination."""
    out = []
    token = None
    while True:
        kwargs = {"FirewallRuleGroupId": group_id, "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = r53.list_firewall_rules(**kwargs)
        out.extend(r["Name"] for r in page.get("FirewallRules", []))
        token = page.get("NextToken")
        if not token:
            return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFirewallRule with a Priority another rule in the group holds is refused with
    ValidationException and adds no rule; once that rule is deleted the same request succeeds at the
    same Priority.
    """
    r53 = ctx.client("route53resolver")
    group_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-frg-"),
        Tags=TAGS_KV,
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=group_id: r53.delete_firewall_rule_group(FirewallRuleGroupId=x))
    dl_id_a = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-fdl-"),
        Tags=TAGS_KV,
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_id_a: r53.delete_firewall_domain_list(FirewallDomainListId=x))
    dl_id_b = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-fdl-"),
        Tags=TAGS_KV,
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_id_b: r53.delete_firewall_domain_list(FirewallDomainListId=x))

    # POSITIVE CONTROL: a rule at Priority=200 is accepted.
    name_a = ctx.unique_name("sim2real-behav-fr-")
    rule_a = r53.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        FirewallRuleGroupId=group_id,
        FirewallDomainListId=dl_id_a,
        Priority=200,
        Action="ALLOW",
        Name=name_a,
    )["FirewallRule"]
    ctx.on_cleanup(lambda g=group_id, d=dl_id_a: _delete_rule_if_present(r53, g, d))
    assert rule_a["Priority"] == 200, rule_a

    # BREAK EXACTLY ONE THING: a second rule, different domain list, same Priority.
    name_b = ctx.unique_name("sim2real-behav-fr-")

    def _create_b():
        return r53.create_firewall_rule(
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
            FirewallRuleGroupId=group_id,
            FirewallDomainListId=dl_id_b,
            Priority=200,
            Action="ALLOW",
            Name=name_b,
        )

    code, message = _err_code(_create_b)
    assert code == "ValidationException", f"expected ValidationException for duplicate Priority=200, got {code}"
    expected = (
        "[RSLVR-02203] The DNS Firewall rule group already has a rule associated with the same "
        f'priority: "{group_id}". Provide another priority.'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # EFFECT ABSENT: an independent read shows only the surviving rule.
    names = _rule_names(r53, group_id)
    assert names == [name_a], f"expected only {name_a!r} in the group after the rejection, got {names}"

    # RESTORE: remove the rule occupying Priority=200, then retry the IDENTICAL request.
    _delete_rule_if_present(r53, group_id, dl_id_a)
    rule_b = _create_b()["FirewallRule"]
    ctx.on_cleanup(lambda g=group_id, d=dl_id_b: _delete_rule_if_present(r53, g, d))
    assert rule_b["Priority"] == 200, rule_b
    assert rule_b["FirewallDomainListId"] == dl_id_b, rule_b

    names_after = _rule_names(r53, group_id)
    assert names_after == [name_b], f"expected only {name_b!r} in the group after the restore, got {names_after}"


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
