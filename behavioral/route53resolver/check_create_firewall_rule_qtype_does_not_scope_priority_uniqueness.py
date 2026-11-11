"""create-firewall-rule-qtype-does-not-scope-priority-uniqueness."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-firewall-rule-qtype-does-not-scope-priority-uniqueness"
GROUP = 'firewall-rule-group'
SERVICES = ['route53resolver']


def _err_code(fn):
    """Call fn(); return botocore Error.Code of the ClientError it raises. An unexpected success
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), _without_trace_id(error.get("Message"))
    raise AssertionError(
        f"expected a ClientError from the duplicate-priority create, but it SUCCEEDED "
        f"and returned {result!r}"
    )


def _delete_when_possible(fn, *, timeout_s=120.0, interval_s=5.0, **kwargs):
    """Retry a delete until it succeeds or the resource is gone; raise on deadline miss."""
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


def _all_rules(r53, group_id):
    """Return every rule in the group, following pagination."""
    out = []
    token = None
    while True:
        kwargs = {"FirewallRuleGroupId": group_id, "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = r53.list_firewall_rules(**kwargs)
        out.extend(page.get("FirewallRules", []))
        token = page.get("NextToken")
        if not token:
            return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The same domain list may be ruled twice with different Qtypes, but Priority stays unique
    across the whole group regardless of Qtype, since priority is the group's single evaluation
    order; freeing the collided priority lets the identical create succeed.
    """
    r53 = ctx.client("route53resolver")

    group_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-frg-"),
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(
        lambda x=group_id: _delete_when_possible(
            r53.delete_firewall_rule_group, FirewallRuleGroupId=x
        )
    )

    dl_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-fdl-"),
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(
        lambda x=dl_id: _delete_when_possible(
            r53.delete_firewall_domain_list, FirewallDomainListId=x
        )
    )

    def make_rule(qtype, priority, label):
        name = ctx.unique_name(f"sim2real-behav-fr-{label}-")
        rule = r53.create_firewall_rule(
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
            FirewallRuleGroupId=group_id,
            FirewallDomainListId=dl_id,
            Priority=priority,
            Action="BLOCK",
            BlockResponse="NXDOMAIN",
            Qtype=qtype,
            Name=name,
        )["FirewallRule"]
        ctx.on_cleanup(
            lambda g=group_id, d=dl_id, q=qtype: _delete_when_possible(
                r53.delete_firewall_rule,
                FirewallRuleGroupId=g,
                FirewallDomainListId=d,
                Qtype=q,
            )
        )
        return name, rule

    name_a, rule_a = make_rule("A", 710, "a")
    assert rule_a["Qtype"] == "A", (
        f"the rule must project the Qtype it was created with, got {rule_a.get('Qtype')!r}"
    )
    assert rule_a["Priority"] == 710, rule_a

    # Legal because a rule's identity in a group is (FirewallDomainListId, Qtype).
    name_aaaa, rule_aaaa = make_rule("AAAA", 720, "aaaa")
    assert rule_aaaa["Qtype"] == "AAAA", rule_aaaa
    assert rule_aaaa["FirewallDomainListId"] == dl_id, (
        "the same domain list must be usable twice in one group when Qtype differs; got "
        f"{rule_aaaa!r}"
    )

    # A fresh Qtype keeps the identity unique, so only the reused priority collides.
    bad_name = ctx.unique_name("sim2real-behav-fr-txt-")

    def duplicate_priority():
        resp = r53.create_firewall_rule(
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
            FirewallRuleGroupId=group_id,
            FirewallDomainListId=dl_id,
            Priority=710,
            Action="BLOCK",
            BlockResponse="NXDOMAIN",
            Qtype="TXT",
            Name=bad_name,
        )
        # Registered before _err_code can raise on unexpected success, so a wrongly
        # created rule is still cleaned up.
        ctx.on_cleanup(
            lambda g=group_id, d=dl_id: _delete_when_possible(
                r53.delete_firewall_rule,
                FirewallRuleGroupId=g,
                FirewallDomainListId=d,
                Qtype="TXT",
            )
        )
        return resp

    code, message = _err_code(duplicate_priority)
    assert code == "ValidationException", (
        "Priority uniqueness is group-wide, not Qtype-scoped: expected "
        f"ValidationException for a second rule at Priority=710, got {code}"
    )
    expected = (
        "[RSLVR-02203] The DNS Firewall rule group already has a rule associated with the same "
        f'priority: "{group_id}". Provide another priority.'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    rules = _all_rules(r53, group_id)
    names = sorted(r["Name"] for r in rules)
    assert names == sorted([name_a, name_aaaa]), (
        f"group must hold exactly the two legal rules, got {names}"
    )
    assert sorted(r["Qtype"] for r in rules) == ["A", "AAAA"], (
        f"group Qtypes must be exactly A and AAAA, got {[r.get('Qtype') for r in rules]}"
    )

    by_qtype = {r["Qtype"]: r for r in rules}
    assert by_qtype["A"]["Priority"] == 710, by_qtype["A"]
    assert by_qtype["AAAA"]["Priority"] == 720, by_qtype["AAAA"]
    priorities = [r["Priority"] for r in rules]
    assert len(set(priorities)) == len(priorities), (
        f"priorities must be unique within a rule group, got {priorities}"
    )

    # The identical create succeeding once the priority is freed shows the rejection was
    # about the collision alone, not the TXT rule or a group-wide lockout.
    r53.delete_firewall_rule(
        FirewallRuleGroupId=group_id, FirewallDomainListId=dl_id, Qtype="A"
    )
    name_txt, rule_txt = make_rule("TXT", 710, "txt-restored")
    assert rule_txt["Priority"] == 710, rule_txt
    assert rule_txt["Qtype"] == "TXT", rule_txt

    rules_after = _all_rules(r53, group_id)
    assert sorted(r["Qtype"] for r in rules_after) == ["AAAA", "TXT"], (
        "once priority 710 is freed, the identical call must succeed and the group must "
        f"hold exactly AAAA and TXT, got {[r.get('Qtype') for r in rules_after]}"
    )


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
