"""create-firewall-rule-override-without-block-override-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-firewall-rule-override-without-block-override-rejected"
GROUP = 'overly-permissive'
SERVICES = ['route53resolver']

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


# ===== helpers (self-contained) =====
def _err_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. A call that
    succeeds fails the check: a target accepting what AWS refuses must not read as an
    error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), _without_trace_id(err.get("Message", ""))
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


ERR_CODE_OVERRIDE = 'RSLVR-02013'
"""Resolver's own error code for a partially-specified OVERRIDE rule.

On AWS, omitting BlockOverrideDomain raises
ValidationException "[RSLVR-02013] You must specify an override DNS type, an override domain,
and an override Ttl when you are using OVERRIDE." -- the code is what pins the refusal to THIS
conditional requirement rather than to any other validation failure.
"""

CANONICAL_OVERRIDE_DOMAIN = 'override.example.com.'
"""BlockOverrideDomain is canonicalized to a lowercase FQDN with a trailing dot.

On AWS, 'override.example.com', 'override.example.com.' and
'OverRide.Example.COM' all come back as 'override.example.com.' -- so the round-trip is a DNS
canonicalization, not a verbatim echo, and it is idempotent (an already-rooted name does not
grow a second dot).
"""


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BlockResponse=OVERRIDE requires BlockOverrideDomain, DnsType and Ttl: a partially-specified
    OVERRIDE rule is refused and nothing is created, a conditional requirement the Smithy model
    cannot express.
    """
    r53 = ctx.client("route53resolver")

    group_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-frg-"),
        Tags=TAGS_KV,
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=group_id: r53.delete_firewall_rule_group(FirewallRuleGroupId=x))

    dl_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-fdl-"),
        Tags=TAGS_KV,
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_id: r53.delete_firewall_domain_list(FirewallDomainListId=x))

    # CONTROL: a fully-specified OVERRIDE rule is accepted and projects all three
    # override members back. This is the positive half the rejection is measured
    # against — without it a "reject everything" emulator would also pass.
    good_name = ctx.unique_name("sim2real-behav-fr-ok-")
    good = r53.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        FirewallRuleGroupId=group_id,
        FirewallDomainListId=dl_id,
        Priority=610,
        Action="BLOCK",
        BlockResponse="OVERRIDE",
        BlockOverrideDomain="override.example.com",
        BlockOverrideDnsType="CNAME",
        BlockOverrideTtl=60,
        Name=good_name,
    )["FirewallRule"]
    ctx.on_cleanup(
        lambda g=group_id, d=dl_id: r53.delete_firewall_rule(
            FirewallRuleGroupId=g, FirewallDomainListId=d
        )
    )
    assert good["BlockResponse"] == "OVERRIDE", good
    # Not a verbatim echo: the redirect target is a DNS name and Resolver roots it (see
    # CANONICAL_OVERRIDE_DOMAIN). An emulator that stores the string as given fails here.
    assert good["BlockOverrideDomain"] == CANONICAL_OVERRIDE_DOMAIN, good
    assert good["BlockOverrideDnsType"] == "CNAME", good
    assert good["BlockOverrideTtl"] == 60, good

    # ...and the canonicalization is idempotent: submitting the already-rooted form stores the
    # identical name rather than appending a second dot. This is what separates a real
    # canonicalizer from a blind `domain + "."`.
    dl_dotted = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-fdl-dot-"),
        Tags=TAGS_KV,
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_dotted: r53.delete_firewall_domain_list(FirewallDomainListId=x))
    dotted_name = ctx.unique_name("sim2real-behav-fr-dot-")
    dotted = r53.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        FirewallRuleGroupId=group_id,
        FirewallDomainListId=dl_dotted,
        Priority=615,
        Action="BLOCK",
        BlockResponse="OVERRIDE",
        BlockOverrideDomain=CANONICAL_OVERRIDE_DOMAIN,
        BlockOverrideDnsType="CNAME",
        BlockOverrideTtl=60,
        Name=dotted_name,
    )["FirewallRule"]
    ctx.on_cleanup(
        lambda g=group_id, d=dl_dotted: r53.delete_firewall_rule(
            FirewallRuleGroupId=g, FirewallDomainListId=d
        )
    )
    assert dotted["BlockOverrideDomain"] == CANONICAL_OVERRIDE_DOMAIN, dotted

    # BREAK EXACTLY ONE THING: same request, a second domain list, BlockOverrideDomain
    # omitted. Everything else — Action, BlockResponse, DnsType, Ttl — stays valid.
    dl2_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-fdl2-"),
        Tags=TAGS_KV,
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl2_id: r53.delete_firewall_domain_list(FirewallDomainListId=x))

    bad_name = ctx.unique_name("sim2real-behav-fr-bad-")
    code, message = _err_code(
        lambda: r53.create_firewall_rule(
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
            FirewallRuleGroupId=group_id,
            FirewallDomainListId=dl2_id,
            Priority=620,
            Action="BLOCK",
            BlockResponse="OVERRIDE",
            # BlockOverrideDomain deliberately omitted — the single broken thing.
            BlockOverrideDnsType="CNAME",
            BlockOverrideTtl=60,
            Name=bad_name,
        )
    )
    assert code == "ValidationException", (
        "expected ValidationException for BlockResponse=OVERRIDE without "
        f"BlockOverrideDomain, got {code} ({message!r})"
    )
    assert ERR_CODE_OVERRIDE in message, (
        f"expected Resolver's own {ERR_CODE_OVERRIDE} code for a partially-specified OVERRIDE "
        f"rule, got {message!r}"
    )
    assert "OVERRIDE" in message, (
        f"the refusal must name the BlockResponse value whose requirement was not met, got "
        f"{message!r}"
    )
    expected = (
        "[RSLVR-02013] You must specify an override DNS type, an override domain, and an "
        "override Ttl when you are using OVERRIDE."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # EFFECT ABSENT: the rejected rule must not exist, not even partially.
    rules = r53.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]
    names = sorted(r["Name"] for r in rules)
    assert bad_name not in names, (
        f"a rejected OVERRIDE rule must not be stored; group holds {names}"
    )
    assert names == sorted([good_name, dotted_name]), (
        f"group must hold exactly the two control rules, got {names}"
    )

    # CONTROL STILL WORKS: the surviving rule is unchanged by the failed attempt.
    still = next(r for r in rules if r["Name"] == good_name)
    assert still["BlockOverrideDomain"] == CANONICAL_OVERRIDE_DOMAIN, still
    assert still["Priority"] == 610, still


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
