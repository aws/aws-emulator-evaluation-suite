"""create-firewall-rule-block-without-response-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-firewall-rule-block-without-response-rejected"
GROUP = 'overly-permissive'
SERVICES = ['route53resolver']

ERR_CODE_BLOCK_RESPONSE = 'RSLVR-02016'
"""Resolver's own error code for a BLOCK rule missing BlockResponse.

On AWS, omitting BlockResponse on a BLOCK rule
raises ValidationException '[RSLVR-02016] Your block option BLOCK RESPONSE is not
valid.' -- the code is what pins the refusal to THIS conditional requirement rather
than to any other validation failure.
"""


def _err_code(fn):
    """Call fn(); return (Error.Code, Error.Message) if a ClientError is raised.

    An unexpected SUCCESS raises, because an emulator accepting input real AWS
    refuses is the strongest signal available and must not be reduced to a
    code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), _without_trace_id(err.get("Message", ""))
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFirewallRule with Action=BLOCK requires BlockResponse: a BLOCK rule that omits it is
    refused with ValidationException and nothing is created.
    """
    r53 = ctx.client("route53resolver")
    group_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-frg-")
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=group_id: r53.delete_firewall_rule_group(FirewallRuleGroupId=x))
    dl_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-fdl-")
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_id: r53.delete_firewall_domain_list(FirewallDomainListId=x))

    # CONTROL: a fully-specified BLOCK rule (BlockResponse=NODATA, no override fields
    # needed) is accepted. This is the positive half the rejection is measured
    # against -- without it, a target that refuses every CreateFirewallRule call
    # would also pass.
    good_name = ctx.unique_name("sim2real-behav-fr-ok-")
    good = r53.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        FirewallRuleGroupId=group_id,
        FirewallDomainListId=dl_id,
        Priority=690,
        Action="BLOCK",
        BlockResponse="NODATA",
        Name=good_name,
    )["FirewallRule"]
    ctx.on_cleanup(
        lambda g=group_id, d=dl_id: r53.delete_firewall_rule(FirewallRuleGroupId=g, FirewallDomainListId=d)
    )
    assert good["BlockResponse"] == "NODATA", good

    # BREAK EXACTLY ONE THING: same request, BlockResponse omitted.
    bad_name = ctx.unique_name("sim2real-behav-fr-bad-")
    code, message = _err_code(
        lambda: r53.create_firewall_rule(
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
            FirewallRuleGroupId=group_id,
            FirewallDomainListId=dl_id,
            Priority=700,
            Action="BLOCK",  # BlockResponse deliberately omitted
            Name=bad_name,
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for BLOCK without BlockResponse, got {code} ({message!r})"
    )
    assert ERR_CODE_BLOCK_RESPONSE in message, (
        f"expected Resolver's own {ERR_CODE_BLOCK_RESPONSE} code for a BLOCK rule missing "
        f"BlockResponse, got {message!r}"
    )
    assert "BLOCK RESPONSE" in message, (
        f"the refusal must name the missing block option, got {message!r}"
    )
    expected = "[RSLVR-02016] Your block option BLOCK RESPONSE is not valid."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # EFFECT ABSENT: the rejected rule must not exist, not even partially -- the
    # group must hold exactly the one control rule.
    rules = r53.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]
    names = sorted(r["Name"] for r in rules)
    assert bad_name not in names, f"a rejected BLOCK rule must not be stored; group holds {names}"
    assert names == [good_name], f"group must hold exactly the control rule, got {names}"

    # CONTROL STILL WORKS: the surviving rule is unchanged by the failed attempt.
    still = next(r for r in rules if r["Name"] == good_name)
    assert still["BlockResponse"] == "NODATA", still
    assert still["Priority"] == 690, still


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
