"""get-firewall-rule-group-policy-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-firewall-rule-group-policy-not-found"
GROUP = "error-semantics"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFirewallRuleGroupPolicy on a rule group with no policy returns the literal "{}", while a
    well-formed ARN of a nonexistent rule group is refused with ResourceNotFoundException
    ([RSLVR-02025]) naming the missing id.
    """
    r53r = ctx.client("route53resolver")
    sts = ctx.client("sts")
    self_account = sts.get_caller_identity()["Account"]

    group = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
        Name=ctx.unique_name("sim2real-behav-frg-"),
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["FirewallRuleGroup"]
    group_id = group["Id"]
    group_arn = group["Arn"]
    ctx.on_cleanup(lambda: r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id))

    resp = r53r.get_firewall_rule_group_policy(Arn=group_arn)
    assert resp["FirewallRuleGroupPolicy"] == "{}", (
        f"expected an empty-JSON-object policy for a rule group with no attached policy, "
        f"got {resp['FirewallRuleGroupPolicy']!r}"
    )

    # The not-found half, against a well-formed ARN in this same account and region whose rule
    # group id cannot exist -- so the difference from the call above is the RESOURCE, not the
    # shape of the request.
    missing_id = "rslvr-frg-0000000000000000"
    missing_arn = f"arn:aws:route53resolver:{ctx.region}:{self_account}:firewall-rule-group/{missing_id}"
    code, message = _error_code_and_message(
        lambda: r53r.get_firewall_rule_group_policy(Arn=missing_arn)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent rule group, got {code!r} ({message!r})"
    )
    # The message ends in a per-request trace id, so everything before it is asserted.
    expected_prefix = f'[RSLVR-02025] Can’t find the resource with ID "{missing_id}". Trace Id: "'
    assert message.startswith(expected_prefix), (
        f"expected message starting {expected_prefix!r}, got {message!r}"
    )

    # And the existing group is still readable afterwards: the not-found above did not disturb it,
    # so the two answers really are per-resource and not a stateful toggle.
    again = r53r.get_firewall_rule_group_policy(Arn=group_arn)
    assert again["FirewallRuleGroupPolicy"] == "{}", (
        f"expected the real rule group to still read back as \"{{}}\", got {again['FirewallRuleGroupPolicy']!r}"
    )


# ===== helpers (self-contained) =====
def _error_code_and_message(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not be reduced to a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

