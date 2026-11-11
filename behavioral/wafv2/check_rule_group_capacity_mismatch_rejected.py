"""rule-group-capacity-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rule-group-capacity-mismatch-rejected"
GROUP = 'rulegroup'
SERVICES = ['wafv2']

# REGIONAL is usable from any endpoint/region; CLOUDFRONT scope requires us-east-1.
SCOPE = "REGIONAL"


def _raises_on_success(fn):
    """Call fn(); return (code, message) if a ClientError is raised. An unexpected success
    raises, so acceptance never reads as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


def _expensive_rule(name, priority=0, n_transforms=5):
    """A ByteMatch rule with several non-NONE text transformations.

    Each non-NONE text transformation adds WCUs, so this is a cheap way to build
    rule sets whose aggregate capacity is comfortably above 1 WCU.
    """
    transform_types = [
        "LOWERCASE",
        "URL_DECODE",
        "HTML_ENTITY_DECODE",
        "COMPRESS_WHITE_SPACE",
        "NORMALIZE_PATH",
        "CMD_LINE",
        "BASE64_DECODE",
        "CSS_DECODE",
    ][:n_transforms]
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {
            "ByteMatchStatement": {
                "SearchString": b"attack",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [
                    {"Priority": i, "Type": t} for i, t in enumerate(transform_types)
                ],
                "PositionalConstraint": "CONTAINS",
            }
        },
        "Action": {"Block": {}},
        "VisibilityConfig": _visibility_config(name),
    }


def _find_by_name(w, name, scope=SCOPE):
    """An independent read: look the rule group up through ListRuleGroups, a different
    operation than CreateRuleGroup."""
    for summary in w.list_rule_groups(Scope=scope, Limit=100).get("RuleGroups", []):
        if summary["Name"] == name:
            return summary
    return None


def _delete_rule_group_by_name(w, name, scope=SCOPE):
    """Teardown for a rule group referenced only by name: resolve its Id and current
    LockToken through ListRuleGroups, then delete. A no-op if it never existed or is gone."""
    try:
        summary = _find_by_name(w, name, scope)
        if summary is None:
            return
        got = w.get_rule_group(Name=name, Scope=scope, Id=summary["Id"])
        w.delete_rule_group(
            Name=name, Scope=scope, Id=summary["Id"], LockToken=got["LockToken"]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRuleGroup with Capacity below the Rules' measured WCU cost is rejected and nothing
    is created, while the identical Rules at their measured Capacity succeed (positive control)."""
    w = ctx.client("wafv2")
    rule = _expensive_rule("costly-rule", priority=0, n_transforms=5)
    measured = w.check_capacity(Scope=SCOPE, Rules=[rule])["Capacity"]
    assert measured > 1, f"expected the crafted rule to cost >1 WCU, got {measured}"

    # Positive control: the identical Rules, declared at their own measured Capacity.
    ok_name = ctx.unique_name("sim2real-behav-waf-rg-okcap-")
    ctx.on_cleanup(lambda: _delete_rule_group_by_name(w, ok_name))
    w.create_rule_group(
        Name=ok_name, Scope=SCOPE, Capacity=measured, Rules=[rule],
        VisibilityConfig=_visibility_config(ok_name),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    control = _find_by_name(w, ok_name)
    assert control is not None, (
        f"the positive control {ok_name!r} did not appear in ListRuleGroups"
    )
    # RuleGroupSummary (ListRuleGroups) carries no Capacity; GetRuleGroup does.
    control_full = w.get_rule_group(Name=ok_name, Scope=SCOPE, Id=control["Id"])["RuleGroup"]
    assert control_full["Capacity"] == measured, (
        f"the positive control's stored Capacity was {control_full['Capacity']}, "
        f"expected {measured}"
    )

    bad_name = ctx.unique_name("sim2real-behav-waf-rg-badcap-")
    # Registered up front so an unexpectedly-accepted CreateRuleGroup cannot leak.
    ctx.on_cleanup(lambda: _delete_rule_group_by_name(w, bad_name))
    code, message = _raises_on_success(
        lambda: w.create_rule_group(
            Name=bad_name,
            Scope=SCOPE,
            Capacity=measured - 1,
            Rules=[rule],
            VisibilityConfig=_visibility_config(bad_name),
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
    )
    assert code == "WAFInvalidParameterException", code
    # The refusal echoes the measured cost of Rules, not the under-declared Capacity.
    assert message == (
        "Error reason: You exceeded the capacity limit for a rule group or web ACL., "
        f"field: RULE_GROUP, parameter: {measured}"
    ), message

    # Effect absent: an independent read (ListRuleGroups, not the rejected CreateRuleGroup's
    # own response) confirms the under-capacity rule group was never created.
    assert _find_by_name(w, bad_name) is None, (
        f"CreateRuleGroup for {bad_name!r} was rejected, but it is visible in ListRuleGroups"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
