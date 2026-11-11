"""alarm-mute-rule-put-get-list-delete-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "alarm-mute-rule-put-get-list-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAlarmMuteRule is retrievable via Get/List; DeleteAlarmMuteRule fully removes it."""
    cw = ctx.client("cloudwatch")
    put_rule = _require_op(cw, "PutAlarmMuteRule")
    get_rule = _require_op(cw, "GetAlarmMuteRule")
    list_rules = _require_op(cw, "ListAlarmMuteRules")
    delete_rule = _require_op(cw, "DeleteAlarmMuteRule")

    # A mute rule must target an existing alarm.
    alarm_name = ctx.unique_name("sim2real-mute-target-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="Sim2RealBehavioral/AlarmMuteRule",
        MetricName="PlaceholderMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _swallow(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))

    rule_name = ctx.unique_name("sim2real-mute-rule-")
    put_rule(
        Name=rule_name,
        Description="sim2real behavioral fidelity check",
        Rule={
            "Schedule": {
                "Expression": "cron(0 2 * * ?)",
                "Duration": "PT2H",
                "Timezone": "UTC",
            }
        },
        MuteTargets={"AlarmNames": [alarm_name]},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _swallow(lambda: delete_rule(AlarmMuteRuleName=rule_name)))

    got = get_rule(AlarmMuteRuleName=rule_name)
    assert got["Name"] == rule_name, f"expected Name={rule_name!r}, got {got.get('Name')!r}"
    # A freshly-created recurring rule (no ExpireDate) is SCHEDULED or, if the wall clock
    # happens to fall inside today's window, ACTIVE. EXPIRED applies only once a rule's
    # own ExpireDate has passed, which this rule has none of -- accepting it here would
    # accept every value the API models.
    assert got["Status"] in ("SCHEDULED", "ACTIVE"), f"expected SCHEDULED or ACTIVE, got {got['Status']!r}"
    # Confirmed against real CloudWatch: MuteType for a cron/rate schedule comes back as
    # the lowercase literal "recurring" (not the uppercase enum name the docs suggest).
    assert got["MuteType"].lower() == "recurring", f"expected recurring, got {got.get('MuteType')!r}"
    assert got["MuteTargets"]["AlarmNames"] == [alarm_name], (
        f"expected MuteTargets.AlarmNames=[{alarm_name!r}], got {got['MuteTargets'].get('AlarmNames')!r}"
    )
    rule_arn = got["AlarmMuteRuleArn"]

    def _listed() -> bool:
        next_token = None
        for _ in range(10):
            kwargs = {"NextToken": next_token} if next_token else {}
            page = list_rules(**kwargs)
            # The real ListAlarmMuteRules response wraps summaries under
            # "AlarmMuteRuleSummaries", and each summary identifies the rule only by its
            # "AlarmMuteRuleArn" - there is no Name/AlarmMuteRuleName field on the summary
            # at all. Match against the ARN returned by GetAlarmMuteRule instead of a name
            # field that doesn't exist on the list response.
            for value in page.values():
                if not isinstance(value, list):
                    continue
                for summary in value:
                    if not isinstance(summary, dict):
                        continue
                    if summary.get("AlarmMuteRuleArn") == rule_arn:
                        return True
            next_token = page.get("NextToken")
            if not next_token:
                break
        return False

    # ListAlarmMuteRules can lag briefly behind a just-created rule; poll instead of a
    # single pass to absorb that propagation delay.
    assert _poll_until(_listed, timeout_s=30, interval_s=3), (
        "created mute rule not found via ListAlarmMuteRules"
    )

    delete_rule(AlarmMuteRuleName=rule_name)

    def _gone() -> bool:
        from botocore.exceptions import ClientError

        try:
            get_rule(AlarmMuteRuleName=rule_name)
        except ClientError:
            return True
        return False

    assert _poll_until(_gone, timeout_s=30, interval_s=2), (
        "GetAlarmMuteRule still returns the rule after DeleteAlarmMuteRule"
    )
    code, message = _error(lambda: get_rule(AlarmMuteRuleName=rule_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = ""  # real AWS returns an empty message for this code
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The delete must also be visible at the list, not just at Get.
    assert not _listed(), f"deleted mute rule {rule_arn} still appears in ListAlarmMuteRules"


# ===== helpers =====
def _error(fn):
    """(code, message) of the ClientError fn() raises. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _swallow(fn) -> None:
    """Run a teardown delete; only an already-deleted resource is tolerated."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("ResourceNotFound", "ResourceNotFoundException"):
            raise


def _bound_method(client, operation_name):
    mapping = getattr(client.meta, "method_to_api_mapping", {})
    for method_name, op in mapping.items():
        if op == operation_name:
            return getattr(client, method_name)
    return None


def _require_op(client, operation_name):
    fn = _bound_method(client, operation_name)
    if fn is None:
        raise AssertionError(f"botocore in this environment has no operation {operation_name}")
    return fn


def _poll_until(probe, timeout_s: float = 30.0, interval_s: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if probe():
                return True
        except Exception:
            pass
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
