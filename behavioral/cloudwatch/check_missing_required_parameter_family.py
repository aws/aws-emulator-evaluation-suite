"""missing-required-parameter-family."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "missing-required-parameter-family"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

def _err(fn):
    """Return (Code, Message) of the ClientError fn() raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """Empty or invalid required content on Insight Rule ops returns InvalidParameterValue.

    StartMetricStreams/StopMetricStreams accept an empty Names list as a no-op success.
    """
    cw = ctx.client("cloudwatch")

    error = _err(lambda: cw.delete_insight_rules(RuleNames=[]))
    assert error == ("InvalidParameterValue", "EMPTY_RULE_NAMES: RuleNames cannot be an empty array."), f"DeleteInsightRules: RuleNames=[] gave {error!r}"

    error = _err(lambda: cw.disable_insight_rules(RuleNames=[]))
    assert error == ("InvalidParameterValue", "EMPTY_RULE_STATES: RuleStates cannot be an empty array."), f"DisableInsightRules: RuleNames=[] gave {error!r}"

    error = _err(lambda: cw.enable_insight_rules(RuleNames=[]))
    assert error == ("InvalidParameterValue", "EMPTY_RULE_STATES: RuleStates cannot be an empty array."), f"EnableInsightRules: RuleNames=[] gave {error!r}"

    # Unlike an empty RuleNames, an empty Names list is a no-op success here.
    resp = cw.start_metric_streams(Names=[])
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, f"StartMetricStreams: Names=[] gave {resp!r}"

    resp = cw.stop_metric_streams(Names=[])
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, f"StopMetricStreams: Names=[] gave {resp!r}"

    rule_name = ctx.unique_name("sim2real-behav-cwprobe-rule-")
    now = datetime.now(timezone.utc)
    error = _err(lambda: cw.get_insight_rule_report(
        RuleName=rule_name, StartTime=now - timedelta(minutes=10), EndTime=now, Period=7
    ))
    assert error == ("InvalidParameterValue", "INVALID_PERIOD: A Period must be a multiple of 60 seconds, from 60 to 86400."), (
        f"GetInsightRuleReport: Period=7 gave {error!r}"
    )

    # "" fails botocore's client-side min-length check; "{}" reaches service validation.
    error = _err(lambda: cw.put_insight_rule(RuleName=ctx.unique_name("sim2real-behav-cwprobe-rule-"), RuleDefinition="{}"))
    assert error == ("InvalidParameterValue", "INVALID_RULE_BODY: The RuleBody could not be parsed."), (
        f"PutInsightRule: a schema-invalid RuleDefinition gave {error!r}"
    )

    error = _err(lambda: cw.put_managed_insight_rules(ManagedRules=[]))
    assert error == ("InvalidParameterValue", "EMPTY_MANAGED_RULES: ManagedRules cannot be an empty array."), f"PutManagedInsightRules: ManagedRules=[] gave {error!r}"

    # "" fails botocore's client-side min-length check; a malformed ARN reaches the service.
    error = _err(lambda: cw.list_managed_insight_rules(ResourceARN="not-a-valid-arn"))
    assert error == ("InvalidParameterValue", "INVALID_RESOURCE_ARN: Invalid ARN."), f"ListManagedInsightRules: a malformed ResourceARN gave {error!r}"

    # DeleteMetricStream is idempotent for any Name meeting the minimum length, even one with
    # characters a real stream name cannot have; it does not validate the value.
    resp = cw.delete_metric_stream(Name="bad name!")
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"DeleteMetricStream: a malformed-but-nonexistent Name gave {resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
