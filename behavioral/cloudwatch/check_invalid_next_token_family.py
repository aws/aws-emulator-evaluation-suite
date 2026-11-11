"""invalid-next-token-family."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-next-token-family"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

_METRIC_ALARM_DEFAULTS = dict(
    Namespace="AWS/EC2",
    MetricName="CPUUtilization",
    Statistic="Average",
    Period=60,
    EvaluationPeriods=1,
    Threshold=80.0,
    ComparisonOperator="GreaterThanThreshold",
)

_INSIGHT_RULE_DEFINITION = json.dumps(
    {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "AggregateOn": "Count",
        "LogGroupNames": ["/aws/lambda/*"],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.requestId"], "Filters": []},
    }
)

def _err(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """Paginated CloudWatch Describe/List/Get ops reject a malformed NextToken with InvalidNextToken
    and their exact messages, while DescribeAlarms and ListAlarmMuteRules accept it."""
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_token = "not-a-real-pagination-token=="

    code, message = _err(lambda: cw.describe_alarm_history(NextToken=bogus_token))
    assert code == "InvalidNextToken", f"DescribeAlarmHistory: expected InvalidNextToken, got {code}"
    assert message == f"Invalid NextToken : {bogus_token}", f"DescribeAlarmHistory: unexpected InvalidNextToken message {message!r}"

    # DescribeAlarms does not validate the NextToken format; any ClientError fails the check.
    cw.describe_alarms(NextToken=bogus_token)

    code, message = _err(lambda: cw.describe_anomaly_detectors(NextToken=bogus_token))
    assert code == "InvalidNextToken", f"DescribeAnomalyDetectors: expected InvalidNextToken, got {code}"
    assert message == f"nextToken = {bogus_token}, accountId = {account}.", f"DescribeAnomalyDetectors: unexpected InvalidNextToken message {message!r}"

    code, message = _err(lambda: cw.describe_insight_rules(NextToken=bogus_token))
    assert code == "InvalidNextToken", f"DescribeInsightRules: expected InvalidNextToken, got {code}"
    assert message == "INVALID_TOKEN: Invalid token.", f"DescribeInsightRules: unexpected InvalidNextToken message {message!r}"

    # ListAlarmMuteRules does not validate the NextToken format either.
    cw.list_alarm_mute_rules(NextToken=bogus_token)

    code, message = _err(lambda: cw.list_metric_streams(NextToken=bogus_token))
    assert code == "InvalidNextToken", f"ListMetricStreams: expected InvalidNextToken, got {code}"
    assert message == "Invalid NextToken", f"ListMetricStreams: unexpected InvalidNextToken message {message!r}"

    rule_name = ctx.unique_name("sim2real-behav-cwprobe-rule-")
    cw.put_insight_rule(
        RuleName=rule_name,
        RuleDefinition=_INSIGHT_RULE_DEFINITION,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=rule_name: cw.delete_insight_rules(RuleNames=[_n]))
    rule_arn = f"arn:aws:cloudwatch:{ctx.region}:{account}:insight-rule/{rule_name}"
    code, message = _err(lambda: cw.list_managed_insight_rules(ResourceARN=rule_arn, NextToken=bogus_token))
    assert code == "InvalidNextToken", f"ListManagedInsightRules: expected InvalidNextToken, got {code}"
    assert message == "INVALID_TOKEN: Invalid token.", f"ListManagedInsightRules: unexpected InvalidNextToken message {message!r}"

    now = datetime.now(timezone.utc)
    code, message = _err(lambda: cw.get_metric_data(
        MetricDataQueries=[{
            "Id": "m1",
            "MetricStat": {
                "Metric": {"Namespace": "AWS/EC2", "MetricName": "CPUUtilization"},
                "Period": 300,
                "Stat": "Average",
            },
            "ReturnData": True,
        }],
        StartTime=now - timedelta(hours=1),
        EndTime=now,
        NextToken=bogus_token,
    ))
    assert code == "InvalidNextToken", f"GetMetricData: expected InvalidNextToken, got {code}"
    assert message == "", f"GetMetricData: unexpected InvalidNextToken message {message!r}"

    # A real alarm, so the NextToken rather than the AlarmName is what gets rejected.
    alarm_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        **_METRIC_ALARM_DEFAULTS,
    )
    ctx.on_cleanup(lambda _n=alarm_name: cw.delete_alarms(AlarmNames=[_n]))
    code, message = _err(lambda: cw.describe_alarm_contributors(AlarmName=alarm_name, NextToken=bogus_token))
    assert code == "InvalidNextToken", f"DescribeAlarmContributors: expected InvalidNextToken, got {code}"
    assert message == f"Invalid NextToken : {bogus_token}", f"DescribeAlarmContributors: unexpected InvalidNextToken message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
