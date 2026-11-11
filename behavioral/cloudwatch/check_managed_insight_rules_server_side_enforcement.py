"""managed-insight-rules-server-side-enforcement."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

_PROBE_TAGS = [{"Key": "sim2real-behav-cwprobe", "Value": "managed-insight-rules-server-side-enforcement"}]

CHECK = "managed-insight-rules-server-side-enforcement"
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

def _err(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """ListManagedInsightRules rejects a malformed ResourceARN but lists none for valid ones;
    PutManagedInsightRules and Enable/DisableInsightRules report unknown names via Failures.
    """
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    ddb = ctx.client("dynamodb")

    # DynamoDB's own Contributor Insights is unrelated to CloudWatch managed rule templates.
    table_name = ctx.unique_name("sim2real-behav-cwprobe-table-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        Tags=_PROBE_TAGS,
    )
    ctx.on_cleanup(lambda _n=table_name: ddb.delete_table(TableName=_n))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=60,
        interval_s=3,
        description="DynamoDB table ACTIVE",
    )
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]
    ddb.update_contributor_insights(TableName=table_name, ContributorInsightsAction="ENABLE")

    # A valid ARN of an ineligible resource type resolves to an empty list, not an error.
    table_resp = cw.list_managed_insight_rules(ResourceARN=table_arn)
    table_rules = table_resp.get("ManagedRules", [])
    assert table_rules == [], (
        f"expected zero managed rules for a DynamoDB table ARN, got {table_rules!r}"
    )

    error = _err(lambda: cw.list_managed_insight_rules(ResourceARN="not-a-valid-arn-at-all"))
    assert error == ("InvalidParameterValue", "INVALID_RESOURCE_ARN: Invalid ARN."), (
        f"expected the InvalidParameterValue rejection for a structurally malformed ResourceARN, got {error!r}"
    )

    alarm_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-")
    cw.put_metric_alarm(AlarmName=alarm_name, Tags=_PROBE_TAGS, **_METRIC_ALARM_DEFAULTS)
    ctx.on_cleanup(lambda _n=alarm_name: cw.delete_alarms(AlarmNames=[_n]))
    alarm_arn = f"arn:aws:cloudwatch:{ctx.region}:{account}:alarm:{alarm_name}"
    alarm_resp = cw.list_managed_insight_rules(ResourceARN=alarm_arn)
    assert alarm_resp.get("ManagedRules", []) == [], (
        f"expected a valid alarm ARN to resolve to an empty list, got {alarm_resp}"
    )

    # An unknown TemplateName is reported per rule in Failures, not raised.
    bogus_template = "sim2real-behav-nonexistent-template"
    put_resp = cw.put_managed_insight_rules(
        ManagedRules=[{"ResourceARN": table_arn, "TemplateName": bogus_template}]
    )
    template_failure = {
        "FailureResource": bogus_template,
        "ExceptionType": "ResourceNotFoundException",
        "FailureCode": "TEMPLATE_NAME",
        "FailureDescription": "Could not find template with the specified templateName.",
    }
    assert put_resp.get("Failures", []) == [template_failure], (
        f"expected PutManagedInsightRules to flag an unrecognized TemplateName via "
        f"exactly one TEMPLATE_NAME Failures entry, got {put_resp}"
    )
    alarm_put_resp = cw.put_managed_insight_rules(
        ManagedRules=[{"ResourceARN": alarm_arn, "TemplateName": bogus_template}]
    )
    assert alarm_put_resp.get("Failures", []) == [template_failure], (
        f"expected PutManagedInsightRules to flag an unrecognized TemplateName for "
        f"the alarm ARN too, got {alarm_put_resp}"
    )

    # A provisioned plain rule flips state with no Failures, so the negative below is meaningful.
    real_rule_name = ctx.unique_name("sim2real-behav-cwprobe-real-rule-")
    cw.put_insight_rule(
        RuleName=real_rule_name,
        RuleDefinition=json.dumps(
            {
                "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
                "AggregateOn": "Count",
                "Contribution": {"Filters": [], "Keys": ["$.key"]},
                "LogFormat": "JSON",
                "LogGroupNames": [f"{real_rule_name}-nonexistent-log-group*"],
            }
        ),
        Tags=_PROBE_TAGS,
    )
    ctx.on_cleanup(lambda _n=real_rule_name: cw.delete_insight_rules(RuleNames=[_n]))
    positive_disable_resp = cw.disable_insight_rules(RuleNames=[real_rule_name])
    assert positive_disable_resp.get("Failures", []) == [], (
        f"expected DisableInsightRules to succeed with no Failures for a rule that "
        f"was actually provisioned via PutInsightRule, got {positive_disable_resp}"
    )
    positive_enable_resp = cw.enable_insight_rules(RuleNames=[real_rule_name])
    assert positive_enable_resp.get("Failures", []) == [], (
        f"expected EnableInsightRules to succeed with no Failures for a rule that "
        f"was actually provisioned via PutInsightRule, got {positive_enable_resp}"
    )

    never_provisioned_rule = ctx.unique_name("sim2real-behav-cwprobe-managed-rule-missing-")
    rule_failure = {
        "FailureResource": never_provisioned_rule,
        "ExceptionType": "ResourceNotFoundException",
        "FailureCode": "RULE_NAME",
        "FailureDescription": f"Rule {never_provisioned_rule} does not exist.",
    }
    disable_resp = cw.disable_insight_rules(RuleNames=[never_provisioned_rule])
    assert disable_resp.get("Failures", []) == [rule_failure], (
        f"expected DisableInsightRules to flag an unprovisioned rule identity via "
        f"Failures, got {disable_resp}"
    )
    enable_resp = cw.enable_insight_rules(RuleNames=[never_provisioned_rule])
    assert enable_resp.get("Failures", []) == [rule_failure], (
        f"expected EnableInsightRules to flag an unprovisioned rule identity via "
        f"Failures, got {enable_resp}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
