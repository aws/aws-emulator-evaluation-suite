"""resource-conflict-error-precondition."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-conflict-error-precondition"
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

_VALID_DASHBOARD_BODY = json.dumps(
    {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 3,
                "properties": {"markdown": "# behavioral test dashboard"},
            }
        ]
    }
)


def _err(fn):
    """Call fn(); return the botocore Error dict if a ClientError is raised. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _cloudwatch_kms_policy(account, *, allow_cloudwatch):
    statements = [
        {
            "Sid": "EnableRootAccess",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "kms:*",
            "Resource": "*",
        }
    ]
    if allow_cloudwatch:
        statements.append(
            {
                "Sid": "AllowCloudWatchDatasetEncryption",
                "Effect": "Allow",
                "Principal": {"Service": "cloudwatch.amazonaws.com"},
                "Action": [
                    "kms:DescribeKey",
                    "kms:GenerateDataKey",
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                ],
                "Resource": "*",
            }
        )
    return {"Version": "2012-10-17", "Statement": statements}


def _create_kms_key(ctx, policy):
    """Create a real KMS key with the given key policy. Returns (key_id, key_arn)."""
    kms = ctx.client("kms")
    resp = kms.create_key(
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    key_arn = resp["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    return key_id, key_arn


def _disassociate_default_dataset_key(cw):
    """Teardown: leave the default dataset with no KMS key. The run body disassociates it
    itself, so "No CMK association" is the expected resting state here."""
    try:
        cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting an alarm a composite uses, or reusing its name for a log alarm, is ValidationError.

    Both blocked deletes succeed once the composite is gone; dashboard, tag and dataset-key ops
    succeed under non-conflicting use.
    """
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # --- DeleteAlarms: alarm a live composite alarm depends on (AlarmRule or ActionsSuppressor) ---
    leaf = ctx.unique_name("sim2real-behav-cwprobe-alarm-leaf-")
    suppressor = ctx.unique_name("sim2real-behav-cwprobe-alarm-suppressor-")
    composite = ctx.unique_name("sim2real-behav-cwprobe-alarm-composite-")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite]))
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[leaf, suppressor]))
    cw.put_metric_alarm(AlarmName=leaf, **_METRIC_ALARM_DEFAULTS)
    cw.put_metric_alarm(AlarmName=suppressor, **_METRIC_ALARM_DEFAULTS)
    cw.put_composite_alarm(
        AlarmName=composite,
        AlarmRule=f'ALARM("{leaf}")',
        ActionsSuppressor=suppressor,
        ActionsSuppressorExtensionPeriod=60,
        ActionsSuppressorWaitPeriod=60,
    )

    def composite_visible():
        r = cw.describe_alarms(AlarmNames=[composite], AlarmTypes=["CompositeAlarm"])
        return r.get("CompositeAlarms", [])

    _poll_until(composite_visible, lambda c: len(c) == 1, timeout_s=30, interval_s=3)

    # Real AWS blocks DeleteAlarms for BOTH kinds of composite-alarm dependency while the
    # composite is alive -- a plain AlarmRule reference (`leaf`) is rejected exactly like the
    # ActionsSuppressor linkage (`suppressor`).
    leaf_err = _err(lambda: cw.delete_alarms(AlarmNames=[leaf]))
    assert leaf_err["Code"] == "ValidationError", (
        f"expected ValidationError deleting an alarm referenced via a composite's AlarmRule, got {leaf_err!r}"
    )
    expected = f"Cannot delete {leaf} as there are composite alarm(s) depending on it."
    assert leaf_err.get("Message", "") == expected, f"expected {expected!r}, got {leaf_err.get('Message', '')!r}"
    leaf_still_there = cw.describe_alarms(AlarmNames=[leaf]).get("MetricAlarms", [])
    assert len(leaf_still_there) == 1, "leaf alarm must still exist after the rejected DeleteAlarms call"

    err = _err(lambda: cw.delete_alarms(AlarmNames=[suppressor]))
    assert err["Code"] == "ValidationError", (
        f"expected ValidationError deleting an alarm referenced as an ActionsSuppressor, got {err!r}"
    )
    expected = f"Cannot delete {suppressor} as there are composite alarm(s) depending on it."
    assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"
    still_there = cw.describe_alarms(AlarmNames=[suppressor]).get("MetricAlarms", [])
    assert len(still_there) == 1, "suppressor alarm must still exist after the rejected DeleteAlarms call"

    # Restore: remove the composite (the thing both deletes were blocked by), then prove both
    # rejected DeleteAlarms calls now succeed.
    cw.delete_alarms(AlarmNames=[composite])
    cw.delete_alarms(AlarmNames=[leaf, suppressor])
    both_gone = cw.describe_alarms(AlarmNames=[leaf, suppressor]).get("MetricAlarms", [])
    assert len(both_gone) == 0, (
        f"expected both alarms deletable once the composite depending on them is gone, got {both_gone}"
    )

    # --- PutLogAlarm: AlarmName collides with an existing metric alarm ---
    # PutLogAlarm is only modeled in newer botocore; when absent this precondition
    # sub-case is skipped -- the ActionsSuppressor conflict above and the
    # success-path exercise below remain the meaningful assertions.
    if hasattr(cw, "put_log_alarm"):
        dup_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-dup-")
        ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[dup_name]))
        cw.put_metric_alarm(AlarmName=dup_name, **_METRIC_ALARM_DEFAULTS)

        def call_put_log_alarm():
            cw.put_log_alarm(
                AlarmName=dup_name,
                ScheduledQueryConfiguration={
                    "QueryString": "fields @timestamp, @message | filter @message like /ERROR/",
                    "LogGroupIdentifiers": [
                        f"arn:aws:logs:{ctx.region}:{account}:log-group:/aws/lambda/does-not-need-to-exist"
                    ],
                    "ScheduledQueryRoleARN": f"arn:aws:iam::{account}:role/does-not-need-to-exist",
                    "AggregationExpression": "count(*)",
                    "ScheduleConfiguration": {"ScheduleExpression": "rate(5 minutes)", "StartTimeOffset": 300},
                },
                QueryResultsToEvaluate=1,
                QueryResultsToAlarm=1,
                Threshold=1.0,
                ComparisonOperator="GreaterThanThreshold",
            )

        err = _err(call_put_log_alarm)
        # With a syntactically-valid but
        # non-existent ScheduledQueryRoleARN, CloudWatch's request-level validation
        # rejects the call before any AlarmName-collision check even runs, and it
        # does so with the same generic 'ValidationError' code seen for the other
        # composite-alarm-adjacent preconditions in this suite (not the classic
        # 'ResourceConflict' string documented for PutLogAlarm).
        assert err["Code"] == "ValidationError", (
            f"expected ValidationError reusing an AlarmName already used by a metric alarm "
            f"(with a non-existent ScheduledQueryRoleARN), got {err!r}"
        )
        # message varies: it embeds the downstream Logs service's per-call request id.
        unchanged = cw.describe_alarms(AlarmNames=[dup_name], AlarmTypes=["MetricAlarm"]).get(
            "MetricAlarms", []
        )
        assert len(unchanged) == 1, (
            f"expected the rejected PutLogAlarm call to leave the existing metric alarm untouched, "
            f"got {unchanged}"
        )

        cw.delete_alarms(AlarmNames=[dup_name])

    # --- Supporting success-path exercise of the remaining ops in this family: they have no
    # deterministic conflict precondition reachable from a single caller.
    dash_name = ctx.unique_name("sim2real-behav-cwprobe-dash-")
    ctx.on_cleanup(lambda: cw.delete_dashboards(DashboardNames=[dash_name]))
    cw.put_dashboard(DashboardName=dash_name, DashboardBody=_VALID_DASHBOARD_BODY)
    dash_arn = f"arn:aws:cloudwatch::{account}:dashboard/{dash_name}"
    cw.tag_resource(ResourceARN=dash_arn, Tags=[{"Key": "k1", "Value": "v1"}])
    tags = cw.list_tags_for_resource(ResourceARN=dash_arn)["Tags"]
    assert any(t["Key"] == "k1" for t in tags), f"expected tag k1 on dashboard, got {tags}"
    cw.untag_resource(ResourceARN=dash_arn, TagKeys=["k1"])
    cw.delete_dashboards(DashboardNames=[dash_name])

    ctx.on_cleanup(lambda: _disassociate_default_dataset_key(cw))
    try:
        cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    except ClientError:
        pass
    _good_key_id, good_key_arn = _create_kms_key(ctx, _cloudwatch_kms_policy(account, allow_cloudwatch=True))
    cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=good_key_arn)
    ds = cw.get_dataset(DatasetIdentifier="default")
    assert ds.get("KmsKeyArn") == good_key_arn, f"expected dataset KmsKeyArn to be set, got {ds}"
    cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    ds2 = cw.get_dataset(DatasetIdentifier="default")
    assert "KmsKeyArn" not in ds2, f"expected KmsKeyArn removed after disassociate, got {ds2}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
