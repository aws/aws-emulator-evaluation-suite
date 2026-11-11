"""resource-not-found-error-family."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-not-found-error-family"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']


def _err(fn):
    """Return the botocore Error dict of the ClientError fn() raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Missing-resource codes differ by API: SetAlarmState and GetDashboard return ResourceNotFound,
    mute-rule, tagging, contributor and dataset-KMS ops return ResourceNotFoundException, with
    exact messages; DeleteAlarms on a missing name succeeds.
    """
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bogus_alarm = ctx.unique_name("sim2real-behav-cwprobe-alarm-missing-")
    # DeleteAlarms on a nonexistent name succeeds despite ResourceNotFound in its documented errors.
    try:
        cw.delete_alarms(AlarmNames=[bogus_alarm])
    except ClientError as exc:
        raise AssertionError(
            f"DeleteAlarms: expected a nonexistent alarm name to be a no-op success, got {exc.response['Error']!r}"
        ) from exc

    err = _err(lambda: cw.set_alarm_state(
        AlarmName=bogus_alarm, StateValue="OK", StateReason="probe"
    ))
    assert (err["Code"], err.get("Message", "")) == ("ResourceNotFound", ""), f"SetAlarmState: got {err!r}"

    bogus_dash = ctx.unique_name("sim2real-behav-cwprobe-dash-missing-")
    err = _err(lambda: cw.get_dashboard(DashboardName=bogus_dash))
    assert (err["Code"], err.get("Message", "")) == ("ResourceNotFound", f"Dashboard {bogus_dash} does not exist"), f"GetDashboard: got {err!r}"

    bogus_mute_rule = ctx.unique_name("sim2real-behav-cwprobe-mute-missing-")
    err = _err(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=bogus_mute_rule))
    assert (err["Code"], err.get("Message", "")) == ("ResourceNotFoundException", ""), f"GetAlarmMuteRule: got {err!r}"

    err = _err(lambda: cw.list_alarm_mute_rules(AlarmName=bogus_alarm))
    assert (err["Code"], err.get("Message", "")) == ("ResourceNotFoundException", ""), f"ListAlarmMuteRules: got {err!r}"

    bogus_rule = ctx.unique_name("sim2real-behav-cwprobe-rule-missing-")
    now = datetime.now(timezone.utc)
    # CloudWatch validates the RuleName value rather than looking it up first, so a
    # nonexistent RuleName is InvalidParameterValue.
    err = _err(lambda: cw.get_insight_rule_report(
        RuleName=bogus_rule, StartTime=now - timedelta(minutes=10), EndTime=now, Period=60
    ))
    assert (err["Code"], err.get("Message", "")) == ("InvalidParameterValue", f"RULE_NAME: {bogus_rule}"), f"GetInsightRuleReport: got {err!r}"

    bogus_arn = f"arn:aws:cloudwatch:{ctx.region}:{account}:alarm:{bogus_alarm}"
    err = _err(lambda: cw.list_tags_for_resource(ResourceARN=bogus_arn))
    assert (err["Code"], err.get("Message", "")) == ("ResourceNotFoundException", ""), f"ListTagsForResource: got {err!r}"

    err = _err(lambda: cw.describe_alarm_contributors(AlarmName=bogus_alarm))
    assert (err["Code"], err.get("Message", "")) == ("ResourceNotFoundException", f"No alarm for name {bogus_alarm} was found"), f"DescribeAlarmContributors: got {err!r}"

    # The caller's `default` dataset always exists, so GetDataset has no reachable not-found case;
    # another account's dataset is rejected with AccessDenied before any lookup.
    other_account_dataset_arn = f"arn:aws:cloudwatch:{ctx.region}:111122223333:dataset/default"
    err = _err(lambda: cw.get_dataset(DatasetIdentifier=other_account_dataset_arn))
    assert (err["Code"], err.get("Message", "")) == ("AccessDenied", f"Caller account {account} is not authorized to access resource in account 111122223333"), f"GetDataset: got {err!r}"

    # DisassociateDatasetKmsKey documents ResourceNotFoundException specifically
    # for "the dataset has no associated KMS key" -- force that baseline first.
    try:
        cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    except ClientError:
        pass
    # Dataset-KMS APIs can transiently throttle on repeated calls; poll past Throttling.
    err = _poll_until(
        lambda: _err(lambda: cw.disassociate_dataset_kms_key(DatasetIdentifier="default")),
        lambda e: e["Code"] != "Throttling",
        timeout_s=30,
        interval_s=5,
        description="DisassociateDatasetKmsKey settles past transient Throttling",
    )
    assert (err["Code"], err.get("Message", "")) == ("ResourceNotFoundException", "No CMK association found for dataset default."), f"DisassociateDatasetKmsKey: got {err!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
