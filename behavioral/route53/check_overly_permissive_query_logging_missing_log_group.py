"""overly-permissive-query-logging-missing-log-group."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "overly-permissive-query-logging-missing-log-group"
GROUP = 'query-logging'
SERVICES = ['route53']

# Query logging requires the CloudWatch Logs log group and its resource policy to live in
# us-east-1, regardless of which region the hosted zone/check otherwise runs in.
LOGS_REGION = "us-east-1"


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx, prefix="zone"):
    raw = ctx.unique_name("sim2real-behav-" + prefix).lower().replace("_", "-")
    # example.com/.org/.net are reserved by AWS for public zones; use a non-reserved suffix.
    return f"{raw}.sim2real-probe-zone.com."


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _list_all_record_sets(r53, zone_id):
    out = []
    kwargs = {"HostedZoneId": zone_id}
    while True:
        resp = r53.list_resource_record_sets(**kwargs)
        out.extend(resp["ResourceRecordSets"])
        if not resp.get("IsTruncated"):
            return out
        kwargs["StartRecordName"] = resp["NextRecordName"]
        kwargs["StartRecordType"] = resp["NextRecordType"]
        if resp.get("NextRecordIdentifier"):
            kwargs["StartRecordIdentifier"] = resp["NextRecordIdentifier"]


def _empty_and_delete_zone(r53, zone_id):
    try:
        for rrs in _list_all_record_sets(r53, zone_id):
            if rrs["Type"] in ("NS", "SOA"):
                continue
            try:
                r53.change_resource_record_sets(
                    HostedZoneId=zone_id,
                    ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rrs}]},
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "HostedZoneNotFound",
                    "NoSuchHealthCheck",
                    "NoSuchHostedZone",
                ):
                    raise
        r53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchHealthCheck",
            "NoSuchHostedZone",
        ):
            raise


def _create_zone(ctx, r53, *, name=None, comment=None):
    resp = r53.create_hosted_zone(
        Name=name or _zone_name(ctx),
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": comment or "behavioral-check", "PrivateZone": False},
    )
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return resp


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). A successful call raises."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {resp!r}")


def _retry_until(fn, *, timeout_s, interval_s, retryable_codes):
    """Retry through CloudWatch Logs policy/log-group propagation delay, which Route 53 documents
    as a cause of transient InsufficientCloudWatchLogsResourcePolicy. Re-raises on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in retryable_codes or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _log_group_arn(logs, name):
    resp = logs.describe_log_groups(logGroupNamePrefix=name)
    for group in resp["logGroups"]:
        if group["logGroupName"] == name:
            return group["arn"]
    raise AssertionError(f"log group {name!r} not found via describe_log_groups after creation")


def _delete_config_if_present(r53, config_id):
    try:
        r53.delete_query_logging_config(Id=config_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchQueryLoggingConfig":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-resource-policy")
def run(ctx) -> None:
    """CreateQueryLoggingConfig is rejected with NoSuchCloudWatchLogsLogGroup when the log group is
    missing even though a resource policy grants Route 53 access; it succeeds once the group exists.
    """
    r53 = ctx.client("route53")
    logs = ctx.client("logs", region=LOGS_REGION)
    account = _account_id(ctx)
    base = ctx.unique_name("sim2real-behav-qlog").lower().replace("_", "-")

    ok_log_group_name = f"/aws/route53/{base}-ok"
    missing_log_group_name = f"/aws/route53/{base}-missing"

    logs.create_log_group(logGroupName=ok_log_group_name, tags={"sim2real-behav": base})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=ok_log_group_name))
    ok_log_group_arn = _log_group_arn(logs, ok_log_group_name)

    # One resource policy, scoped to this run's own name prefix, covers BOTH log groups used
    # below -- so the only variable between the positive control and the negative is whether the
    # target log group exists, not whether the policy exists.
    policy_name = ctx.unique_name("sim2real-behav-qlog-pol")
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "route53QueryLogging",
                    "Effect": "Allow",
                    "Principal": {"Service": "route53.amazonaws.com"},
                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": f"arn:aws:logs:{LOGS_REGION}:{account}:log-group:/aws/route53/{base}-*",
                }
            ],
        }
    )
    logs.put_resource_policy(policyName=policy_name, policyDocument=policy_doc)
    ctx.on_cleanup(lambda: logs.delete_resource_policy(policyName=policy_name))

    zone_ok = _create_zone(ctx, r53)
    zone_ok_id = zone_ok["HostedZone"]["Id"]

    created = _retry_until(
        lambda: r53.create_query_logging_config(
            HostedZoneId=zone_ok_id, CloudWatchLogsLogGroupArn=ok_log_group_arn
        ),
        timeout_s=90,
        interval_s=5,
        retryable_codes={"InsufficientCloudWatchLogsResourcePolicy"},
    )
    ok_config_id = created["QueryLoggingConfig"]["Id"]
    ctx.on_cleanup(lambda: _delete_config_if_present(r53, ok_config_id))

    listed_ok = r53.list_query_logging_configs(HostedZoneId=zone_ok_id)["QueryLoggingConfigs"]
    assert any(c["Id"] == ok_config_id for c in listed_ok), (ok_config_id, listed_ok)

    # --- break exactly one thing: same policy, but the target log group does not exist yet. ---
    zone_missing = _create_zone(ctx, r53)
    zone_missing_id = zone_missing["HostedZone"]["Id"]
    missing_log_group_arn = f"arn:aws:logs:{LOGS_REGION}:{account}:log-group:{missing_log_group_name}"

    code, message = _error(
        lambda: r53.create_query_logging_config(
            HostedZoneId=zone_missing_id, CloudWatchLogsLogGroupArn=missing_log_group_arn
        )
    )
    assert code == "NoSuchCloudWatchLogsLogGroup", code
    expected = "The specified CloudWatch Logs log group doesn't exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed_missing = r53.list_query_logging_configs(HostedZoneId=zone_missing_id)
    assert listed_missing["QueryLoggingConfigs"] == [], listed_missing["QueryLoggingConfigs"]

    # --- restore: create the log group the policy already covers -> identical call succeeds. ---
    logs.create_log_group(logGroupName=missing_log_group_name, tags={"sim2real-behav": base})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=missing_log_group_name))

    restored = _retry_until(
        lambda: r53.create_query_logging_config(
            HostedZoneId=zone_missing_id, CloudWatchLogsLogGroupArn=missing_log_group_arn
        ),
        timeout_s=60,
        interval_s=5,
        retryable_codes={"NoSuchCloudWatchLogsLogGroup", "InsufficientCloudWatchLogsResourcePolicy"},
    )
    restored_config_id = restored["QueryLoggingConfig"]["Id"]
    ctx.on_cleanup(lambda: _delete_config_if_present(r53, restored_config_id))

    listed_restored = r53.list_query_logging_configs(HostedZoneId=zone_missing_id)["QueryLoggingConfigs"]
    assert any(c["Id"] == restored_config_id for c in listed_restored), (
        restored_config_id,
        listed_restored,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
