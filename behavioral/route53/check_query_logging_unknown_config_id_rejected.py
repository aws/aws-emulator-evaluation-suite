"""query-logging-unknown-config-id-rejected."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "query-logging-unknown-config-id-rejected"
GROUP = 'query-logging'
SERVICES = ['route53']


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx):
    raw = ctx.unique_name("sim2real-behav-qlcfg").lower().replace("_", "-")
    # example.com/.org/.net are reserved by AWS for public zones; use a non-reserved suffix.
    return f"{raw}.sim2real-probe-zone.com."


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _client_error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


_NO_SUCH_CONFIG_MESSAGE = "The query logging configuration does not exist."


def _delete_config_ignore_missing(r53, config_id):
    try:
        r53.delete_query_logging_config(Id=config_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchQueryLoggingConfig":
            raise


def _create_real_query_logging_config(ctx, r53):
    """Stand up a genuinely working query logging config: a public hosted zone plus a
    us-east-1 CloudWatch log group whose resource policy grants Route 53 write access.
    Query logging config log groups must live in us-east-1 regardless of ctx.region.
    """
    zone = r53.create_hosted_zone(
        Name=_zone_name(ctx),
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": "behavioral-check", "PrivateZone": False},
    )
    zone_id = zone["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: r53.delete_hosted_zone(Id=z))

    logs = ctx.client("logs", region="us-east-1")
    log_group_name = f"/aws/route53/{ctx.unique_name('sim2real-behav-qlcfg-lg')}"
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": "behavioral-check"})
    ctx.on_cleanup(lambda n=log_group_name: logs.delete_log_group(logGroupName=n))
    log_group_arn = f"arn:aws:logs:us-east-1:{_account_id(ctx)}:log-group:{log_group_name}:*"

    policy_name = ctx.unique_name("sim2real-behav-qlcfg-policy")
    policy_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "Route53LogsToCloudWatchLogs",
            "Effect": "Allow",
            "Principal": {"Service": "route53.amazonaws.com"},
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": log_group_arn,
        }],
    })
    logs.put_resource_policy(policyName=policy_name, policyDocument=policy_doc)
    ctx.on_cleanup(lambda p=policy_name: logs.delete_resource_policy(policyName=p))

    # The resource policy can take a few seconds to become visible to Route 53's own
    # validation; retry the create on the specific transient error with a bounded deadline
    # rather than sleeping unconditionally.
    deadline = time.monotonic() + 60
    while True:
        try:
            config = r53.create_query_logging_config(
                HostedZoneId=zone_id, CloudWatchLogsLogGroupArn=log_group_arn
            )["QueryLoggingConfig"]
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InsufficientCloudWatchLogsResourcePolicy" or time.monotonic() >= deadline:
                raise
            time.sleep(3)

    config_id = config["Id"]
    ctx.on_cleanup(lambda c=config_id: _delete_config_ignore_missing(r53, c))
    return zone_id, config_id, log_group_arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-resource-policy")
def run(ctx) -> None:
    """GetQueryLoggingConfig / DeleteQueryLoggingConfig on an unknown id return
    NoSuchQueryLoggingConfig, while a real query logging config stays readable and deletable,
    so the error is about the id rather than a blanket rejection."""
    r53 = ctx.client("route53")

    zone_id, config_id, log_group_arn = _create_real_query_logging_config(ctx, r53)
    # CreateHostedZone returns Id as "/hostedzone/Z...", but GetQueryLoggingConfig echoes
    # the bare zone id with no prefix.
    bare_zone_id = zone_id.rsplit("/", 1)[-1]

    # Positive control: the config we created is real and readable.
    got = r53.get_query_logging_config(Id=config_id)["QueryLoggingConfig"]
    assert got["HostedZoneId"] == bare_zone_id, (got["HostedZoneId"], bare_zone_id)
    assert got["CloudWatchLogsLogGroupArn"] == log_group_arn, (
        got["CloudWatchLogsLogGroupArn"], log_group_arn
    )

    bogus_id = "00000000-0000-0000-0000-000000000000"
    code, message = _client_error(lambda: r53.get_query_logging_config(Id=bogus_id))
    assert code == "NoSuchQueryLoggingConfig", code
    assert message == _NO_SUCH_CONFIG_MESSAGE, message

    code2, message2 = _client_error(lambda: r53.delete_query_logging_config(Id=bogus_id))
    assert code2 == "NoSuchQueryLoggingConfig", code2
    assert message2 == _NO_SUCH_CONFIG_MESSAGE, message2

    # The bogus-id delete above must not have disturbed the real config.
    still_there = r53.get_query_logging_config(Id=config_id)["QueryLoggingConfig"]
    assert still_there["Id"] == config_id, still_there

    # Delete the real config, then prove it is both gone and unusable: an independent
    # read returns the specific not-found code, and a further delete on the now-dead id does
    # too rather than succeeding silently.
    r53.delete_query_logging_config(Id=config_id)
    code3, message3 = _client_error(lambda: r53.get_query_logging_config(Id=config_id))
    assert code3 == "NoSuchQueryLoggingConfig", code3
    assert message3 == _NO_SUCH_CONFIG_MESSAGE, message3
    code4, message4 = _client_error(lambda: r53.delete_query_logging_config(Id=config_id))
    assert code4 == "NoSuchQueryLoggingConfig", code4
    assert message4 == _NO_SUCH_CONFIG_MESSAGE, message4


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
