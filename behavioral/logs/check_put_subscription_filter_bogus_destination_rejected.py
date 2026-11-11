"""put-subscription-filter-bogus-destination-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-subscription-filter-bogus-destination-rejected"
GROUP = 'overly-permissive'
SERVICES = ['logs']


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_log_group(ctx, logs, name=None, **kwargs) -> str:
    name = name or ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(
        logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"}, **kwargs
    )
    ctx.on_cleanup(lambda: _delete_log_group(logs, name))
    return name


def _delete_log_group(logs, name) -> None:
    """Drop deletion protection (if any) before deleting, mirroring the suite's teardown."""
    try:
        logs.put_log_group_deletion_protection(
            logGroupIdentifier=name, deletionProtectionEnabled=False
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    logs.delete_log_group(logGroupName=name)


def _wait_stream_active(kinesis, stream_name, timeout_s=120.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2.0)
    raise AssertionError(f"kinesis stream {stream_name} never became ACTIVE")


def _put_filter_with_retry(logs, group, filter_name, dest_arn, role_arn, timeout_s=60.0) -> None:
    """CloudWatch Logs delivers a synchronous test record through roleArn before
    accepting a Kinesis subscription filter; a freshly-created role's trust/permissions
    can take a few seconds to propagate, which surfaces as a transient
    InvalidParameterException indistinguishable from a real rejection unless retried."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            logs.put_subscription_filter(
                logGroupName=group,
                filterName=filter_name,
                filterPattern="",
                destinationArn=dest_arn,
                roleArn=role_arn,
            )
            return
        except ClientError as exc:
            last_err = exc
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterException":
                raise
            time.sleep(3.0)
    raise AssertionError(f"PutSubscriptionFilter never succeeded within {timeout_s}s: {last_err}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutSubscriptionFilter to a nonexistent Kinesis stream is refused with InvalidParameterException
    naming the stream and account and persists nothing, while the same role works on a real stream;
    once the stream exists the identical call succeeds.
    """
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    group = _create_log_group(ctx, logs)

    role_name = ctx.unique_name("sim2real-behav-sf-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "logs.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-put-record",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "kinesis:PutRecord",
                        "Resource": f"arn:aws:kinesis:{ctx.region}:{account_id}:stream/*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="allow-put-record"))

    good_stream = ctx.unique_name("sim2real-behav-sf-good-")
    kinesis.create_stream(StreamName=good_stream, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=good_stream, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, good_stream)
    good_arn = f"arn:aws:kinesis:{ctx.region}:{account_id}:stream/{good_stream}"

    # Positive control: a real, active stream through this exact role succeeds --
    # isolating the negative below to "the stream doesn't exist", not "the role
    # is unusable".
    good_filter = ctx.unique_name("sim2real-behav-sf-good-filt-")
    _put_filter_with_retry(logs, group, good_filter, good_arn, role_arn)
    filters = logs.describe_subscription_filters(logGroupName=group)["subscriptionFilters"]
    names = {f["filterName"] for f in filters}
    assert good_filter in names, f"positive control filter missing after create: {names}"

    # Break exactly one thing: same role, same permission shape, but the stream
    # this ARN names has never been created.
    bogus_stream = ctx.unique_name("sim2real-behav-sf-bogus-")
    bogus_arn = f"arn:aws:kinesis:{ctx.region}:{account_id}:stream/{bogus_stream}"
    bogus_filter = ctx.unique_name("sim2real-behav-sf-bogus-filt-")
    code, message = _client_error(
        lambda: logs.put_subscription_filter(
            logGroupName=group,
            filterName=bogus_filter,
            filterPattern="",
            destinationArn=bogus_arn,
            roleArn=role_arn,
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == (
        "Could not deliver test message to specified Kinesis stream. "
        f"Stream {bogus_stream} under account {account_id} not found."
    ), f"unexpected message: {message!r}"

    filters = logs.describe_subscription_filters(logGroupName=group)["subscriptionFilters"]
    names = {f["filterName"] for f in filters}
    assert names == {good_filter}, f"unexpected filter set after rejected put: {names}"

    # Restore: create the stream this ARN names, then reissue the identical call.
    kinesis.create_stream(StreamName=bogus_stream, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=bogus_stream, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, bogus_stream)
    _put_filter_with_retry(logs, group, bogus_filter, bogus_arn, role_arn)

    filters = logs.describe_subscription_filters(logGroupName=group)["subscriptionFilters"]
    names = {f["filterName"] for f in filters}
    assert names == {good_filter, bogus_filter}, (
        f"expected both filters present once the destination exists, got {names}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
