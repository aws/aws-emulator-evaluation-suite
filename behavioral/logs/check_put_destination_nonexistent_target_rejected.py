"""put-destination-nonexistent-target-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-destination-nonexistent-target-rejected"
GROUP = 'overly-permissive'
SERVICES = ['logs']


def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _retry_on_invalid_parameter(fn, *, timeout_s=45, interval_s=3.0):
    """Retry fn() while it raises InvalidParameterException (absorbs IAM
    trust/permission propagation lag before CloudWatch Logs can deliver a test
    record through the role). Re-raises the last exception past the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _error(fn):
    """Call fn(); return its (error code, error message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutDestination with a real role and a nonexistent Kinesis stream is refused with
    InvalidParameterException and its exact message and keeps the previous target; once the stream
    exists the same call succeeds.
    """
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    good_stream_name = ctx.unique_name("sim2real-behav-kstream-good-")
    ghost_stream_name = ctx.unique_name("sim2real-behav-kstream-ghost-")
    good_arn = f"arn:aws:kinesis:{ctx.region}:{account}:stream/{good_stream_name}"
    ghost_arn = f"arn:aws:kinesis:{ctx.region}:{account}:stream/{ghost_stream_name}"

    kinesis.create_stream(StreamName=good_stream_name, ShardCount=1)
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=good_stream_name, EnforceConsumerDeletion=True)
    )
    _poll_until(
        lambda: kinesis.describe_stream(StreamName=good_stream_name)["StreamDescription"],
        lambda d: d["StreamStatus"] == "ACTIVE",
        timeout_s=90,
        interval_s=2.0,
        description=f"Kinesis stream {good_stream_name} becomes ACTIVE",
    )

    role_name = ctx.unique_name("sim2real-behav-role-ghost-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))

    def _teardown_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="allow-put-record")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_teardown_role)
    # Wildcard resource covers both the good and the not-yet-created ghost stream,
    # so the role's permissions never change across the break/restore boundary.
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
                        "Resource": f"arn:aws:kinesis:{ctx.region}:{account}:stream/sim2real-behav-kstream-*",
                    }
                ],
            }
        ),
    )
    role_arn = f"arn:aws:iam::{account}:role/{role_name}"

    dest_name = ctx.unique_name("sim2real-behav-dest-ghost-")
    ctx.on_cleanup(lambda: logs.delete_destination(destinationName=dest_name))

    # Positive control: same role, a target that genuinely exists — must succeed.
    _retry_on_invalid_parameter(
        lambda: logs.put_destination(
            destinationName=dest_name, targetArn=good_arn, roleArn=role_arn
        )
    )
    before = logs.describe_destinations(DestinationNamePrefix=dest_name).get("destinations", [])
    assert len(before) == 1 and before[0]["targetArn"] == good_arn, (
        f"positive control did not land: expected 1 destination targeting {good_arn!r}, got {before!r}"
    )

    # Break exactly one thing: point the same destination at a stream that does
    # not exist. Role and permissions are unchanged from the positive control.
    code, msg = _error(
        lambda: logs.put_destination(
            destinationName=dest_name, targetArn=ghost_arn, roleArn=role_arn
        )
    )
    assert code == "InvalidParameterException", f"got {code!r}"
    assert msg == (
        "Could not deliver test message to specified destination. Check if the destination is valid."
    ), f"got {msg!r}"

    # Effect absent, via an independent read: the destination must still point at
    # the last-valid target, not at the dead one and not at nothing.
    mid = logs.describe_destinations(DestinationNamePrefix=dest_name).get("destinations", [])
    assert len(mid) == 1 and mid[0]["targetArn"] == good_arn, (
        f"rejected update was applied anyway: expected target still {good_arn!r}, got {mid!r}"
    )

    # Restore: create the missing stream, then retry the
    # identical call. Same destination, same role, same target ARN — only the
    # stream's existence changed.
    kinesis.create_stream(StreamName=ghost_stream_name, ShardCount=1)
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=ghost_stream_name, EnforceConsumerDeletion=True)
    )
    _poll_until(
        lambda: kinesis.describe_stream(StreamName=ghost_stream_name)["StreamDescription"],
        lambda d: d["StreamStatus"] == "ACTIVE",
        timeout_s=90,
        interval_s=2.0,
        description=f"Kinesis stream {ghost_stream_name} becomes ACTIVE",
    )
    _retry_on_invalid_parameter(
        lambda: logs.put_destination(
            destinationName=dest_name, targetArn=ghost_arn, roleArn=role_arn
        )
    )
    after = logs.describe_destinations(DestinationNamePrefix=dest_name).get("destinations", [])
    assert len(after) == 1 and after[0]["targetArn"] == ghost_arn, (
        f"identical call did not succeed once the target became real: expected target {ghost_arn!r}, got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
