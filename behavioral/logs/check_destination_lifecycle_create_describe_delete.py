"""destination-lifecycle-create-describe-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "destination-lifecycle-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDestination creates a destination that DescribeDestinations reports with its target and
    role; DeleteDestination removes it and a second delete fails with ResourceNotFoundException.
    """
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    ctx.client("sts")

    name = ctx.unique_name("sim2real-dest-")
    stream_name = ctx.unique_name("sim2real-deststream-")
    role_name = ctx.unique_name("sim2real-destrole-")

    kinesis.create_stream(
        StreamName=stream_name,
        ShardCount=1,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _ignore(lambda: kinesis.delete_stream(StreamName=stream_name)))
    _poll_until(
        lambda: kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )
    target_arn = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["StreamARN"]

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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup_role():
        _ignore(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-destpolicy"))
        _ignore(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup_role)

    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "kinesis:PutRecord",
                "Resource": target_arn,
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-destpolicy",
        PolicyDocument=json.dumps(access_policy),
    )

    # PutDestination delivers a test message to the target and rejects the call if delivery
    # fails, so it needs a real stream and role; retry past IAM eventual consistency.
    _retry_on_error(
        lambda: logs.put_destination(
            destinationName=name,
            targetArn=target_arn,
            roleArn=role_arn,
            tags={"sim2real": CHECK},
        ),
        retriable_codes={"InvalidParameterException", "AccessDeniedException"},
        timeout_s=90,
        interval_s=5,
    )
    ctx.on_cleanup(
        lambda: _ignore(lambda: logs.delete_destination(destinationName=name))
    )

    resp = logs.describe_destinations(DestinationNamePrefix=name)
    matches = [d for d in resp.get("destinations", []) if d["destinationName"] == name]
    assert len(matches) == 1, f"expected destination {name} in DescribeDestinations, got {resp}"
    assert matches[0]["targetArn"] == target_arn, (
        f"expected targetArn {target_arn!r} on {name}, got {matches[0]['targetArn']!r}"
    )
    assert matches[0]["roleArn"] == role_arn, (
        f"expected roleArn {role_arn!r} on {name}, got {matches[0]['roleArn']!r}"
    )

    logs.delete_destination(destinationName=name)

    resp2 = logs.describe_destinations(DestinationNamePrefix=name)
    matches2 = [d for d in resp2.get("destinations", []) if d["destinationName"] == name]
    assert matches2 == [], f"destination {name} still present after delete: {matches2}"

    delete_again_code, delete_again_message = _error(
        lambda: logs.delete_destination(destinationName=name)
    )
    assert delete_again_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting already-deleted destination {name}, "
        f"got {delete_again_code!r}"
    )
    assert delete_again_message == "The specified destination does not exist.", (
        f"unexpected DeleteDestination message for already-deleted destination {name}: "
        f"{delete_again_message!r}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _ignore(fn):
    """Best-effort teardown call; a not-found error is ignored."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_on_error(fn, *, retriable_codes, timeout_s=60.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            if code not in retriable_codes:
                raise
            last_err = err
            time.sleep(interval_s)
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
