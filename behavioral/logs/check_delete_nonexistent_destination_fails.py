"""delete-nonexistent-destination-fails."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-nonexistent-destination-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A real destination listed by DescribeDestinations deletes and is unlisted, and deleting the same name
    again raises ResourceNotFoundException with its exact message."""
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")

    name = ctx.unique_name("sim2real-dest-missing-")
    stream_name = ctx.unique_name("sim2real-deststream-")
    role_name = ctx.unique_name("sim2real-destrole-")

    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: _swallow(lambda: kinesis.delete_stream(StreamName=stream_name)))
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]

    def _cleanup_role():
        _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-destpolicy"))
        _swallow(lambda: iam.delete_role(RoleName=role_name))

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

    # PutDestination actively delivers a test message to the target and rejects
    # with InvalidParameterException/AccessDeniedException while the freshly
    # created role's PassRole grant is still propagating.
    _retry_on_error(
        lambda: logs.put_destination(destinationName=name, targetArn=target_arn, roleArn=role_arn),
        retriable_codes={"InvalidParameterException", "AccessDeniedException"},
        timeout_s=90,
        interval_s=5,
    )
    ctx.on_cleanup(lambda: _swallow(lambda: logs.delete_destination(destinationName=name)))

    resp = logs.describe_destinations(DestinationNamePrefix=name)
    matches = [d for d in resp.get("destinations", []) if d["destinationName"] == name]
    assert len(matches) == 1, f"expected destination {name} in DescribeDestinations, got {resp}"

    # --- positive control: deleting a destination that genuinely exists succeeds ---
    logs.delete_destination(destinationName=name)

    resp2 = logs.describe_destinations(DestinationNamePrefix=name)
    matches2 = [d for d in resp2.get("destinations", []) if d["destinationName"] == name]
    assert matches2 == [], f"destination {name} still present after delete: {matches2}"

    # --- the negative under test: the same name, now genuinely absent ---
    error = _expect_error(lambda: logs.delete_destination(destinationName=name))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted destination, got {error!r}"
    )
    expected_message = "The specified destination does not exist."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


def _expect_error(fn):
    """Call fn(); return the botocore Error dict. Raises if fn() unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _swallow(fn):
    """Best-effort teardown: ignore an API refusal (the resource may already be gone)."""
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
