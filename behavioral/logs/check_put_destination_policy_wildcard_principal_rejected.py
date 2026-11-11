"""put-destination-policy-wildcard-principal-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-destination-policy-wildcard-principal-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutDestinationPolicy with an overly-broad wildcard principal is rejected,
    confirming the service validates principals rather than accepting any JSON."""
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    account_id = sts.get_caller_identity()["Account"]

    # PutDestination validates connectivity by attempting to deliver a test message to
    # the target, so targetArn/roleArn must refer to a real, reachable Kinesis stream
    # and a role that CloudWatch Logs can actually assume and use to write to it.
    stream_name = ctx.unique_name("sim2real-behav-destpol-stream-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    stream_arn = _wait_for_stream_active(kinesis, stream_name)

    role_name = ctx.unique_name("sim2real-behav-destpol-role-")
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
    ctx.on_cleanup(lambda: _delete_role_best_effort(iam, role_name))
    write_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["kinesis:PutRecord", "kinesis:PutRecords", "kinesis:DescribeStream"],
                "Resource": stream_arn,
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="allow-kinesis-write", PolicyDocument=json.dumps(write_policy)
    )
    ctx.on_cleanup(lambda: _delete_role_policy_best_effort(iam, role_name))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    dest_name = ctx.unique_name("sim2real-behav-destpol-")
    dest = _put_destination_with_retry(logs, dest_name, stream_arn, role_arn)["destination"]
    ctx.on_cleanup(lambda: logs.delete_destination(destinationName=dest_name))

    wildcard_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "logs:PutSubscriptionFilter",
                "Resource": dest["arn"],
            }
        ],
    }
    code, msg = _error(
        lambda: logs.put_destination_policy(
            destinationName=dest_name, accessPolicy=json.dumps(wildcard_policy)
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a wildcard '*' principal, got {code!r}"
    )
    assert msg == (
        "Error occurred while parsing accessPolicy. Please check if the accessPolicy has been "
        "constructed correctly using IAM grammar."
    ), f"got {msg!r}"

    # Independent read: the rejected call must have left no accessPolicy in place at all,
    # not merely returned an error while silently storing the wildcard document anyway.
    rejected_match = _describe_destination(logs, dest_name)
    assert not rejected_match.get("accessPolicy"), (
        f"wildcard principal was rejected but an accessPolicy is present anyway: "
        f"{rejected_match.get('accessPolicy')!r}"
    )

    # Sanity: a normal, scoped principal for the same destination IS accepted.
    scoped_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "logs:PutSubscriptionFilter",
                "Resource": dest["arn"],
            }
        ],
    }
    logs.put_destination_policy(destinationName=dest_name, accessPolicy=json.dumps(scoped_policy))

    # Terminal assertion is an independent read at the destination, not just the fact that
    # the mutating call itself did not raise: confirm the scoped policy actually round-trips.
    accepted_match = _describe_destination(logs, dest_name)
    stored_policy = json.loads(accepted_match["accessPolicy"])
    assert stored_policy == scoped_policy, (
        f"scoped principal was accepted but did not round-trip: stored={stored_policy} "
        f"expected={scoped_policy}"
    )


def _describe_destination(logs, dest_name: str) -> dict:
    resp = logs.describe_destinations(DestinationNamePrefix=dest_name)
    matches = [d for d in resp.get("destinations", []) if d["destinationName"] == dest_name]
    assert len(matches) == 1, f"expected destination {dest_name!r} in DescribeDestinations, got {resp}"
    return matches[0]


def _wait_for_stream_active(kinesis, stream_name: str, timeout_s: float = 60.0) -> str:
    deadline = time.monotonic() + timeout_s
    description = None
    while time.monotonic() < deadline:
        description = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
        if description["StreamStatus"] == "ACTIVE":
            return description["StreamARN"]
        time.sleep(2.0)
    raise AssertionError(f"stream {stream_name!r} did not become ACTIVE within {timeout_s}s: {description!r}")


def _put_destination_with_retry(logs, dest_name: str, target_arn: str, role_arn: str, timeout_s: float = 60.0):
    # A freshly created IAM role can take a few seconds to propagate before
    # CloudWatch Logs can successfully assume it to deliver the test message that
    # PutDestination sends to validate connectivity.
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return logs.put_destination(destinationName=dest_name, targetArn=target_arn, roleArn=role_arn)
        except ClientError as err:
            last_err = err
            time.sleep(3.0)
    raise AssertionError(f"could not create destination {dest_name!r} within {timeout_s}s: {last_err}")


def _delete_role_policy_best_effort(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="allow-kinesis-write")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_best_effort(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a mere mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
