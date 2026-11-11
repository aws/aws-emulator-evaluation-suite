"""put-destination-policy-then-describe."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "put-destination-policy-then-describe"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDestinationPolicy attaches an access policy to an existing destination, reflected
    on subsequent DescribeDestinations calls."""

    # PutDestination delivers a test message to the target and rejects an unwritable one with
    # InvalidParameterException, so a real stream and role are provisioned (retrying past IAM
    # propagation) before the destination is created.
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-destpol-")
    stream_name = ctx.unique_name("sim2real-destpolstream-")
    role_name = ctx.unique_name("sim2real-destpolrole-")

    kinesis.create_stream(
        StreamName=stream_name,
        ShardCount=1,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kinesis.delete_stream(StreamName=stream_name)))
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup_role():
        _ignore_not_found(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-destpolpolicy"))
        _ignore_not_found(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup_role)

    stream_access_policy = {
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
        PolicyName="sim2real-destpolpolicy",
        PolicyDocument=json.dumps(stream_access_policy),
    )

    dest = _retry_on_error(
        lambda: logs.put_destination(
            destinationName=name,
            targetArn=target_arn,
            roleArn=role_arn,
            tags={"sim2real-check": CHECK},
        ),
        retriable_codes={"InvalidParameterException", "AccessDeniedException"},
        timeout_s=90,
        interval_s=5,
    )["destination"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: logs.delete_destination(destinationName=name))
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PermitSubFilter",
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "logs:PutSubscriptionFilter",
                "Resource": dest["arn"],
            }
        ],
    }
    logs.put_destination_policy(destinationName=name, accessPolicy=json.dumps(policy))

    resp = logs.describe_destinations(DestinationNamePrefix=name)
    matches = [d for d in resp.get("destinations", []) if d["destinationName"] == name]
    assert len(matches) == 1, f"expected destination {name} in DescribeDestinations, got {resp}"
    match = matches[0]
    assert match.get("accessPolicy"), "expected accessPolicy to be populated after PutDestinationPolicy"

    got_policy = json.loads(match["accessPolicy"])
    statement = got_policy["Statement"][0]
    assert statement["Action"] == "logs:PutSubscriptionFilter", (
        f"expected Action 'logs:PutSubscriptionFilter', got {statement.get('Action')!r}"
    )
    assert statement["Resource"] == dest["arn"], (
        f"expected Resource {dest['arn']!r}, got {statement.get('Resource')!r}"
    )
    assert statement["Principal"]["AWS"] == account_id, (
        f"expected Principal.AWS {account_id!r}, got {statement.get('Principal')!r}"
    )


# ===== helpers =====
def _ignore_not_found(fn):
    """Run a teardown delete; an already-deleted resource is fine, any other error raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") not in ("ResourceNotFoundException", "NoSuchEntity"):
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
