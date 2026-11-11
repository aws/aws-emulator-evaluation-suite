"""put-destination-then-get."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
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


def _create_subscription_destination(ctx, tag):
    """Create a REAL, ACTIVE Kinesis stream plus a REAL IAM role trusting
    logs.amazonaws.com that can kinesis:PutRecord into it. CloudWatch Logs
    validates same-account Kinesis targets SYNCHRONOUSLY by delivering a test
    record, so both must be genuinely reachable. Returns (stream_arn, role_arn);
    both are registered for cleanup."""
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    stream_name = ctx.unique_name(f"sim2real-behav-kstream-{tag}-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1, Tags={"sim2real": "true"})
    ctx.on_cleanup(
        lambda _n=stream_name: kinesis.delete_stream(StreamName=_n, EnforceConsumerDeletion=True)
    )
    _poll_until(
        lambda: kinesis.describe_stream(StreamName=stream_name)["StreamDescription"],
        lambda d: d["StreamStatus"] == "ACTIVE",
        timeout_s=90,
        interval_s=2.0,
        description=f"Kinesis stream {stream_name} becomes ACTIVE",
    )
    stream_arn = f"arn:aws:kinesis:{ctx.region}:{account}:stream/{stream_name}"

    role_name = ctx.unique_name(f"sim2real-behav-role-{tag}-")
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    def _teardown_role(rn=role_name, _iam=iam):
        try:
            _iam.delete_role_policy(RoleName=rn, PolicyName="allow-put-record")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        _iam.delete_role(RoleName=rn)

    ctx.on_cleanup(_teardown_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-put-record",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "kinesis:PutRecord", "Resource": stream_arn}
                ],
            }
        ),
    )
    role_arn = f"arn:aws:iam::{account}:role/{role_name}"
    return stream_arn, role_arn


CHECK = "put-destination-then-get"
GROUP = 'destinations'
SERVICES = ['logs']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDestination plus PutDestinationPolicy create an accessible cross-account
    destination visible via DescribeDestinations and removable via DeleteDestination."""
    svc = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    dest_name = ctx.unique_name("sim2real-behav-dest-")
    # CloudWatch Logs validates a same-account Kinesis target SYNCHRONOUSLY by
    # delivering a test record, so the stream + role must be real.
    target_arn, role_arn = _create_subscription_destination(ctx, "dest")

    _retry_on_invalid_parameter(
        lambda: svc.put_destination(
            destinationName=dest_name, targetArn=target_arn, roleArn=role_arn
        )
    )
    ctx.on_cleanup(lambda _n=dest_name: _ignore_not_found(lambda: svc.delete_destination(destinationName=_n)))

    desc = svc.describe_destinations(DestinationNamePrefix=dest_name)
    dests = desc.get("destinations", [])
    assert len(dests) == 1 and dests[0]["destinationName"] == dest_name, (
        f"expected exactly 1 destination named {dest_name!r}, got {dests!r}"
    )
    assert dests[0]["targetArn"] == target_arn
    assert dests[0]["roleArn"] == role_arn, f"expected roleArn {role_arn!r}, got {dests[0]!r}"

    destination_arn = f"arn:aws:logs:{ctx.region}:{account}:destination:{dest_name}"
    access_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": account},
                    "Action": "logs:PutSubscriptionFilter",
                    "Resource": destination_arn,
                }
            ],
        }
    )
    svc.put_destination_policy(destinationName=dest_name, accessPolicy=access_policy)
    desc_after_policy = svc.describe_destinations(DestinationNamePrefix=dest_name)
    reflected_raw = desc_after_policy["destinations"][0].get("accessPolicy")
    assert reflected_raw, "access policy not reflected"
    reflected = json.loads(reflected_raw)
    reflected_stmt = reflected["Statement"][0]
    assert reflected_stmt["Action"] == "logs:PutSubscriptionFilter", (
        f"expected Action logs:PutSubscriptionFilter, got {reflected_stmt!r}"
    )
    assert reflected_stmt["Resource"] == destination_arn, (
        f"expected Resource {destination_arn!r}, got {reflected_stmt!r}"
    )
    assert reflected_stmt["Principal"]["AWS"] == account, (
        f"expected Principal.AWS {account!r}, got {reflected_stmt!r}"
    )

    svc.delete_destination(destinationName=dest_name)
    desc_final = svc.describe_destinations(DestinationNamePrefix=dest_name)
    assert desc_final.get("destinations", []) == [], "destination still listed after delete"

    try:
        svc.put_destination_policy(destinationName=dest_name, accessPolicy=access_policy)
        raise AssertionError("PutDestinationPolicy on a deleted destination unexpectedly succeeded")
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got_err = (err.get("Code"), err.get("Message"))
        # Measured on real AWS: PutDestinationPolicy on a destination name that no longer
        # exists reports InvalidParameterException, not ResourceNotFoundException.
        assert got_err == ("InvalidParameterException", f"Destination with name {dest_name} does not exist"), (
            f"expected InvalidParameterException for PutDestinationPolicy on deleted "
            f"destination {dest_name!r}, got {got_err!r}"
        )


def _ignore_not_found(fn):
    """Teardown wrapper: the check deletes this resource itself, so a teardown that finds it
    already gone is the expected outcome, not a leak."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
