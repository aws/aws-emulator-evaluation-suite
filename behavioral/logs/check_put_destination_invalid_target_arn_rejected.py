"""put-destination-invalid-target-arn-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-destination-invalid-target-arn-rejected"
GROUP = 'overly-permissive'
SERVICES = ['logs']

def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutDestination with a malformed targetArn fails with InvalidParameterException and creates
    nothing, while a real Kinesis target and role still succeed afterward.
    """
    logs = ctx.client("logs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    dest_name = ctx.unique_name("sim2real-behav-dest-bad-")
    # Registered even though the call is expected to be refused, in case it is accepted.
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: logs.delete_destination(destinationName=dest_name)))
    role_arn = f"arn:aws:iam::{account_id}:role/FidelityTestRole"
    code, msg = _error(
        lambda: logs.put_destination(
            destinationName=dest_name, targetArn="not-an-arn", roleArn=role_arn
        )
    )
    assert code == "InvalidParameterException", f"got {code!r}"
    assert msg == "Error parsing ARN from given role or target", f"got {msg!r}"

    found = logs.describe_destinations(DestinationNamePrefix=dest_name).get("destinations", [])
    assert found == [], f"destination created despite invalid targetArn: {found}"

    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")

    stream_name = ctx.unique_name("sim2real-behav-dest-stream-")
    kinesis.create_stream(
        StreamName=stream_name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    stream_arn = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"],
        lambda desc: desc["StreamStatus"] == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )["StreamARN"]

    role_name = ctx.unique_name("sim2real-behav-dest-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    good_role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "put-records"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
                        "Resource": stream_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    good_dest_name = ctx.unique_name("sim2real-behav-dest-good-")

    def _put_good_destination():
        return logs.put_destination(
            destinationName=good_dest_name,
            targetArn=stream_arn,
            roleArn=good_role_arn,
            tags={"sim2real": CHECK},
        )

    # New IAM roles are eventually consistent; retry through the propagation window.
    _retry_on_code(_put_good_destination, "InvalidParameterException", attempts=10, delay_s=3)
    ctx.on_cleanup(lambda: logs.delete_destination(destinationName=good_dest_name))

    described = logs.describe_destinations(DestinationNamePrefix=good_dest_name).get("destinations", [])
    matched = [d for d in described if d["destinationName"] == good_dest_name]
    assert matched, f"valid destination not visible in DescribeDestinations: {described}"
    assert matched[0]["targetArn"] == stream_arn, (
        f"expected targetArn {stream_arn}, got {matched[0]['targetArn']}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _retry_on_code(fn, code: str, *, attempts: int = 5, delay_s: float = 2.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != code:
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _ignore_not_found(fn):
    """Teardown wrapper that tolerates the resource already being gone."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
