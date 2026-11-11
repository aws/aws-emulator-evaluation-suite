"""destination-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "destination-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDestination creates a cross-account destination visible in DescribeDestinations,
    accepts a policy via PutDestinationPolicy, and disappears after DeleteDestination."""
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    stream_name = ctx.unique_name("sim2real-dest-stream-")
    kinesis.create_stream(
        StreamName=stream_name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
            "StreamStatus"
        ],
        lambda status: status == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
        "StreamARN"
    ]

    role_name = ctx.unique_name("sim2real-dest-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    role_arn = role["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    inline_policy_name = "put-records"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
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
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name))

    destination_name = ctx.unique_name("sim2real-destination-")

    def _put_destination():
        return logs.put_destination(
            destinationName=destination_name,
            targetArn=stream_arn,
            roleArn=role_arn,
            tags={"sim2real": CHECK},
        )

    # New IAM roles are eventually consistent; retry through the propagation window.
    put_resp = _retry_on_code(_put_destination, "InvalidParameterException", attempts=10, delay_s=3)
    ctx.on_cleanup(lambda: _delete_if_present(lambda: logs.delete_destination(destinationName=destination_name)))
    assert put_resp["destination"]["destinationName"] == destination_name
    assert put_resp["destination"]["targetArn"] == stream_arn

    described = logs.describe_destinations(DestinationNamePrefix=destination_name)
    names = [d["destinationName"] for d in described.get("destinations", [])]
    assert destination_name in names, f"{destination_name} not in {names}"

    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOwnAccountSubscribe",
                "Effect": "Allow",
                # PutDestinationPolicy requires the Principal to be a bare account ID, not an
                # IAM ARN like "arn:aws:iam::<id>:root".
                "Principal": {"AWS": account_id},
                "Action": "logs:PutSubscriptionFilter",
                "Resource": put_resp["destination"]["arn"],
            }
        ],
    }
    logs.put_destination_policy(
        destinationName=destination_name, accessPolicy=json.dumps(access_policy)
    )
    described_after_policy = logs.describe_destinations(DestinationNamePrefix=destination_name)
    matched = [d for d in described_after_policy["destinations"] if d["destinationName"] == destination_name]
    assert matched, "destination disappeared after PutDestinationPolicy"
    stored_policy_raw = matched[0].get("accessPolicy")
    assert stored_policy_raw, "accessPolicy not reflected on destination"
    stored_statement = json.loads(stored_policy_raw)["Statement"][0]
    assert stored_statement["Action"] == "logs:PutSubscriptionFilter", stored_statement
    assert stored_statement["Resource"] == put_resp["destination"]["arn"], stored_statement
    assert stored_statement["Principal"]["AWS"] == account_id, stored_statement

    logs.delete_destination(destinationName=destination_name)

    for _ in range(10):
        remaining = logs.describe_destinations(DestinationNamePrefix=destination_name)
        if destination_name not in [d["destinationName"] for d in remaining.get("destinations", [])]:
            break
        time.sleep(1.0)
    else:
        raise AssertionError("destination still visible after DeleteDestination")

    from botocore.exceptions import ClientError

    try:
        logs.delete_destination(destinationName=destination_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        message = exc.response["Error"].get("Message", "")
        expected = "The specified destination does not exist."
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError("DeleteDestination on an already-deleted destination did not fail")


def _delete_if_present(fn):
    """Teardown for a resource the check itself deletes: an already-gone resource is fine."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    from botocore.exceptions import ClientError

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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
