"""destination-duplicate-name-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "destination-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot-managed-integrations"]

# iot-managed-integrations is only available in ca-central-1 / eu-west-1 (see _iot_client
# below); a DeliveryDestinationArn must name the SAME region the service call itself targets,
# or CreateDestination rejects it with ValidationException ("Service region doesn't match
# region in DeliveryDestinationArn").
IOT_REGION = "eu-west-1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateDestination reusing an existing Name is rejected with ConflictException,
    the original destination is untouched, and creating a destination with a distinct name
    still succeeds (positive control)."""
    iot = _iot_client(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = _create_destination_role(ctx, account_id)

    name = ctx.unique_name("sim2real-dest-")
    original_arn = _create_kinesis_stream(ctx, ctx.unique_name("sim2real-stream-a-"))

    _retry_role_propagation(
        lambda: iot.create_destination(
            DeliveryDestinationArn=original_arn,
            DeliveryDestinationType="KINESIS",
            Name=name,
            RoleArn=role_arn,
        )
    )
    ctx.on_cleanup(lambda: _delete_destination_ignore_missing(iot, name))

    conflicting_arn = _create_kinesis_stream(ctx, ctx.unique_name("sim2real-stream-b-"))
    code, code_msg = _error(
        lambda: iot.create_destination(
            DeliveryDestinationArn=conflicting_arn,
            DeliveryDestinationType="KINESIS",
            Name=name,
            RoleArn=role_arn,
        )
    )
    assert code == "ConflictException", code
    assert code_msg == 'Destination already exists', code_msg

    # Effect absent: the original destination's ARN was not overwritten by the conflicting call.
    still_original = iot.get_destination(Name=name)
    assert still_original["DeliveryDestinationArn"] == original_arn

    # Positive control: a distinct name still creates successfully.
    other_name = ctx.unique_name("sim2real-dest-other-")
    other_arn = _create_kinesis_stream(ctx, ctx.unique_name("sim2real-stream-c-"))
    iot.create_destination(
        DeliveryDestinationArn=other_arn,
        DeliveryDestinationType="KINESIS",
        Name=other_name,
        RoleArn=role_arn,
    )
    ctx.on_cleanup(lambda: _delete_destination_ignore_missing(iot, other_name))
    assert iot.get_destination(Name=other_name)["DeliveryDestinationArn"] == other_arn


def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1, so pin the region
    # via ctx.client's `region=` override, which keeps ctx's credentials and endpoint wiring.
    from botocore.config import Config

    return ctx.client(
        "iot-managed-integrations",
        region=IOT_REGION,
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )


def _create_destination_role(ctx, account_id: str) -> str:
    """A real, assumable IAM role for the destination's RoleArn -- IoT Managed Integrations
    assumes this to deliver events to the Kinesis destination, and enforces iam:PassRole
    against it, so a fabricated cross-account ARN is rejected before the check's own subject
    (the duplicate-name conflict) is ever reached."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-dest-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "iotmanagedintegrations.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-kinesis-put",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["kinesis:PutRecord", "kinesis:PutRecords", "kinesis:DescribeStream"],
                        "Resource": f"arn:aws:kinesis:*:{account_id}:stream/*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _delete_role_ignore_missing(iam, role_name))
    return role_arn


def _create_kinesis_stream(ctx, stream_name: str) -> str:
    """CreateDestination validates that DeliveryDestinationArn names a real, existing stream
    (ValidationException otherwise), so the delivery target has to be a real Kinesis stream, not
    just a well-formed ARN."""
    kinesis = ctx.client("kinesis", region=IOT_REGION)
    kinesis.create_stream(StreamName=stream_name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: _delete_stream_ignore_missing(kinesis, stream_name))
    return _wait_stream_active(kinesis, stream_name)


def _wait_stream_active(kinesis, stream_name: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary["StreamARN"]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stream {stream_name} did not reach ACTIVE within {timeout_s}s, "
                f"last status {summary['StreamStatus']}"
            )
        time.sleep(interval_s)


def _delete_stream_ignore_missing(kinesis, stream_name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_role_ignore_missing(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="allow-kinesis-put")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 3.0):
    """IAM is eventually consistent: a role created moments ago may not yet be assumable by
    IoT Managed Integrations. Retry only the specific role/trust-related rejection, bounded by a
    stated deadline -- never an unconditional sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "").lower()
            # The role's inline Kinesis policy propagates separately from the role itself.
            retryable = (code == "AccessDeniedException" and "role" in message) or (
                code == "ValidationException"
                and ("assum" in message or "insufficient permissions" in message)
            )
            if not retryable or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_destination_ignore_missing(iot, name: str) -> None:
    try:
        iot.delete_destination(Name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
