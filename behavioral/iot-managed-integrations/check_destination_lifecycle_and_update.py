"""destination-lifecycle-and-update."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "destination-lifecycle-and-update"
GROUP = "crud-depth"
SERVICES = ["iot-managed-integrations"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDestination/GetDestination/UpdateDestination/DeleteDestination round-trip and
    persist field changes; the destination is left both gone (independent read) and unusable
    (a mutation on the dead name also fails) after delete."""
    iot = _iot_client(ctx)
    stream_arn = _create_stream(ctx)
    role_arn = _create_destination_role(ctx, stream_arn)
    name = ctx.unique_name("sim2real-dest-")

    _retry_transient(
        lambda: iot.create_destination(
            DeliveryDestinationArn=stream_arn,
            DeliveryDestinationType="KINESIS",
            Name=name,
            RoleArn=role_arn,
            Description="initial description",
        )
    )
    ctx.on_cleanup(lambda: _delete_destination_ignore_missing(iot, name))

    got = iot.get_destination(Name=name)
    assert got["DeliveryDestinationArn"] == stream_arn
    assert got["Description"] == "initial description"

    iot.update_destination(Name=name, Description="updated description")
    updated = iot.get_destination(Name=name)
    assert updated["Description"] == "updated description"
    assert updated["DeliveryDestinationArn"] == stream_arn

    iot.delete_destination(Name=name)
    code, code_msg = _error(lambda: iot.get_destination(Name=name))
    assert code == "ResourceNotFoundException", code
    assert code_msg == "", code_msg  # AWS answers this refusal with a null message

    # The dead name is also unusable for a mutation, not just for a read.
    update_code, update_code_msg = _error(lambda: iot.update_destination(Name=name, Description="post-delete"))
    assert update_code == "ResourceNotFoundException", update_code
    assert update_code_msg == "", update_code_msg


def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1, so pin the region
    # via ctx.client's `region=` override, which keeps ctx's credentials and endpoint wiring.
    return ctx.client("iot-managed-integrations", region="eu-west-1")
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message") or ""
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_destination_ignore_missing(iot, name: str) -> None:
    try:
        iot.delete_destination(Name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_stream(ctx) -> str:
    # Match the iot-managed-integrations client's region pin (see _iot_client) so the
    # stream lives alongside the service that will assume the role to write to it.
    kinesis = ctx.client("kinesis", region="eu-west-1")
    name = ctx.unique_name("sim2real-dest-stream-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": CHECK},
    )

    def _cleanup():
        try:
            kinesis.delete_stream(StreamName=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return _poll_until(
        lambda: kinesis.describe_stream(StreamName=name)["StreamDescription"],
        lambda d: d["StreamStatus"] == "ACTIVE",
        timeout_s=120.0,
        interval_s=3.0,
    )["StreamARN"]


def _create_destination_role(ctx, stream_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-dest-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "iotmanagedintegrations.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["kinesis:PutRecord", "kinesis:PutRecords", "kinesis:DescribeStream"],
                "Resource": stream_arn,
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="kinesis-put", PolicyDocument=json.dumps(policy))

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="kinesis-put")
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _retry_transient(fn, timeout_s=60.0, interval_s=5.0):
    """A freshly created role/policy can lag briefly before iot-managed-integrations
    honours it; poll the actual downstream call instead of sleeping a fixed duration."""
    import time

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
