"""notification-configuration-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notification-configuration-lifecycle"
GROUP = "crud-depth"
SERVICES = ["iot-managed-integrations"]

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "iotmanagedintegrations.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

ACCESS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kinesis:PutRecord",
                "kinesis:PutRecords",
                "kinesis:DescribeStream",
                "kinesis:DescribeStreamSummary",
            ],
            "Resource": "*",
        }
    ],
}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iotmi-notification-configuration")
def run(ctx) -> None:
    """CreateNotificationConfiguration referencing a non-existent destination is rejected with
    ValidationException and nothing is created; against a real destination it round-trips and
    UpdateNotificationConfiguration re-points it at a different destination."""
    iot = _iot_client(ctx)

    missing_code, missing_code_msg = _error(
        lambda: iot.create_notification_configuration(
            EventType="DEVICE_STATE", DestinationName="sim2real-bogus-destination-name"
        )
    )
    assert missing_code == "ValidationException", missing_code
    assert missing_code_msg == "Destination doesn't exist", missing_code_msg
    not_created_code, not_created_code_msg = _error(lambda: iot.get_notification_configuration(EventType="DEVICE_STATE"))
    assert not_created_code == "ResourceNotFoundException", not_created_code
    assert not_created_code_msg is None, not_created_code_msg

    dest_a = _create_destination(ctx, iot, "sim2real-dest-a-")
    dest_b = _create_destination(ctx, iot, "sim2real-dest-b-")

    iot.create_notification_configuration(EventType="DEVICE_STATE", DestinationName=dest_a)
    ctx.on_cleanup(lambda: _delete_notification_ignore_missing(iot, "DEVICE_STATE"))

    got = iot.get_notification_configuration(EventType="DEVICE_STATE")
    assert got["DestinationName"] == dest_a

    iot.update_notification_configuration(EventType="DEVICE_STATE", DestinationName=dest_b)
    updated = iot.get_notification_configuration(EventType="DEVICE_STATE")
    assert updated["DestinationName"] == dest_b

    iot.delete_notification_configuration(EventType="DEVICE_STATE")
    deleted_code, deleted_code_msg = _error(lambda: iot.get_notification_configuration(EventType="DEVICE_STATE"))
    assert deleted_code == "ResourceNotFoundException", deleted_code
    assert deleted_code_msg is None, deleted_code_msg
    dead_update_code, dead_update_code_msg = _error(
        lambda: iot.update_notification_configuration(EventType="DEVICE_STATE", DestinationName=dest_a)
    )
    assert dead_update_code == "ResourceNotFoundException", dead_update_code
    assert dead_update_code_msg is None, dead_update_code_msg


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
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_destination(ctx, iot, prefix: str) -> str:
    name = ctx.unique_name(prefix)
    stream_arn = _create_kinesis_stream(ctx, prefix)
    role_arn = _create_delivery_role(ctx, prefix)
    _create_destination_with_retry(iot, name, stream_arn, role_arn)

    def _cleanup():
        try:
            iot.delete_destination(Name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _create_kinesis_stream(ctx, prefix: str) -> str:
    # A real stream — CreateDestination validates the DeliveryDestinationArn against the caller's
    # own account, so a fabricated ARN (a different account id) is rejected outright, never reaching
    # the check's subject. Pinned to match _iot_client's region — CreateDestination rejects a
    # DeliveryDestinationArn whose region doesn't match the service's own.
    kinesis = ctx.client("kinesis", region="eu-west-1")
    name = ctx.unique_name(prefix + "stream-")
    kinesis.create_stream(StreamName=name, ShardCount=1, Tags={"sim2real": "true"})

    def _teardown():
        try:
            kinesis.delete_stream(StreamName=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_teardown)
    return _poll_until(
        lambda: kinesis.describe_stream(StreamName=name)["StreamDescription"],
        lambda d: d["StreamStatus"] == "ACTIVE",
        timeout_s=60,
        interval_s=2,
        description=f"kinesis stream {name} active",
    )["StreamARN"]


def _create_delivery_role(ctx, prefix: str) -> str:
    # Real IAM role Managed Integrations can assume (validated at CreateDestination
    # time, so a fabricated role ARN is not usable, and cross-account PassRole is
    # rejected outright).
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix + "role-")
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        Description="SimParity behavioral fixture role",
    )
    iam.put_role_policy(
        RoleName=name,
        PolicyName="iot-managed-integrations-destination-access",
        PolicyDocument=json.dumps(ACCESS_POLICY),
    )

    def _teardown():
        try:
            for pn in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
                try:
                    iam.delete_role_policy(RoleName=name, PolicyName=pn)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_teardown)
    return resp["Role"]["Arn"]


def _create_destination_with_retry(iot, name: str, stream_arn: str, role_arn: str, timeout_s: int = 60) -> None:
    """Retries while the freshly created IAM role is still propagating (the service
    rejects a brand-new role until it is visible, the same way Firehose does)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.create_destination(
                DeliveryDestinationArn=stream_arn,
                DeliveryDestinationType="KINESIS",
                Name=name,
                RoleArn=role_arn,
            )
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = (e.response["Error"].get("Message") or "").lower()
            propagating = code in ("ValidationException", "AccessDeniedException") and (
                "assume" in msg or "not authorized" in msg or "pass role" in msg or "does not exist" in msg
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_notification_ignore_missing(iot, event_type: str) -> None:
    try:
        iot.delete_notification_configuration(EventType=event_type)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
