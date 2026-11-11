"""update-destination-invalid-destination-id."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-destination-invalid-destination-id"
GROUP = "error-semantics"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDestination referencing a DestinationId that does not exist on the stream is
    refused with InvalidArgumentException and leaves the stream's VersionId unchanged, while
    updating the real DestinationId (positive control) succeeds and increments VersionId."""
    role_arn = _iam_role_for_firehose(ctx)
    _bucket_name, bucket_arn = _s3_bucket(ctx)
    firehose = ctx.client("firehose")

    stream_name = ctx.unique_name("sim2real-fh-upd-")
    _create_stream_retrying_role_propagation(ctx, firehose, stream_name, role_arn, bucket_arn)
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    desc0 = _wait_stream_active(ctx, stream_name)
    real_destination_id = desc0["Destinations"][0]["DestinationId"]
    version_id_0 = desc0["VersionId"]

    # Positive control: updating the real destination with the matching version succeeds
    # and increments VersionId, and the new buffering hint is reflected.
    firehose.update_destination(
        DeliveryStreamName=stream_name,
        CurrentDeliveryStreamVersionId=version_id_0,
        DestinationId=real_destination_id,
        ExtendedS3DestinationUpdate={"BufferingHints": {"IntervalInSeconds": 120, "SizeInMBs": 2}},
    )
    desc1 = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    version_id_1 = desc1["VersionId"]
    assert version_id_1 != version_id_0, (
        f"expected VersionId to advance past {version_id_0} after a valid UpdateDestination, "
        f"still {version_id_1}"
    )
    interval_1 = desc1["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"][
        "IntervalInSeconds"
    ]
    assert interval_1 == 120, f"expected the positive control's IntervalInSeconds=120 to apply, got {interval_1}"

    # Negative: an unknown DestinationId is refused and must not bump VersionId.
    bogus_destination_id = "destinationId-999999"
    try:
        firehose.update_destination(
            DeliveryStreamName=stream_name,
            CurrentDeliveryStreamVersionId=version_id_1,
            DestinationId=bogus_destination_id,
            ExtendedS3DestinationUpdate={"BufferingHints": {"IntervalInSeconds": 180, "SizeInMBs": 3}},
        )
    except ClientError as e:
        err = e.response["Error"]
        assert err["Code"] == "InvalidArgumentException", f"expected InvalidArgumentException, got {err!r}"
        expected_msg = f"Destination Id {bogus_destination_id} not found"
        assert err.get("Message") == expected_msg, (
            f"expected message {expected_msg!r}, got {err.get('Message')!r}"
        )
    else:
        raise AssertionError("expected InvalidArgumentException for an unknown DestinationId")

    desc2 = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    assert desc2["VersionId"] == version_id_1, (
        f"expected the rejected update to leave VersionId at {version_id_1}, now {desc2['VersionId']}"
    )
    interval_2 = desc2["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"][
        "IntervalInSeconds"
    ]
    assert interval_2 == 120, (
        f"expected the rejected update to leave IntervalInSeconds at 120, got {interval_2}"
    )


def _iam_role_for_firehose(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:*", "kinesis:*", "kms:*"], "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-fh-inline", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-fh-inline"))
    return role_arn


def _create_stream_retrying_role_propagation(
    ctx, firehose, stream_name: str, role_arn: str, bucket_arn: str, timeout_s: float = 60.0
) -> None:
    """CreateDeliveryStream fails with InvalidArgumentException while the new IAM role has
    not yet propagated to Firehose's assume-role check; retry on that specific signal only,
    bounded by a deadline, rather than guessing a fixed sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream_name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=_basic_s3_dest(bucket_arn, role_arn),
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "").lower()
            propagating = code == "InvalidArgumentException" and (
                "assume" in msg or "not authorized" in msg or "does not exist" in msg
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _s3_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        # us-east-1 is S3's legacy default region and CreateBucket rejects an explicit
        # LocationConstraint naming it; every other region requires the constraint.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name, f"arn:aws:s3:::{name}"


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_object_versions(Bucket=name)
    objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in resp.get("Versions", [])]
    objs += [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in resp.get("DeleteMarkers", [])]
    if objs:
        failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _basic_s3_dest(bucket_arn: str, role_arn: str) -> dict:
    return {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
    }


def _wait_stream_active(ctx, name: str, timeout_s: float = 300.0) -> dict:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(
                f"delivery stream {name} entered CREATING_FAILED: {desc.get('FailureDescription')}"
            )
        time.sleep(5)
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
