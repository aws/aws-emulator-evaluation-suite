"""delete-stream-during-creating-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-stream-during-creating-rejected"
GROUP = "negative-classes"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeliveryStream on a CREATING stream fails with ResourceInUseException and its exact
    message; the stream still reaches ACTIVE, and a delete from ACTIVE then succeeds.

    Reference: https://docs.aws.amazon.com/firehose/latest/APIReference/API_DeleteDeliveryStream.html
    """
    firehose = ctx.client("firehose")
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_s3_role(ctx, bucket)

    # Warm the role up first (retrying past IAM propagation lag) with a throwaway
    # stream, so the CREATING-state race below can't be confused with a role problem.
    warm_name = ctx.unique_name("sim2real-fh-warm-")
    ctx.on_cleanup(lambda: _best_effort_delete(firehose, warm_name))
    _create_active_stream(ctx, firehose, warm_name, role_arn, bucket)

    stream_name = ctx.unique_name("sim2real-fh-delconflict-")
    firehose.create_delivery_stream(
        DeliveryStreamName=stream_name,
        S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket}"},
    )
    ctx.on_cleanup(lambda: _best_effort_delete(firehose, stream_name))

    # No wait: a new stream stays CREATING for tens of seconds.
    desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    assert desc["DeliveryStreamStatus"] == "CREATING", (
        "stream reached ACTIVE before the delete-while-creating race could be observed"
    )
    code, message = _expect_error(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    assert code == "ResourceInUseException", (
        f"expected ResourceInUseException deleting a CREATING stream, got {code!r}: {message!r}"
    )
    expected = (
        f"Firehose {stream_name} under account {ctx.account} cannot be deleted in CREATING state"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    active_desc = _wait_for_stream_status(ctx, firehose, stream_name, {"ACTIVE"})
    assert active_desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"expected the rejected-delete stream to still reach ACTIVE, got "
        f"{active_desc['DeliveryStreamStatus']!r}"
    )

    firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
    deadline = time.monotonic() + 300.0
    while True:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=stream_name)
        except ClientError as e:
            nf_code = e.response["Error"]["Code"]
            nf_message = e.response["Error"].get("Message")
            break
        if time.monotonic() >= deadline:
            raise AssertionError("delivery stream was never removed after a delete from ACTIVE")
        time.sleep(3)
    assert nf_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException describing the deleted stream, got {nf_code!r}: {nf_message!r}"
    )
    expected_nf = f"Firehose under account {ctx.account} not found."
    assert nf_message == expected_nf, f"expected message {expected_nf!r}, got {nf_message!r}"


def _expect_error(fn):
    """Call fn(), which must fail; return (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-").lower()
    kwargs = {"Bucket": name}
    # S3 CreateBucket rejects a LocationConstraint of us-east-1.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_firehose_s3_role(ctx, bucket_name):
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
    policy_name = ctx.unique_name("sim2real-fh-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:AbortMultipartUpload",
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:PutObject",
                ],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _wait_for_stream_status(ctx, firehose, name, target_statuses, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        last = desc["DeliveryStreamStatus"]
        if last in target_statuses:
            return desc
        time.sleep(3)
    raise AssertionError(f"stream {name} never reached {target_statuses}, last status={last}")


def _create_active_stream(ctx, firehose, name, role_arn, bucket_name, buffering=None):
    s3_config = {"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket_name}"}
    if buffering:
        s3_config["BufferingHints"] = buffering
    deadline = time.monotonic() + 90.0
    while True:
        try:
            firehose.create_delivery_stream(DeliveryStreamName=name, S3DestinationConfiguration=s3_config)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    return _wait_for_stream_status(ctx, firehose, name, {"ACTIVE"})


def _best_effort_delete(firehose, name):
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
