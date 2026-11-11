"""get-metric-stream-and-notfound-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "get-metric-stream-and-notfound-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetMetricStream returns the exact FirehoseArn/RoleArn/OutputFormat/State
    that PutMetricStream configured, and is rejected with
    ResourceNotFoundException for a metric stream name that was never created."""
    cw = ctx.client("cloudwatch")
    infra = _create_metric_stream_infra(ctx)
    stream_name = ctx.unique_name("sim2real-behav-ms-")

    _put_metric_stream_with_retry(ctx, stream_name, infra["firehose_arn"], infra["role_arn"])
    ctx.on_cleanup(lambda: _safe_delete_metric_stream(ctx, stream_name))

    got = cw.get_metric_stream(Name=stream_name)
    assert got["Name"] == stream_name, f"expected Name={stream_name!r}, got {got['Name']!r}"
    assert got["FirehoseArn"] == infra["firehose_arn"], (
        f"expected FirehoseArn={infra['firehose_arn']!r}, got {got['FirehoseArn']!r}"
    )
    assert got["RoleArn"] == infra["role_arn"], f"expected RoleArn={infra['role_arn']!r}, got {got['RoleArn']!r}"
    assert got["OutputFormat"] == "json", f"expected OutputFormat='json', got {got['OutputFormat']!r}"
    assert got["State"] == "running", f"expected State='running', got {got['State']!r}"
    assert got["Arn"].endswith(f"metric-stream/{stream_name}"), (
        f"expected Arn to end with 'metric-stream/{stream_name}', got {got['Arn']!r}"
    )

    # Error boundary: a metric stream name that was never created is rejected.
    bogus_name = ctx.unique_name("sim2real-behav-ms-missing-")
    code, message = _error_code(lambda: cw.get_metric_stream(Name=bogus_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    # AWS returns this code with no message text.
    assert message == "", f"expected an empty message, got {message!r}"


# ===== helpers =====

def _create_metric_stream_infra(ctx: Any) -> dict[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")

    bucket = ctx.unique_name("sim2real-behav-cwms-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    fh_role_name = ctx.unique_name("sim2real-behav-fhrole-")
    fh_role = iam.create_role(
        RoleName=fh_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=fh_role_name))
    iam.put_role_policy(
        RoleName=fh_role_name,
        PolicyName="s3access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=fh_role_name, PolicyName="s3access"))

    delivery_stream_name = ctx.unique_name("sim2real-behav-fh-")
    _create_delivery_stream_with_retry(
        ctx, delivery_stream_name, fh_role["Arn"], f"arn:aws:s3:::{bucket}"
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=delivery_stream_name))
    _wait_delivery_stream_active(ctx, delivery_stream_name)
    fh_arn = firehose.describe_delivery_stream(DeliveryStreamName=delivery_stream_name)[
        "DeliveryStreamDescription"
    ]["DeliveryStreamARN"]

    cw_role_name = ctx.unique_name("sim2real-behav-cwrole-")
    cw_role = iam.create_role(
        RoleName=cw_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=cw_role_name))
    iam.put_role_policy(
        RoleName=cw_role_name,
        PolicyName="firehoseaccess",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"], "Resource": fh_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=cw_role_name, PolicyName="firehoseaccess"))

    return {"firehose_arn": fh_arn, "role_arn": cw_role["Arn"]}


def _create_delivery_stream_with_retry(
    ctx: Any, name: str, role_arn: str, bucket_arn: str, timeout_s: float = 90.0
) -> None:
    """Firehose needs a few seconds after CreateRole/PutRolePolicy before it can
    successfully assume the new role; retry CreateDeliveryStream on the
    InvalidArgumentException it raises while that IAM propagation is pending."""
    from botocore.exceptions import ClientError

    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
            )
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            last_err = e
            time.sleep(3)
    raise AssertionError(f"CreateDeliveryStream never succeeded (likely IAM propagation): {last_err}")


def _wait_delivery_stream_active(ctx: Any, name: str, timeout_s: float = 90.0) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"][
            "DeliveryStreamStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} never reached ACTIVE within {timeout_s}s")


def _put_metric_stream_with_retry(
    ctx: Any, name: str, firehose_arn: str, role_arn: str, timeout_s: float = 60.0
) -> None:
    from botocore.exceptions import ClientError

    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            cw.put_metric_stream(Name=name, FirehoseArn=firehose_arn, RoleArn=role_arn, OutputFormat="json")
            return
        except ClientError as e:
            last_err = e
            time.sleep(3)
    raise AssertionError(f"PutMetricStream never succeeded (likely IAM propagation): {last_err}")


def _empty_and_delete_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    if objects:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objects]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _safe_delete_metric_stream(ctx: Any, name: str) -> None:
    """DeleteMetricStream of an already-deleted name succeeds, so any error is a real failure."""
    ctx.client("cloudwatch").delete_metric_stream(Name=name)


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so a
    target accepting a call AWS refuses is reported as such rather than as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
