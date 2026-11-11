"""delete-metric-stream-status-immediately-absent-from-list."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "delete-metric-stream-status-immediately-absent-from-list"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Immediately after DeleteMetricStream, ListMetricStreams excludes it and GetMetricStream 404s."""
    cw = ctx.client("cloudwatch")
    infra = _provision_metric_stream(ctx)
    stream_name = infra["stream_name"]

    # Sanity: it exists and is running before we delete it.
    got = cw.get_metric_stream(Name=stream_name)
    assert got["Name"] == stream_name, f"expected GetMetricStream Name={stream_name!r}, got {got['Name']!r}"
    assert got["State"] == "running", (
        f"expected metric stream {stream_name} to be running before delete, got State={got['State']!r}"
    )

    cw.delete_metric_stream(Name=stream_name)
    infra["deleted"]["done"] = True

    # Read-after-write: no eventual-consistency lag expected, poll only as a small safety margin.
    names_after_delete = None
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        names_after_delete = _list_all_metric_stream_names(cw)
        if stream_name not in names_after_delete:
            break
        time.sleep(1.0)
    assert stream_name not in (names_after_delete or []), (
        f"ListMetricStreams still contains deleted stream {stream_name}"
    )

    code, message = _error(lambda: cw.get_metric_stream(Name=stream_name))
    assert code == "ResourceNotFoundException", (
        f"expected GetMetricStream on deleted stream {stream_name} to raise "
        f"ResourceNotFoundException, got {code!r}"
    )
    expected_message = ""  # real AWS returns an empty Message for this code
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its ClientError code. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _list_all_metric_stream_names(cw) -> list[str]:
    names: list[str] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {}
        if token:
            kwargs["NextToken"] = token
        resp = cw.list_metric_streams(**kwargs)
        names.extend(e["Name"] for e in resp.get("Entries", []))
        token = resp.get("NextToken")
        if not token:
            break
    return names


def _provision_metric_stream(ctx) -> dict[str, Any]:
    """Create S3 bucket + two IAM roles + a Firehose delivery stream + a CloudWatch metric
    stream, and register cleanup for all of it. Returns dict with stream_name and a mutable
    'deleted' flag the caller sets once it has deleted the metric stream itself (so cleanup
    does not try to delete it twice)."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")
    cw = ctx.client("cloudwatch")

    bucket_name = ctx.unique_name("sim2real-behav-cwms-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    firehose_role_name = ctx.unique_name("sim2real-behav-fh-role-")
    firehose_role = iam.create_role(
        RoleName=firehose_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "firehose.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=firehose_role_name))
    iam.put_role_policy(
        RoleName=firehose_role_name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {
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
                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=firehose_role_name, PolicyName="s3-access"))

    delivery_stream_name = ctx.unique_name("sim2real-behav-fhstream-")
    deadline = time.monotonic() + 90.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=delivery_stream_name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={"RoleARN": firehose_role["Arn"], "BucketARN": bucket_arn},
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )
            last_exc = None
            break
        except Exception as exc:  # noqa: BLE001 - broad retry on IAM propagation delay
            last_exc = exc
            time.sleep(3.0)
    if last_exc is not None:
        raise last_exc
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=delivery_stream_name))


    delivery_stream_arn = None
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=delivery_stream_name)[
            "DeliveryStreamDescription"
        ]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            delivery_stream_arn = desc["DeliveryStreamARN"]
            break
        time.sleep(3.0)
    assert delivery_stream_arn, "Firehose delivery stream never became ACTIVE"

    metric_role_name = ctx.unique_name("sim2real-behav-cwms-role-")
    metric_role = iam.create_role(
        RoleName=metric_role_name,
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=metric_role_name))
    iam.put_role_policy(
        RoleName=metric_role_name,
        PolicyName="firehose-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["firehose:PutRecord", "firehose:PutRecordBatch", "firehose:DescribeDeliveryStream"],
                        "Resource": delivery_stream_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=metric_role_name, PolicyName="firehose-access"))

    stream_name = ctx.unique_name("sim2real-behav-metricstream-")
    deleted = {"done": False}
    ctx.on_cleanup(lambda: None if deleted["done"] else cw.delete_metric_stream(Name=stream_name))

    # New IAM role/policy may not be immediately usable by the CloudWatch service; retry.
    deadline = time.monotonic() + 90.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cw.put_metric_stream(
                Name=stream_name,
                FirehoseArn=delivery_stream_arn,
                RoleArn=metric_role["Arn"],
                OutputFormat="json",
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )
            last_exc = None
            break
        except Exception as exc:  # noqa: BLE001 - broad retry on IAM propagation delay
            last_exc = exc
            time.sleep(3.0)
    if last_exc is not None:
        raise last_exc

    state = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        state = cw.get_metric_stream(Name=stream_name)["State"]
        if state == "running":
            break
        time.sleep(2.0)
    assert state == "running", f"metric stream never reached running state, last state={state}"

    return {"stream_name": stream_name, "deleted": deleted}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
