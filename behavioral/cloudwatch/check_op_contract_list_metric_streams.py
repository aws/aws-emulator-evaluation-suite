"""op-contract-listMetricStreams."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-listMetricStreams"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListMetricStreams surfaces a created metric stream with its config; a garbage NextToken is rejected."""
    cw = ctx.client("cloudwatch")
    infra = _provision_metric_stream_infra(ctx)
    stream_name = ctx.unique_name("sim2real-cwms-list-")
    _put_metric_stream_with_retry(
        ctx,
        Name=stream_name,
        FirehoseArn=infra["firehose_arn"],
        RoleArn=infra["role_arn"],
        OutputFormat="json",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=stream_name))

    entries = _poll_until(
        lambda: cw.list_metric_streams().get("Entries", []),
        lambda entries: any(e["Name"] == stream_name for e in entries),
        timeout_s=30,
    )
    match = next((e for e in entries if e["Name"] == stream_name), None)
    assert match is not None, f"stream {stream_name} not found in ListMetricStreams entries {entries}"
    assert match["FirehoseArn"] == infra["firehose_arn"], (
        f"expected FirehoseArn {infra['firehose_arn']!r}, got {match['FirehoseArn']!r}"
    )
    assert match["OutputFormat"] == "json", f"expected OutputFormat 'json', got {match['OutputFormat']!r}"
    assert match["State"] == "running", f"expected State 'running', got {match['State']!r}"

    err, message = _error(lambda: cw.list_metric_streams(NextToken="garbage-not-a-token"))
    assert err == "InvalidNextToken", f"expected InvalidNextToken, got {err}"
    assert message == "Invalid NextToken", f"expected the exact message 'Invalid NextToken', got {message!r}"


def _provision_metric_stream_infra(ctx) -> dict:
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    bucket = ctx.unique_name("sim2real-cwms-list-b-")
    if ctx.region == "us-east-1":
        # us-east-1 rejects a LocationConstraint on CreateBucket; this is the S3 API's
        # own region-pinned quirk, not a hardcoded target region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    fh_role_name = ctx.unique_name("sim2real-cwms-list-fhrole-")
    fh_role = iam.create_role(
        RoleName=fh_role_name,
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
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=fh_role_name))
    iam.put_role_policy(
        RoleName=fh_role_name,
        PolicyName="s3-write",
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
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=fh_role_name, PolicyName="s3-write"))

    stream_name = ctx.unique_name("sim2real-cwms-list-fh-")
    deadline = time.monotonic() + 90
    last_exc = None
    created = False
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream_name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={
                    "RoleARN": fh_role["Arn"],
                    "BucketARN": f"arn:aws:s3:::{bucket}",
                },
            )
            created = True
            break
        except Exception as exc:  # noqa: BLE001 - IAM propagation retry
            last_exc = exc
            time.sleep(5)
    if not created:
        raise AssertionError(f"could not create delivery stream: {last_exc}")
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    firehose_arn = _wait_firehose_active(ctx, stream_name)

    cw_role_name = ctx.unique_name("sim2real-cwms-list-cwrole-")
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
        PolicyName="firehose-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                        "Resource": firehose_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=cw_role_name, PolicyName="firehose-write"))

    return {"firehose_arn": firehose_arn, "role_arn": cw_role["Arn"]}


def _wait_firehose_active(ctx, stream_name, timeout_s=120.0) -> str:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
            "DeliveryStreamDescription"
        ]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return desc["DeliveryStreamARN"]
        time.sleep(3)
    raise AssertionError(f"delivery stream {stream_name} never became ACTIVE")


def _empty_and_delete_bucket(ctx, bucket) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        objects = resp.get("Contents", [])
        if objects:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objects]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _put_metric_stream_with_retry(ctx, *, timeout_s=90.0, **kwargs):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cw.put_metric_stream(**kwargs)
        except Exception as exc:  # noqa: BLE001 - IAM/role trust propagation retry
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"put_metric_stream never succeeded: {last_exc}")


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
