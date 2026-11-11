"""op-contract-listMetricStreams-state-visibility."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listMetricStreams-state-visibility"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListMetricStreams Entries track a stream's state ('running', then 'stopped' after
    StopMetricStreams), and an invalid NextToken is rejected with InvalidNextToken."""
    cw = ctx.client("cloudwatch")
    stream_name, firehose_arn = _create_running_metric_stream(ctx)

    entry = _find_entry(cw, stream_name)
    assert entry is not None, f"metric stream {stream_name!r} not found in ListMetricStreams"
    assert entry["State"] == "running", entry["State"]
    assert entry["FirehoseArn"] == firehose_arn, entry["FirehoseArn"]

    cw.stop_metric_streams(Names=[stream_name])
    entry_after_stop = _poll_until(
        lambda: _find_entry(cw, stream_name),
        lambda e: e is not None and e["State"] == "stopped",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert entry_after_stop is not None and entry_after_stop["State"] == "stopped", entry_after_stop

    code, message = _error(lambda: cw.list_metric_streams(NextToken="not-a-real-token"))
    assert code == "InvalidNextToken", f"expected InvalidNextToken, got {code}"
    assert message == "Invalid NextToken", f"expected the exact message 'Invalid NextToken', got {message!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result if predicate(result) else None


def _retry(fn, *, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    if last_exc is not None:
        raise last_exc
    raise AssertionError("retry loop exited without success or exception")


def _delete_bucket(s3, bucket):
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_role(iam, role_name):
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _find_entry(cw, stream_name, max_pages=10):
    token = None
    for _ in range(max_pages):
        kwargs = {"NextToken": token} if token else {}
        resp = cw.list_metric_streams(**kwargs)
        for entry in resp.get("Entries", []):
            if entry["Name"] == stream_name:
                return entry
        token = resp.get("NextToken")
        if not token:
            break
    return None


def _create_running_metric_stream(ctx):
    """Create an S3 bucket, Firehose delivery stream, IAM roles and a metric stream targeting it.

    Returns (stream_name, firehose_arn)."""
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    cw = ctx.client("cloudwatch")

    bucket = ctx.unique_name("sim2real-cwmsx-").lower().replace("_", "-")
    stream_name = ctx.unique_name("sim2real-cwmsx-")
    firehose_role_name = ctx.unique_name("sim2real-cwmsx-fh-role-")
    cw_role_name = ctx.unique_name("sim2real-cwmsx-cw-role-")
    resource_tags = [{"Key": "sim2real-check", "Value": "list-metric-streams-contract"}]

    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": resource_tags})
    bucket_arn = f"arn:aws:s3:::{bucket}"

    fh_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    fh_role = iam.create_role(
        RoleName=firehose_role_name, AssumeRolePolicyDocument=json.dumps(fh_trust), Tags=resource_tags
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(iam, firehose_role_name))
    iam.put_role_policy(
        RoleName=firehose_role_name,
        PolicyName="s3-write",
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
                        "Resource": [bucket_arn, bucket_arn + "/*"],
                    }
                ],
            }
        ),
    )

    _retry(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=stream_name,
            DeliveryStreamType="DirectPut",
            ExtendedS3DestinationConfiguration={"RoleARN": fh_role["Arn"], "BucketARN": bucket_arn},
            Tags=resource_tags,
        ),
        timeout_s=90.0,
        interval_s=5.0,
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))

    description = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"],
        lambda d: d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert description is not None, "firehose delivery stream never became ACTIVE"
    firehose_arn = description["DeliveryStreamARN"]

    cw_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    cw_role = iam.create_role(
        RoleName=cw_role_name, AssumeRolePolicyDocument=json.dumps(cw_trust), Tags=resource_tags
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(iam, cw_role_name))
    iam.put_role_policy(
        RoleName=cw_role_name,
        PolicyName="firehose-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["firehose:PutRecord", "firehose:PutRecordBatch", "firehose:DescribeDeliveryStream"],
                        "Resource": firehose_arn,
                    }
                ],
            }
        ),
    )

    _retry(
        lambda: cw.put_metric_stream(
            Name=stream_name,
            FirehoseArn=firehose_arn,
            RoleArn=cw_role["Arn"],
            OutputFormat="json",
            Tags=resource_tags,
        ),
        timeout_s=90.0,
        interval_s=5.0,
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=stream_name))

    return stream_name, firehose_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
