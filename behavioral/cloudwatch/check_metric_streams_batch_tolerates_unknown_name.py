"""metric-streams-batch-tolerates-unknown-name."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "metric-streams-batch-tolerates-unknown-name"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Start/StopMetricStreams with one real and one unknown name return 200, act on the real
    stream, and do not create the unknown one; repeating either call on the real name alone
    is idempotent."""
    cw = ctx.client("cloudwatch")
    stack = _build_metric_stream_stack(ctx)
    name = stack["name"]
    bogus_name = ctx.unique_name("sim2real-cwms-missing-")

    resp = cw.stop_metric_streams(Names=[name, bogus_name])
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"mixed-name StopMetricStreams should succeed with 200, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    state = _poll_until(lambda: cw.get_metric_stream(Name=name)["State"], lambda s: s == "stopped", timeout_s=30.0, interval_s=2.0)
    assert state == "stopped", f"valid stream in a mixed batch was not stopped, state={state!r}"
    assert _error(lambda: cw.get_metric_stream(Name=bogus_name)) == ("ResourceNotFoundException", ""), (
        "an unknown name named in a Stop batch must not be fabricated into a real, listable stream"
    )

    cw.stop_metric_streams(Names=[name])
    state = cw.get_metric_stream(Name=name)["State"]
    assert state == "stopped", f"idempotent solo StopMetricStreams on an already-stopped stream, got state={state!r}"

    resp = cw.start_metric_streams(Names=[name, bogus_name])
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"mixed-name StartMetricStreams should succeed with 200, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    state = _poll_until(lambda: cw.get_metric_stream(Name=name)["State"], lambda s: s == "running", timeout_s=30.0, interval_s=2.0)
    assert state == "running", f"valid stream in a mixed batch was not started, state={state!r}"
    assert _error(lambda: cw.get_metric_stream(Name=bogus_name)) == ("ResourceNotFoundException", ""), (
        "an unknown name named in a Start batch must not be fabricated into a real, listable stream"
    )

    cw.start_metric_streams(Names=[name])
    state = cw.get_metric_stream(Name=name)["State"]
    assert state == "running", f"idempotent solo StartMetricStreams on an already-running stream, got state={state!r}"


_NOT_FOUND = ("NoSuchBucket", "NoSuchEntity", "ResourceNotFoundException")
_BUCKET_CLEANUP_BUDGET_S = 240.0


def _safe(fn):
    """Run a teardown; only an already-gone resource is tolerated, every other error raises."""
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in _NOT_FOUND:
            raise


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _retry_call(fn, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    assert last_err is not None, "retry loop exited without ever calling fn()"
    raise last_err


def _build_metric_stream_stack(ctx) -> dict[str, str]:
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")
    cw = ctx.client("cloudwatch")

    bucket = ctx.unique_name("sim2realcwms").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})

    def _cleanup_bucket():
        """Empty then delete; a Firehose flush can land after the empty, so BucketNotEmpty re-empties."""
        from botocore.exceptions import ClientError
        deadline = time.monotonic() + _BUCKET_CLEANUP_BUDGET_S
        while True:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            try:
                s3.delete_bucket(Bucket=bucket)
                return
            except ClientError as err:
                if err.response["Error"]["Code"] != "BucketNotEmpty" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(lambda: _safe(_cleanup_bucket))
    bucket_arn = f"arn:aws:s3:::{bucket}"

    fh_role_name = ctx.unique_name("sim2real-cwms-fhrole-")
    fh_trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ]}
    fh_role_arn = iam.create_role(
        RoleName=fh_role_name, AssumeRolePolicyDocument=json.dumps(fh_trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=fh_role_name)))
    iam.put_role_policy(
        RoleName=fh_role_name, PolicyName="s3-write",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                            "Resource": [bucket_arn, bucket_arn + "/*"]}],
        }),
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=fh_role_name, PolicyName="s3-write")))

    fh_stream_name = ctx.unique_name("sim2real-cwms-fh-")

    def _create_fh():
        return firehose.create_delivery_stream(
            DeliveryStreamName=fh_stream_name,
            DeliveryStreamType="DirectPut",
            ExtendedS3DestinationConfiguration={
                "RoleARN": fh_role_arn,
                "BucketARN": bucket_arn,
                "BufferingHints": {"SizeInMBs": 5, "IntervalInSeconds": 300},
            },
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )

    fh_resp = _retry_call(_create_fh)
    fh_arn = fh_resp["DeliveryStreamARN"]
    ctx.on_cleanup(lambda: _safe(lambda: firehose.delete_delivery_stream(DeliveryStreamName=fh_stream_name)))

    def _fh_status():
        return firehose.describe_delivery_stream(DeliveryStreamName=fh_stream_name)["DeliveryStreamDescription"]["DeliveryStreamStatus"]

    _poll_until(_fh_status, lambda s: s == "ACTIVE", timeout_s=120.0, interval_s=5.0)

    cw_role_name = ctx.unique_name("sim2real-cwms-cwrole-")
    cw_trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ]}
    cw_role_arn = iam.create_role(
        RoleName=cw_role_name, AssumeRolePolicyDocument=json.dumps(cw_trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=cw_role_name)))
    iam.put_role_policy(
        RoleName=cw_role_name, PolicyName="firehose-put",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                            "Resource": fh_arn}],
        }),
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=cw_role_name, PolicyName="firehose-put")))

    stream_name = ctx.unique_name("sim2real-cwms-")

    def _create_ms():
        return cw.put_metric_stream(
            Name=stream_name, FirehoseArn=fh_arn, RoleArn=cw_role_arn, OutputFormat="json",
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )

    ms_resp = _retry_call(_create_ms)
    ctx.on_cleanup(lambda: _safe(lambda: cw.delete_metric_stream(Name=stream_name)))
    return {"name": stream_name, "arn": ms_resp["Arn"], "firehose_arn": fh_arn, "role_arn": cw_role_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
